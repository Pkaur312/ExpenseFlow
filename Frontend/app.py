from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import requests
from datetime import datetime
import json
import re
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key in production
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Backend API URL
BACKEND_URL = 'http://127.0.0.1:5001'

# Add these configurations
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Call backend login API
            response = requests.post(f'{BACKEND_URL}/api/auth/login', json={
                'email': email,
                'password': password
            })
            
            if response.status_code == 200:
                data = response.json()
                session['user'] = data['user']
                session['token'] = data['token']  # Store the JWT token
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error_msg = response.json().get('error', 'Invalid email or password.')
                flash(error_msg, 'error')
                return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([name, email, password, confirm_password]):
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))
        
        try:
            # Call backend signup API
            response = requests.post(f'{BACKEND_URL}/api/auth/signup', json={
                'name': name,
                'email': email,
                'password': password
            })
            
            if response.status_code == 201:
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                error_msg = response.json().get('error', 'An error occurred during signup.')
                flash(error_msg, 'error')
                return redirect(url_for('signup'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Fetch expenses from backend API
        headers = {'Authorization': f'Bearer {session.get("token")}'}
        response = requests.get(
            f'{BACKEND_URL}/api/expenses',
            headers=headers
        )
        
        if response.status_code == 200:
            expenses = response.json()
            # Calculate total expenses
            total_expenses = sum(expense['amount'] for expense in expenses)
            # Calculate this month's expenses
            current_month = datetime.now().strftime('%Y-%m')
            monthly_expenses = sum(
                expense['amount'] 
                for expense in expenses 
                if expense['date'].startswith(current_month)
            )
            # Get unique categories
            categories = len(set(expense['category'] for expense in expenses))
            
            return render_template(
                'dashboard.html',
                expenses=expenses,
                total_expenses=total_expenses,
                monthly_expenses=monthly_expenses,
                categories=categories,
                transaction_count=len(expenses)
            )
        else:
            flash('Failed to fetch expenses.', 'error')
            return render_template('dashboard.html', expenses=[])
    except Exception as e:
        flash('An error occurred while fetching expenses.', 'error')
        return render_template('dashboard.html', expenses=[])

@app.route('/add-expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        try:
            # Get form data
            data = {
                'amount': float(request.form.get('amount')),
                'category': request.form.get('category'),
                'date': request.form.get('date'),
                'description': request.form.get('description')
            }
            
            # Send data to backend API
            headers = {'Authorization': f'Bearer {session.get("token")}'}
            response = requests.post(
                f'{BACKEND_URL}/api/expenses',
                json=data,
                headers=headers
            )
            
            if response.status_code == 201:
                flash('Expense added successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Failed to add expense. Please try again.', 'error')
                return redirect(url_for('add_expense'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('add_expense'))
    
    return render_template('add_expense.html')

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/voice-expense', methods=['POST'])
@login_required
def voice_expense():
    """Handle voice-based expense entry"""
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"success": False, "error": "No voice input received"}), 400
        
    text = data['text'].lower()
    
    # Initialize expense details
    expense = {
        "amount": None,
        "category": None,
        "description": text,
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    
    # Extract amount (looking for currency patterns)
    amount_pattern = r'\$?\s*(\d+(?:\.\d{2})?)'
    amount_match = re.search(amount_pattern, text)
    if amount_match:
        expense["amount"] = float(amount_match.group(1))
    else:
        return jsonify({"success": False, "error": "Could not detect an amount in the voice input"}), 400
    
    # Define common expense categories
    categories = {
        "food": ["food", "grocery", "groceries", "restaurant", "dining", "lunch", "dinner", "breakfast"],
        "transportation": ["transport", "uber", "taxi", "bus", "train", "gas", "fuel"],
        "utilities": ["utility", "utilities", "electricity", "water", "internet", "phone"],
        "entertainment": ["entertainment", "movie", "game", "concert"],
        "shopping": ["shopping", "clothes", "clothing", "shoes", "accessories"],
        "health": ["health", "medical", "medicine", "doctor", "hospital"],
        "other": ["other", "miscellaneous"]
    }
    
    # Find category from text
    for category, keywords in categories.items():
        if any(keyword in text for keyword in keywords):
            expense["category"] = category
            break
    
    if not expense["category"]:
        expense["category"] = "other"
    
    # Send the expense to the backend
    try:
        headers = {'Authorization': f'Bearer {session.get("token")}'}
        response = requests.post(
            f'{BACKEND_URL}/api/expenses',
            json=expense,
            headers=headers
        )
        
        if response.status_code == 201:
            flash('Expense added successfully!', 'success')
            return jsonify({"success": True, "redirect": url_for('dashboard')}), 200
        else:
            return jsonify({"success": False, "error": "Failed to save expense"}), 400
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/scan-receipt', methods=['POST'])
@login_required
def scan_receipt():
    if 'receipt' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['receipt']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Create upload folder if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        try:
            # Send to backend for OCR processing
            headers = {'Authorization': f'Bearer {session.get("token")}'}
            files = {'receipt': open(filepath, 'rb')}
            response = requests.post(
                f'{BACKEND_URL}/api/scan-receipt',
                files=files,
                headers=headers
            )
            
            # Clean up uploaded file
            os.remove(filepath)
            
            if response.status_code == 200:
                return response.json()
            else:
                return jsonify({'success': False, 'error': 'Failed to process receipt'}), 400
                
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
            
    return jsonify({
        'success': False, 
        'error': f'Invalid file type. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}'
    }), 400

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload-receipt', methods=['POST'])
@login_required
def upload_receipt():
    if 'receipt' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['receipt']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        
        # Create upload folder if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # For now, just save the file and return success
            # Later we'll add the backend processing
            return jsonify({
                'success': True,
                'message': 'Receipt uploaded successfully'
            })
            
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'success': False, 'error': str(e)}), 500
            
    return jsonify({'success': False, 'error': 'Invalid file type'}), 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, port=5100) 