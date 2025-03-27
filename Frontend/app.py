from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import requests
from datetime import datetime
import json
import re
import os
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key in production
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Backend API URL
BACKEND_URL = 'http://127.0.0.1:5001'

TAGGUN_API_KEY = 'YOUR_TAGGUN_API_KEY'  # You'll need to get this from Taggun
UPLOAD_FOLDER = 'temp_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
            monthly_expenses = 0
            for expense in expenses:
                try:
                    expense_date = datetime.strptime(expense['date'], '%Y-%m-%d')
                    if expense_date.strftime('%Y-%m') == current_month:
                        monthly_expenses += expense['amount']
                except (ValueError, TypeError):
                    continue  # Skip if date is invalid
            
            # Sort expenses by date for recent expenses (show all, sorted by most recent)
            sorted_expenses = sorted(
                expenses,
                key=lambda x: datetime.strptime(x['date'], '%Y-%m-%d'),
                reverse=True
            )
            
            # Get unique categories
            categories = len(set(expense['category'] for expense in expenses))
            
            return render_template(
                'dashboard.html',
                expenses=sorted_expenses,  # Pass all expenses, sorted by date
                total_expenses=total_expenses,
                monthly_expenses=monthly_expenses,
                categories=categories,
                transaction_count=len(expenses)
            )
        else:
            flash('Failed to fetch expenses.', 'error')
            return render_template('dashboard.html', expenses=[])
    except Exception as e:
        print(f"Dashboard error: {str(e)}")  # Add logging for debugging
        flash('An error occurred while fetching expenses.', 'error')
        return render_template('dashboard.html', expenses=[])

@app.route('/add-expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        try:
            # Get data from either JSON or form data
            if request.is_json:
                data = request.get_json()
            else:
                data = {
                    'amount': float(request.form.get('amount')),
                    'category': request.form.get('category'),
                    'date': request.form.get('date'),
                    'description': request.form.get('description')
                }
            
            # Validate required fields
            if not all(key in data for key in ['amount', 'category', 'date', 'description']):
                flash('Missing required fields', 'error')
                return redirect(url_for('add_expense'))
            
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
                error_msg = response.json().get('error', 'Failed to add expense')
                flash(error_msg, 'error')
                return redirect(url_for('add_expense'))
        except ValueError as e:
            flash('Invalid amount format', 'error')
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

def preprocess_image(image_path):
    """Preprocess the image for better OCR results"""
    try:
        import numpy as np
        image = Image.open(image_path)
        
        # Convert to grayscale
        image = image.convert('L')
        
        # Get image size
        width, height = image.size
        
        # Calculate new dimensions while maintaining aspect ratio
        target_width = 3000  # Increased resolution for better detail
        aspect_ratio = height / width
        target_height = int(target_width * aspect_ratio)
        
        # Resize image
        image = image.resize((target_width, target_height), Image.Resampling.LANCZOS)
        
        # Enhance image
        from PIL import ImageEnhance, ImageFilter
        
        # Basic image enhancement
        # 1. Remove noise
        image = image.filter(ImageFilter.MedianFilter(size=3))
        
        # 2. Enhance edges
        image = image.filter(ImageFilter.EDGE_ENHANCE_MORE)
        
        # 3. Increase contrast
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.5)
        
        # 4. Adjust brightness
        enhancer = ImageEnhance.Brightness(image)
        image = enhancer.enhance(1.3)
        
        # 5. Increase sharpness
        enhancer = ImageEnhance.Sharpness(image)
        image = enhancer.enhance(2.0)
        
        # 6. Apply adaptive thresholding
        img_array = np.array(image)
        block_size = 25
        C = 15
        
        # Calculate the local mean using a moving window
        from scipy.ndimage import uniform_filter
        local_mean = uniform_filter(img_array, size=block_size)
        
        # Apply adaptive threshold
        binary_image = img_array > (local_mean - C)
        processed_array = np.where(binary_image, 255, 0).astype(np.uint8)
        
        return Image.fromarray(processed_array)
        
    except Exception as e:
        print(f"Error in image preprocessing: {str(e)}")
        # If preprocessing fails, return original image
        return Image.open(image_path)

def extract_amount(text):
    """Enhanced amount extraction with multiple patterns and validation"""
    print("\nSearching for amounts in text:")
    print("Raw text:", text)
    
    # Clean the text
    text = text.upper()  # Convert to uppercase for consistency
    text = re.sub(r'\s+', ' ', text)  # Normalize spaces
    
    # List of patterns from most specific to least specific
    amount_patterns = [
        # Total amount patterns
        (r'TOTAL\s*[:\$]?\s*(\d+\.\d{2})', 'TOTAL'),
        (r'TOTAL\s*AMOUNT\s*[:\$]?\s*(\d+\.\d{2})', 'TOTAL'),
        (r'GRAND\s*TOTAL\s*[:\$]?\s*(\d+\.\d{2})', 'TOTAL'),
        (r'BALANCE\s*DUE\s*[:\$]?\s*(\d+\.\d{2})', 'TOTAL'),
        
        # Payment patterns
        (r'AMOUNT\s*PAID\s*[:\$]?\s*(\d+\.\d{2})', 'PAID'),
        (r'CREDIT\s*TEND\s*[:\$]?\s*(\d+\.\d{2})', 'PAID'),
        (r'DEBIT\s*TEND\s*[:\$]?\s*(\d+\.\d{2})', 'PAID'),
        (r'PAYMENT\s*[:\$]?\s*(\d+\.\d{2})', 'PAID'),
        
        # Subtotal patterns
        (r'SUB\s*TOTAL\s*[:\$]?\s*(\d+\.\d{2})', 'SUBTOTAL'),
        (r'SUBTOTAL\s*[:\$]?\s*(\d+\.\d{2})', 'SUBTOTAL'),
        
        # Generic amount patterns
        (r'(?:^|\s)\$?\s*(\d+\.\d{2})(?:\s|$)', 'AMOUNT')  # Any dollar amount
    ]
    
    found_amounts = []
    
    # First pass: Look for amounts with their labels
    for pattern, label in amount_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            try:
                amount_str = match.group(1).strip()
                amount = float(amount_str)
                
                # Validate amount is reasonable (between 0.01 and 99999.99)
                if 0.01 <= amount <= 99999.99:
                    # Get context (20 characters before and after)
                    start_pos = max(0, match.start() - 20)
                    end_pos = min(len(text), match.end() + 20)
                    context = text[start_pos:end_pos]
                    
                    print(f"\nFound {label} amount: {amount}")
                    print(f"Pattern: {pattern}")
                    print(f"Context: ...{context}...")
                    
                    # Score the match based on context
                    score = 0
                    if label == 'TOTAL': score = 100
                    elif label == 'PAID': score = 90
                    elif label == 'SUBTOTAL': score = 80
                    else: score = 50
                    
                    # Additional scoring based on context
                    if 'TOTAL' in context: score += 10
                    if '$' in context: score += 5
                    if 'AMOUNT' in context: score += 5
                    
                    found_amounts.append({
                        'amount': amount,
                        'label': label,
                        'context': context,
                        'score': score
                    })
            except ValueError as e:
                print(f"Failed to parse amount: {match.group(0)}, Error: {str(e)}")
                continue
    
    if found_amounts:
        # Sort by score (highest first) and amount (highest first for ties)
        found_amounts.sort(key=lambda x: (-x['score'], -x['amount']))
        
        print("\nAll found amounts (sorted by score):")
        for item in found_amounts:
            print(f"{item['label']}: {item['amount']}, Score: {item['score']}, Context: {item['context']}")
        
        selected_amount = found_amounts[0]['amount']
        print(f"\nSelected amount: {selected_amount}")
        return selected_amount
    
    print("\nNo valid amounts found")
    return None

def extract_date(text):
    """Extract date from text using regex patterns"""
    # Common date formats, prioritizing MM/DD/YY format common in US receipts
    patterns = [
        r'(\d{2}/\d{2}/\d{2}(?:\d{2})?)',      # MM/DD/YY or MM/DD/YYYY
        r'(\d{2}-\d{2}-\d{2}(?:\d{2})?)',      # MM-DD-YY or MM-DD-YYYY
        r'(\d{4}-\d{2}-\d{2})',                # YYYY-MM-DD
        r'(\w{3,9}\s+\d{1,2},?\s+\d{4})'       # Month DD, YYYY
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            try:
                date_str = match.group(1)
                # Try different date formats
                for fmt in ['%m/%d/%y', '%m/%d/%Y', '%Y-%m-%d', '%B %d, %Y', '%b %d, %Y']:
                    try:
                        parsed_date = datetime.strptime(date_str, fmt)
                        # Validate year is reasonable
                        if 2000 <= parsed_date.year <= datetime.now().year + 1:
                            return parsed_date.strftime('%Y-%m-%d')
                    except ValueError:
                        continue
            except:
                continue
    
    return None

def determine_category(text):
    """Determine expense category based on keywords"""
    text = text.lower()
    
    categories = {
        'Food & Dining': ['restaurant', 'cafe', 'food', 'burger', 'pizza', 'diner', 'coffee', 'meal', 'lunch', 'dinner'],
        'Transportation': ['gas', 'fuel', 'uber', 'lyft', 'taxi', 'transport', 'parking', 'bus', 'train'],
        'Shopping': ['walmart', 'target', 'amazon', 'store', 'market', 'shop', 'retail'],
        'Bills & Utilities': ['utility', 'electric', 'water', 'gas', 'internet', 'phone', 'bill'],
        'Entertainment': ['cinema', 'movie', 'theatre', 'concert', 'game', 'entertainment'],
        'Healthcare': ['pharmacy', 'doctor', 'medical', 'health', 'drug', 'prescription'],
        'Education': ['book', 'school', 'university', 'college', 'course', 'education']
    }
    
    for category, keywords in categories.items():
        if any(keyword in text for keyword in keywords):
            return category
    
    return 'Other'

def extract_merchant(text):
    """Extract merchant name from the receipt using CORD dataset patterns"""
    # Common store patterns
    store_patterns = {
        'Walmart': [
            r'WAL(?:\s*-?\s*)?MART(?:\s+SUPERCENTER)?',
            r'WALMART\s*#?\d*',
            r'WWW\.WALMART\.COM'
        ],
        'Target': [
            r'TARGET(?:\s+STORE)?\s*#?\d*',
            r'TARGET\.COM'
        ],
        'Costco': [
            r'COSTCO\s*WHOLESALE\s*#?\d*',
            r'COSTCO\.COM'
        ],
        'CVS': [
            r'CVS(?:/PHARMACY)?\s*#?\d*',
            r'CVS\.COM'
        ]
    }
    
    # Try to match known store patterns first
    for store_name, patterns in store_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return store_name
    
    # Fallback to general merchant detection
    lines = text.split('\n')
    for line in lines[:5]:  # Check first 5 lines
        line = line.strip()
        # Skip common non-merchant lines
        if any(skip in line.lower() for skip in ['receipt', 'tel:', 'tel.', 'phone:', 'date:', 'time:']):
            continue
        if line and not re.search(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', line) and not re.search(r'\$?\d+\.\d{2}', line):
            return line
    
    return None

@app.route('/process-receipt', methods=['POST'])
@login_required
def process_receipt():
    if 'receipt' not in request.files:
        return jsonify({'error': 'No receipt file provided'}), 400
    
    file = request.files['receipt']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Save file temporarily
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            try:
                # Preprocess image
                processed_image = preprocess_image(filepath)
                
                # Enhanced OCR configurations
                configs = [
                    '--psm 6 --oem 3 -c preserve_interword_spaces=1',  # Assume uniform block of text
                    '--psm 3 --oem 3 -c preserve_interword_spaces=1',  # Assume column of text
                    '--psm 4 --oem 3 -c preserve_interword_spaces=1',  # Assume single column of text
                    '--psm 1 --oem 3 -c preserve_interword_spaces=1'   # Automatic page segmentation
                ]
                
                best_text = ''
                best_confidence = 0
                
                print("\nTrying different OCR configurations:")
                for config in configs:
                    try:
                        text = pytesseract.image_to_string(
                            processed_image,
                            config=config
                        )
                        
                        # Clean up the text
                        text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces
                        text = text.replace('$', ' $ ')   # Add spaces around dollar signs
                        
                        # Enhanced confidence scoring
                        keywords = ['TOTAL', 'SUBTOTAL', 'CREDIT', 'TEND', 'WALMART', 'CHANGE', 'DUE', 'BALANCE', 'AMOUNT']
                        confidence = sum(3 for term in keywords if term in text.upper())
                        
                        # Additional confidence points
                        amounts = re.findall(r'\d+\.\d{2}', text)
                        confidence += len(amounts) * 2
                        
                        print(f"\nConfig: {config}")
                        print(f"Confidence score: {confidence}")
                        print(f"Sample text: {text[:200]}...")
                        
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_text = text
                    except Exception as e:
                        print(f"Error with OCR config {config}: {str(e)}")
                        continue
                
                if not best_text:
                    raise Exception("Failed to extract text from receipt")
                
                text = best_text
                print("\nBest extracted text:", text)
                
                # Extract information
                amount = extract_amount(text)
                date = extract_date(text)
                category = determine_category(text)
                merchant = extract_merchant(text)
                
                print("\nFinal extracted data:")
                print(f"Amount: {amount}")
                print(f"Date: {date}")
                print(f"Category: {category}")
                print(f"Merchant: {merchant}")
                
                if not amount:
                    return jsonify({
                        'error': 'Could not extract amount from receipt. Please ensure:\n' +
                                '1. The receipt is well-lit and not too dark or bright\n' +
                                '2. The image is clear and not blurry\n' +
                                '3. The total amount is clearly visible\n' +
                                '4. The receipt is not crumpled or damaged'
                    }), 400
                
                return jsonify({
                    'amount': amount,
                    'date': date or datetime.now().strftime('%Y-%m-%d'),
                    'category': category,
                    'merchantName': merchant or 'Unknown Merchant',
                    'rawText': text
                })
                
            finally:
                # Clean up temporary file
                if os.path.exists(filepath):
                    os.remove(filepath)
                
        except Exception as e:
            print(f"Error processing receipt: {str(e)}")
            return jsonify({
                'error': 'Failed to process receipt. Please try:\n' +
                        '1. Taking the photo in better lighting (avoid shadows and glare)\n' +
                        '2. Holding the camera steady and close to the receipt\n' +
                        '3. Making sure the receipt is flat on a dark surface\n' +
                        '4. Ensuring the entire receipt is in frame'
            }), 500
            
    return jsonify({'error': 'Invalid file type'}), 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, port=5090) 