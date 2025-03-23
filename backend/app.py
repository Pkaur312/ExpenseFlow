from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
from bson import ObjectId
from functools import wraps
from enum import Enum
import hashlib
import jwt
import os

class ExpenseCategory(str, Enum):
    FOOD = "FOOD"
    TRANSPORT = "TRANSPORT"
    ENTERTAINMENT = "ENTERTAINMENT"
    SHOPPING = "SHOPPING"
    UTILITIES = "UTILITIES"
    OTHER = "OTHER"

print("Starting ExpenseFlow Backend API...")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['expense_flow']
users_collection = db['users']
expenses_collection = db['expenses']

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "No authorization header"}), 401

        try:
            token = auth_header.split(" ")[1]
            # verify the JWT token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data['user_id']
            return f(user_id, *args, **kwargs)
        except Exception as e:
            print(f"Auth error: {e}")
            return jsonify({"error": "Invalid token"}), 401
    return decorated

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')

        if not all([email, password, name]):
            return jsonify({"error": "Missing required fields"}), 400

        # Check if user already exists
        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered"}), 400

        # Create user in MongoDB
        user = {
            "email": email,
            "password": hash_password(password),
            "name": name,
            "created_at": datetime.utcnow()
        }
        
        result = users_collection.insert_one(user)
        
        return jsonify({
            "message": "User created successfully",
            "user_id": str(result.inserted_id)
        }), 201
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({"error": "Missing email or password"}), 400

        # Find user and verify password
        user = users_collection.find_one({"email": email})
        if not user or user['password'] != hash_password(password):
            return jsonify({"error": "Invalid credentials"}), 401

        # Generate JWT token
        token = jwt.encode(
            {'user_id': str(user['_id'])},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": str(user['_id']),
                "email": user['email'],
                "name": user['name']
            }
        }), 200
    except Exception as e:
        print(f"Error logging in: {e}")
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/expenses', methods=['POST'])
@auth_required
def add_expense(user_id):
    try:
        data = request.get_json()
        required_fields = ["description", "amount", "category", "date"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        expense = {
            "user_id": user_id,
            "description": data["description"],
            "amount": float(data["amount"]),
            "category": data["category"],
            "date": data["date"]
        }

        result = expenses_collection.insert_one(expense)
        return jsonify({
            "message": "Expense added successfully",
            "id": str(result.inserted_id)
        }), 201
    except Exception as e:
        print(f"Error adding expense: {e}")
        return jsonify({"error": "Failed to add expense"}), 500

@app.route('/api/expenses', methods=['GET'])
@auth_required
def get_expenses(user_id):
    try:
        expenses = list(expenses_collection.find({"user_id": user_id}))
        for expense in expenses:
            expense['_id'] = str(expense['_id'])
        return jsonify(expenses), 200
    except Exception as e:
        print(f"Error getting expenses: {e}")
        return jsonify({"error": "Failed to get expenses"}), 500

@app.route('/api/expenses/<expense_id>', methods=['GET'])
@auth_required
def get_expense(user_id, expense_id):
    try:
        expense = expenses_collection.find_one({
            '_id': ObjectId(expense_id),
            'user_id': user_id
        })
        if expense:
            expense['_id'] = str(expense['_id'])
            return jsonify(expense), 200
        return jsonify({"error": "Expense not found"}), 404
    except Exception as e:
        print(f"Error getting expense: {e}")
        return jsonify({"error": "Invalid expense ID"}), 400

@app.route('/api/expenses/<expense_id>', methods=['PUT'])
@auth_required
def update_expense(user_id, expense_id):
    try:
        data = request.get_json()
        update_data = {}
        valid_fields = ["description", "amount", "category", "date"]
        
        for field in valid_fields:
            if field in data:
                update_data[field] = data[field]
                if field == "amount":
                    update_data[field] = float(update_data[field])

        if not update_data:
            return jsonify({"error": "No valid fields to update"}), 400

        result = expenses_collection.update_one(
            {"_id": ObjectId(expense_id), "user_id": user_id},
            {"$set": update_data}
        )

        if result.modified_count == 1:
            return jsonify({"message": "Expense updated successfully"}), 200
        return jsonify({"error": "Expense not found"}), 404
    except Exception as e:
        print(f"Error updating expense: {e}")
        return jsonify({"error": "Failed to update expense"}), 500

@app.route('/api/expenses/<expense_id>', methods=['DELETE'])
@auth_required
def delete_expense(user_id, expense_id):
    try:
        result = expenses_collection.delete_one({
            '_id': ObjectId(expense_id),
            'user_id': user_id
        })
        if result.deleted_count == 1:
            return jsonify({"message": "Expense deleted successfully"}), 200
        return jsonify({"error": "Expense not found"}), 404
    except Exception as e:
        print(f"Error deleting expense: {e}")
        return jsonify({"error": "Failed to delete expense"}), 500

@app.route('/api/categories', methods=['GET'])
def get_categories():
    return jsonify([category.value for category in ExpenseCategory]), 200

@app.route('/')
def home():
    return jsonify({"message": "Welcome to ExpenseFlow API!"}), 200

if __name__ == '__main__':
    print("Running ExpenseFlow Backend API...")
    app.run(debug=True, port=5001) 