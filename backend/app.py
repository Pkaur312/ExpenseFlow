from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from bson import ObjectId
import firebase_admin
from firebase_admin import credentials, firestore
from functools import wraps

print("Starting Flask...")

# Initializing the Firebase Admin
cred = credentials.Certificate()
firebase_admin.initialize_app(cred)

app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['expense_flow']
collection = db['expenses']

database_schema = {
    "user_id": str,
    "description": str,
    "amount": float,
    "category": ExpenseCategory,
    "cost": float,
    "date": datetime,
}

def firebase_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs);
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "No authorization header given"}), 401

        try:
            token = auth_header.split(" ")[1]
            # verify the Firebase token
            decoded_token = auth.verify_id_token(token)

            # get user's UID
            user_id = decoded_token['uid']
            
            return f(user_id, *args, **kwards)

        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
    return decorated

    
        
# function to add an expense to database
@app.route('/expenses', methods=['POST'])
@firebase_auth_required
def add_expense(user_id):
    data = request.get_json()

    required_fields = ["user_id", "description", "amount", "category", "cost", "date"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    expense = {
        "user_id": data["user_id"],
        "description": data["description"],
        "amount": data["amount"],
        "category": data["category"],
        "cost": data["cost"],
        "date": data["date"],
    }

    result = collection.insert_one(expense)
    return jsonify({"message": "New expense added successfully", "id":str(result.inserted_id)}), 201
    

# function to get expenses in the database
@app.route('/expenses', methods=['GET'])
@firebase_auth_required
def get_expenses():
    expenses = list(collection.find())
    for expense in expenses:
        expense['_id'] = str(expense['_id'])
    return jsonify(expenses), 200

# function to get specified item on list
@app.route('/expenses/<expense_id>', methods=['GET'])
@firebase_auth_required
def get_expense(expense_id):
    try:
        expense = collection.find_one({'_id': ObjectId(expense_id)})
        if expense:
            expense['_id'] = str(expense['_id'])
            expense['date'] = expense['date'].isoformat()
            return jsonify(expense), 200
        else:
            return jsonify({"error": "Expense not found"}), 400

# function to update an expense // I'm not sure if this is needed
@app.route('/expenses/<expense_id>', methods=['PUT'])
@firebase_auth_required
def update_expense(expense_id):
    try:
        data = request.get_json()
        update_data = {}
        for field in database_schema:
            if field in data:
                update_data[field] = data[field]

        result = collection.update_one(
            {"_id": ObjectId(expense_id)},
            {"$set": update_data}
        )

        if result.modified_count == 1:
            return jsonify({"message": "Expense updated successfully"})
        return jsonify({"message": "Expense not found"}), 404
    
    except:
        return jsonify({"error": "Invalid expense ID"}), 400
            

# function to delete item 
@app.route('/expenses/<expense_id>', methods=['DELETE'])
@firebase_auth_required
def delete_expense(expense_id):
    try:
        result = collection.delete_one({'_id': ObjectId(expense_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Expense deleted successfully"})
        return jsonify({"error"; "Expense not found"}), 404
    
    except:
        return jsonify({"error": "Invalid expense ID"}), 400

@app.route('/')
def home():
    return 'Welcome to Expense Flow!'

if __name__ == '__main__':
    print("Running app...")
    app.run(debug=True)