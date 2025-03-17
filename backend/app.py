from flask import Flask
from pymongo import MongoClient

print("Starting Flask...")

app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['shopping_assistant']
collection = db['items']

# function to add item to database
# def add_item()

# function to get items on list
# def get_items()

# function to get specified item on list
# def get_item(name)

# function to update item
# def update_item(item_id)

# function to delete item 
# def delete_item(item_id)

@app.route('/')
def home():
    return 'Hello, Flask!'

if __name__ == '__main__':
    print("Running app...")
    app.run(debug=True)