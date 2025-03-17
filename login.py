import gradio as gr
import hashlib
import json
import os

# Initialize users database (in a real app, use a proper database)
USERS_FILE = "users.json"

def init_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    """Load users from JSON file"""
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def register(username, password, confirm_password):
    """Register a new user"""
    if not username or not password or not confirm_password:
        return "Please fill in all fields", False
    
    if password != confirm_password:
        return "Passwords do not match", False
    
    users = load_users()
    if username in users:
        return "Username already exists", False
    
    users[username] = hash_password(password)
    save_users(users)
    return "Registration successful! Please login.", True

def login(username, password):
    """Login a user"""
    if not username or not password:
        return "Please fill in all fields", False
    
    users = load_users()
    if username not in users:
        return "Username not found", False
    
    if users[username] != hash_password(password):
        return "Incorrect password", False
    
    return f"Welcome back, {username}!", True

# Initialize users database
init_users()

# Create the Gradio interface
with gr.Blocks(title="ExpenseFlow Login") as demo:
    gr.Markdown("# 🔐 ExpenseFlow Login")
    
    with gr.Tabs():
        with gr.Tab("Login"):
            with gr.Column():
                login_username = gr.Textbox(label="Username", placeholder="Enter your username")
                login_password = gr.Textbox(label="Password", placeholder="Enter your password", type="password")
                login_btn = gr.Button("Login", variant="primary")
                login_message = gr.Textbox(label="Status", interactive=False)
        
        with gr.Tab("Register"):
            with gr.Column():
                reg_username = gr.Textbox(label="Username", placeholder="Choose a username")
                reg_password = gr.Textbox(label="Password", placeholder="Choose a password", type="password")
                reg_confirm = gr.Textbox(label="Confirm Password", placeholder="Confirm your password", type="password")
                register_btn = gr.Button("Register", variant="primary")
                register_message = gr.Textbox(label="Status", interactive=False)
    
    # Set up event handlers
    login_btn.click(
        fn=login,
        inputs=[login_username, login_password],
        outputs=[login_message]
    )
    
    register_btn.click(
        fn=register,
        inputs=[reg_username, reg_password, reg_confirm],
        outputs=[register_message]
    )

if __name__ == "__main__":
    demo.launch() 