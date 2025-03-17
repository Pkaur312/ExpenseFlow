import gradio as gr
import json
from datetime import datetime
import os

# Initialize expenses list
expenses = []

def add_expense(amount, category, description):
    try:
        amount = float(amount)
        expense = {
            "id": len(expenses) + 1,
            "amount": amount,
            "category": category,
            "description": description,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        expenses.append(expense)
        return "Expense added successfully!", get_expenses()
    except ValueError:
        return "Please enter a valid amount", get_expenses()

def get_expenses():
    if not expenses:
        return "No expenses recorded yet."
    
    total = sum(expense["amount"] for expense in expenses)
    expense_list = "\n".join([
        f"Date: {expense['date']}\n"
        f"Amount: ${expense['amount']:.2f}\n"
        f"Category: {expense['category']}\n"
        f"Description: {expense['description']}\n"
        f"-------------------"
        for expense in expenses
    ])
    
    return f"Total Expenses: ${total:.2f}\n\n{expense_list}"

# Create Gradio interface
with gr.Blocks(title="ExpenseFlow - AI-Powered Expense Tracker") as demo:
    gr.Markdown("# ExpenseFlow - AI-Powered Expense Tracker")
    
    with gr.Row():
        with gr.Column():
            amount = gr.Number(label="Amount", precision=2)
            category = gr.Dropdown(
                choices=["Food", "Transportation", "Entertainment", "Utilities", "Other"],
                label="Category"
            )
            description = gr.Textbox(label="Description")
            add_btn = gr.Button("Add Expense")
        
        with gr.Column():
            output = gr.Textbox(label="Expenses", lines=10)
    
    add_btn.click(
        fn=add_expense,
        inputs=[amount, category, description],
        outputs=[gr.Textbox(label="Status"), output]
    )

if __name__ == "__main__":
    demo.launch() 