import gradio as gr
from datetime import datetime
import json
import os

# Initialize expenses list
expenses = []

def analyze_expense(amount, description):
    """Simple AI-like expense analysis"""
    try:
        amount = float(amount)
        
        # Basic categorization logic
        if amount < 10:
            category = "Small Purchase"
        elif amount < 50:
            category = "Medium Purchase"
        else:
            category = "Large Purchase"
        
        # Generate insights
        description = str(description).lower()
        if "food" in description or "eggs" in description or "grocery" in description:
            category = "Food & Dining"
            insight = "Consider meal planning to reduce food expenses"
        elif "transport" in description or "gas" in description or "fuel" in description:
            category = "Transportation"
            insight = "Look into public transport or carpooling options"
        elif "entertainment" in description or "movie" in description or "game" in description:
            category = "Entertainment"
            insight = "Consider setting a monthly entertainment budget"
        else:
            insight = "Track this category to identify spending patterns"
        
        return category, insight
    except Exception as e:
        return "Uncategorized", f"Error in analysis: {str(e)}"

def add_expense(amount, description):
    try:
        if not amount or not description:
            return "Please fill in both amount and description", "", "", ""
            
        amount = float(amount)
        if amount <= 0:
            return "Amount must be greater than 0", "", "", ""
            
        category, insight = analyze_expense(amount, description)
        
        expense = {
            "id": len(expenses) + 1,
            "amount": amount,
            "category": category,
            "description": description,
            "insight": insight,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        expenses.append(expense)
        
        # Generate summary
        total = sum(e["amount"] for e in expenses)
        category_totals = {}
        for e in expenses:
            category_totals[e["category"]] = category_totals.get(e["category"], 0) + e["amount"]
        
        summary = f"Total Expenses: ${total:.2f}\n\nCategory Breakdown:\n"
        for cat, amt in category_totals.items():
            summary += f"{cat}: ${amt:.2f}\n"
        
        return f"Successfully added ${amount:.2f} expense!", category, insight, summary
    except ValueError:
        return "Please enter a valid amount", "", "", ""
    except Exception as e:
        return f"An error occurred: {str(e)}", "", "", ""

# Create Gradio interface
with gr.Blocks(title="AI Expense Analyzer") as demo:
    gr.Markdown("# 🤖 AI Expense Analyzer")
    gr.Markdown("""
    This app helps you track expenses and provides AI-powered insights:
    - Automatically categorizes expenses
    - Generates spending insights
    - Shows category breakdown
    """)
    
    with gr.Row():
        with gr.Column():
            amount = gr.Number(label="Amount", precision=2, minimum=0.01)
            description = gr.Textbox(
                label="Description",
                placeholder="Enter expense description...",
                max_lines=1
            )
            add_btn = gr.Button("Add Expense", variant="primary")
        
        with gr.Column():
            status = gr.Textbox(label="Status", interactive=False)
            category = gr.Textbox(label="AI Category", interactive=False)
            insight = gr.Textbox(label="AI Insight", interactive=False)
            summary = gr.Textbox(label="Expense Summary", lines=8, interactive=False)
    
    add_btn.click(
        fn=add_expense,
        inputs=[amount, description],
        outputs=[status, category, insight, summary]
    )

# This is required for Hugging Face Spaces
demo.launch() 