import React, { useState } from 'react';
import ExpenseForm from './ExpenseForm';
import './MainComponent.css';

const MainComponent = () => {
    const [showForm, setShowForm] = useState(false);
    const [expenses, setExpenses] = useState([]);

    const handleAddExpense = (expense) => {
        setExpenses([expense, ...expenses]); // Add new expense at the beginning
        setShowForm(false); // Hide the form after adding
    };

    const handleCancel = () => {
        setShowForm(false); // Hide the form when cancelled
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    const formatAmount = (amount) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(amount);
    };

    return (
        <div className="main-component">
            <div className="header-section">
                <h2>Expense Tracker</h2>
                <button 
                    className="add-expense-btn"
                    onClick={() => setShowForm(true)}
                >
                    Add New Expense
                </button>
            </div>

            {showForm && (
                <div className="form-overlay">
                    <ExpenseForm 
                        onAddExpense={handleAddExpense}
                        onCancel={handleCancel}
                    />
                </div>
            )}

            <div className="expenses-section">
                <h3>Recent Transactions</h3>
                {expenses.length === 0 ? (
                    <p className="no-expenses">No expenses added yet. Click "Add New Expense" to get started!</p>
                ) : (
                    <div className="expenses-list">
                        {expenses.map((expense) => (
                            <div key={expense.id} className="expense-item">
                                <div className="expense-info">
                                    <div className="expense-header">
                                        <h4>{expense.description}</h4>
                                        <span className="expense-amount">{formatAmount(expense.amount)}</span>
                                    </div>
                                    <div className="expense-details">
                                        <span className="expense-category">{expense.category}</span>
                                        <span className="expense-date">{formatDate(expense.date)}</span>
                                        <span className="expense-method">{expense.paymentMethod}</span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default MainComponent;