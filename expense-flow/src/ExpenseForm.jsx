import React, { useState } from 'react';
import './ExpenseForm.css';

const ExpenseForm = ({ onAddExpense, onCancel }) => {
    const [formData, setFormData] = useState({
        description: '',
        amount: '',
        date: new Date().toISOString().split('T')[0],
        category: 'other',
        paymentMethod: 'cash'
    });

    const categories = [
        'food',
        'transportation',
        'utilities',
        'entertainment',
        'shopping',
        'healthcare',
        'other'
    ];

    const paymentMethods = [
        'cash',
        'credit card',
        'debit card',
        'bank transfer',
        'mobile payment',
        'other'
    ];

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        
        // Validate amount
        const amount = parseFloat(formData.amount);
        if (isNaN(amount) || amount <= 0) {
            alert('Please enter a valid amount');
            return;
        }

        // Create expense object
        const expense = {
            ...formData,
            amount: amount,
            id: Date.now(), // Simple unique ID
            timestamp: new Date().toISOString()
        };

        // Call the parent component's handler
        onAddExpense(expense);

        // Reset form
        setFormData({
            description: '',
            amount: '',
            date: new Date().toISOString().split('T')[0],
            category: 'other',
            paymentMethod: 'cash'
        });
    };

    return (
        <div className="expense-form-container">
            <form onSubmit={handleSubmit} className="expense-form">
                <div className="form-header">
                    <h2>Add New Expense</h2>
                    <button type="button" className="close-btn" onClick={onCancel}>&times;</button>
                </div>
                
                <div className="form-group">
                    <label htmlFor="description">Description</label>
                    <input
                        type="text"
                        id="description"
                        name="description"
                        value={formData.description}
                        onChange={handleChange}
                        required
                        placeholder="Enter expense description"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="amount">Amount</label>
                    <input
                        type="number"
                        id="amount"
                        name="amount"
                        value={formData.amount}
                        onChange={handleChange}
                        required
                        min="0"
                        step="0.01"
                        placeholder="Enter amount"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="date">Date</label>
                    <input
                        type="date"
                        id="date"
                        name="date"
                        value={formData.date}
                        onChange={handleChange}
                        required
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="category">Category</label>
                    <select
                        id="category"
                        name="category"
                        value={formData.category}
                        onChange={handleChange}
                        required
                    >
                        {categories.map(category => (
                            <option key={category} value={category}>
                                {category.charAt(0).toUpperCase() + category.slice(1)}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="form-group">
                    <label htmlFor="paymentMethod">Payment Method</label>
                    <select
                        id="paymentMethod"
                        name="paymentMethod"
                        value={formData.paymentMethod}
                        onChange={handleChange}
                        required
                    >
                        {paymentMethods.map(method => (
                            <option key={method} value={method}>
                                {method.charAt(0).toUpperCase() + method.slice(1)}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="form-actions">
                    <button type="button" className="cancel-btn" onClick={onCancel}>Cancel</button>
                    <button type="submit" className="submit-btn">Add Expense</button>
                </div>
            </form>
        </div>
    );
};

export default ExpenseForm; 