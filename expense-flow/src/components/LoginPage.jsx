import React, { useState } from 'react';
import './LoginPage.css';

const LoginPage = ({ onLogin }) => {
    const [activeForm, setActiveForm] = useState('login'); // login, register, or forgot
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        confirmPassword: '',
        name: ''
    });
    const [error, setError] = useState('');

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
        setError('');
    };

    const handleLogin = (e) => {
        e.preventDefault();
        // Here you would typically make an API call to verify credentials
        if (!formData.email || !formData.password) {
            setError('Please fill in all fields');
            return;
        }
        // For now, we'll just simulate a successful login
        onLogin({ email: formData.email });
    };

    const handleRegister = (e) => {
        e.preventDefault();
        if (!formData.email || !formData.password || !formData.confirmPassword || !formData.name) {
            setError('Please fill in all fields');
            return;
        }
        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        // Here you would typically make an API call to register the user
        // For now, we'll just simulate a successful registration
        onLogin({ email: formData.email, name: formData.name });
    };

    const handleForgotPassword = (e) => {
        e.preventDefault();
        if (!formData.email) {
            setError('Please enter your email');
            return;
        }
        // Here you would typically make an API call to send a password reset email
        alert('Password reset instructions have been sent to your email');
        setActiveForm('login');
    };

    const renderLoginForm = () => (
        <form onSubmit={handleLogin} className="login-form">
            <h2>Welcome Back</h2>
            <div className="form-group">
                <label htmlFor="email">Email</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email"
                    required
                />
            </div>
            <div className="form-group">
                <label htmlFor="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="Enter your password"
                    required
                />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" className="submit-btn">Login</button>
            <div className="form-links">
                <button 
                    type="button" 
                    className="link-btn"
                    onClick={() => setActiveForm('forgot')}
                >
                    Forgot Password?
                </button>
                <button 
                    type="button" 
                    className="link-btn"
                    onClick={() => setActiveForm('register')}
                >
                    Create Account
                </button>
            </div>
        </form>
    );

    const renderRegisterForm = () => (
        <form onSubmit={handleRegister} className="login-form">
            <h2>Create Account</h2>
            <div className="form-group">
                <label htmlFor="name">Full Name</label>
                <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    placeholder="Enter your full name"
                    required
                />
            </div>
            <div className="form-group">
                <label htmlFor="reg-email">Email</label>
                <input
                    type="email"
                    id="reg-email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email"
                    required
                />
            </div>
            <div className="form-group">
                <label htmlFor="reg-password">Password</label>
                <input
                    type="password"
                    id="reg-password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="Create a password"
                    required
                />
            </div>
            <div className="form-group">
                <label htmlFor="confirmPassword">Confirm Password</label>
                <input
                    type="password"
                    id="confirmPassword"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    placeholder="Confirm your password"
                    required
                />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" className="submit-btn">Create Account</button>
            <div className="form-links">
                <button 
                    type="button" 
                    className="link-btn"
                    onClick={() => setActiveForm('login')}
                >
                    Already have an account? Login
                </button>
            </div>
        </form>
    );

    const renderForgotPasswordForm = () => (
        <form onSubmit={handleForgotPassword} className="login-form">
            <h2>Reset Password</h2>
            <p className="form-description">
                Enter your email address and we'll send you instructions to reset your password.
            </p>
            <div className="form-group">
                <label htmlFor="forgot-email">Email</label>
                <input
                    type="email"
                    id="forgot-email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email"
                    required
                />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" className="submit-btn">Send Reset Instructions</button>
            <div className="form-links">
                <button 
                    type="button" 
                    className="link-btn"
                    onClick={() => setActiveForm('login')}
                >
                    Back to Login
                </button>
            </div>
        </form>
    );

    return (
        <div className="login-page">
            <div className="background-shapes">
                <div className="shape shape-1"></div>
                <div className="shape shape-2"></div>
                <div className="shape shape-3"></div>
            </div>
            <div className="login-container">
                <div className="logo">
                    <h1>ExpenseFlow</h1>
                    <div className="logo-accent"></div>
                </div>
                {activeForm === 'login' && renderLoginForm()}
                {activeForm === 'register' && renderRegisterForm()}
                {activeForm === 'forgot' && renderForgotPasswordForm()}
            </div>
        </div>
    );
};

export default LoginPage; 