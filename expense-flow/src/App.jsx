import React, { useState } from 'react';
import MainComponent from './MainComponent'; // Import the MainComponent
import LoginPage from './components/LoginPage';
import './App.css';

function App() {
  const [user, setUser] = useState(null);

  const handleLogin = (userData) => {
    // Here you would typically store the user data in a more secure way
    // For now, we'll just store it in state
    setUser(userData);
  };

  const handleLogout = () => {
    setUser(null);
  };

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <>
      <div className="container">
        <header className='header'>
          <h1>ExpenseFlow</h1>
          <div className="user-section">
            <span className="user-email">{user.email}</span>
            <button className="logout-btn" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </header>

        <main className='main'>
          <MainComponent /> {/* Use the MainComponent here */}
        </main>

        <footer className='footer'>
          <div className='buttons'>
            <div className='button-container'>
              <button className='scan_footer'>
                Scan
              </button>
              <button className='report'>
                Report
              </button>
              <button className='settings'>
                Settings
              </button>
            </div>
          </div>
          &copy; 2025 AI Budgeting Assistant. All Rights Reserved.
        </footer>
      </div>
    </>
  );
}

export default App;