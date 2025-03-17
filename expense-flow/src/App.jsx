import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [transactions, setTransactions] = useState([
    {id: 1, name: "Groceries", amount: 45.99 },
    {id: 2, name: "Gas", amount: 30.00 },
    {id: 3, name: "Online Shopping", amount: 120.50},
  ]);

  const handleScanReceipt = () => alert("Opening receipt scanner...");
  const handleManualEntry = () => alert("Opening manual entry form...");
  const handleVoiceInput = () => alert("Listening for voice input...");
  const handleReport = () => alert("Opening reports...");
  const handleSettings = () => alert("Opening settings...");

  return (
    <>
      <div className="container">
        <header className='header'>
          <h1>ExpenseFlow</h1>
        </header>

        <main className='main'>
          <h2>Get Started!</h2>

          <div className='buttons'>
            <button onClick={handleScanReceipt} className='button scan'>
              📸 Scan Receipt
            </button>
            <button onClick={handleManualEntry} className='button manual'>
              ✍️ Enter Manually
            </button>
            <button onClick={handleVoiceInput} className='button voice'>
              🎙️ Voice Input
            </button>
          </div>

          <section className='transactions'>
            <h2>Recent Transactions</h2>
            {transactions.length === 0 ? (
              <p>No recent transactions yet.</p>
            ) : (
              <ul>
                {transactions.map((transactions) => (
                  <li key={transactions.id} className='transaction'>
                    <span>{transactions.name}</span>
                    <span className='amount'>${transactions.amount.toFixed(2)}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </main>

        <footer className='footer'>

        <div className='buttons'>
            <div className='button-container'>
              <button onClick={handleScanReceipt} className='scan_footer'>
                Scan
              </button>
              <button onClick={handleReport} className='report'>
                Report
              </button>
              <button onClick={handleSettings} className='settings'>
                Settings
              </button>
            </div>
          </div>
          &copy; 2025 AI Budgeting Assistant. All Rights Reserved.
        </footer>
      </div>
    </>
  )
}

export default App
