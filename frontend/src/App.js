import React, { useState } from 'react';
import { HashRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { LayoutGrid, PlayCircle, ShieldAlert, Bell } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResults from './pages/ScanResults';
import Vulnerabilities from './pages/Vulnerabilities';

function App() {
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  return (
    <Router>
      <div className="app-container">
        {/* Sidebar Navigation */}
        <aside className="sidebar">
          <div className="logo-container">
            <div className="logo-icon">S</div>
            <span className="logo-text">SentinelAI</span>
          </div>
          
          <nav>
            <ul className="nav-links">
              <li className="nav-item">
                <NavLink to="/" end>
                  <LayoutGrid />
                  Dashboard
                </NavLink>
              </li>
              <li className="nav-item">
                <NavLink to="/new-scan">
                  <PlayCircle />
                  New Scan
                </NavLink>
              </li>
              <li className="nav-item">
                <NavLink to="/vulnerabilities">
                  <ShieldAlert />
                  Vulnerabilities
                </NavLink>
              </li>
            </ul>
          </nav>
          
          <div className="sidebar-footer">
            <p>SentinelAI v1.0.0</p>
            <p>AI Security Scanner</p>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard addToast={addToast} />} />
            <Route path="/new-scan" element={<NewScan addToast={addToast} />} />
            <Route path="/scan/:scanId" element={<ScanResults addToast={addToast} />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities addToast={addToast} />} />
          </Routes>
        </main>

        {/* Toast Container */}
        <div className="toast-container">
          {toasts.map((toast) => (
            <div key={toast.id} className={`toast toast-${toast.type}`}>
              <Bell size={16} />
              <span>{toast.message}</span>
            </div>
          ))}
        </div>
      </div>
    </Router>
  );
}

export default App;
