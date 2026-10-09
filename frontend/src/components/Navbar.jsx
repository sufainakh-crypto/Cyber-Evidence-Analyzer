import React from 'react';
import { NavLink } from 'react-router-dom';

function Navbar() {
  return (
    <header className="navbar">
      <div className="navbar-container">
        <NavLink to="/" className="navbar-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-text">Cyber Evidence Analyzer</span>
        </NavLink>
        <nav className="navbar-links">
          <NavLink to="/" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')} end>
            Dashboard
          </NavLink>
          <NavLink to="/analyze" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            Analyze
          </NavLink>
          <NavLink to="/evidence" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            Evidence
          </NavLink>
          <NavLink to="/correlation" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            Correlations
          </NavLink>
          <NavLink to="/cases" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            Cases
          </NavLink>
          <NavLink to="/reports" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            Reports
          </NavLink>
        </nav>
      </div>
    </header>
  );
}

export default Navbar;
