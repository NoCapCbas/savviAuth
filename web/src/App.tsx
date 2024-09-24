import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import { useState } from 'react';
import './App.css';
import AuthenticationPage from './components/pages/AuthenticationPage';

function ProtectedRoute({ children }: { children: JSX.Element }) {
  const isAuthenticated = localStorage.getItem('isAuthenticated');
  return isAuthenticated ? children : <Navigate to="/login" />;
}

function HomePage() {
  return <h2 className="text-2xl font-bold">Home Page - Protected</h2>;
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<AuthenticationPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <HomePage />
            </ProtectedRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
