import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './components/Auth/Login';
import SignUp from './components/Auth/SignUp';
import Home from './components/Home';
import UserDashboard from './components/UserDashboard';
import Layout from './components/Layout';
import './App.css';

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Layout showHeader={false}><Home /></Layout>} />
                <Route path="/dashboard" element={<Layout showHeader={false}><UserDashboard /></Layout>} />
                <Route path="/login" element={<Login />} />
                <Route path="/signup" element={<SignUp />} />
            </Routes>
        </Router>
    );
}

export default App; 