import React from 'react';

const Logo = () => (
    <svg width="50" height="50" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg">
        <circle cx="25" cy="25" r="20" fill="url(#logoGradient)" />
        <defs>
            <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style={{ stopColor: '#1a237e' }} />
                <stop offset="100%" style={{ stopColor: '#0d47a1' }} />
            </linearGradient>
        </defs>
        <text x="25" y="30" fontSize="15" textAnchor="middle" fill="white">CTI</text>
    </svg>
);

export default Logo; 