import React from 'react';
import { AppBar, Toolbar, Typography, Container } from '@mui/material';
import { Link } from 'react-router-dom';
import Logo from './Logo';

const Layout = ({ children, showHeader = true }) => {
    return (
        <div>
            {showHeader && (
                <AppBar position="static" sx={{ 
                    backgroundColor: 'linear-gradient(45deg, #1a237e 0%, #0d47a1 100%)',
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    zIndex: 1000,
                    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)'
                }}>
                    <Toolbar>
                        <Logo />
                        <Typography variant="h6" component="div" sx={{ 
                            flexGrow: 1,
                            ml: 2,
                            color: 'white',
                            fontWeight: 'bold'
                        }}>
                            Cyber Threat Intelligence
                        </Typography>
                        <div style={{ flexGrow: 1 }} />
                        <Link to="/login" style={{ color: 'white', textDecoration: 'none', margin: '0 10px' }}>Login</Link>
                        <Link to="/signup" style={{ color: 'white', textDecoration: 'none', margin: '0 10px' }}>Sign Up</Link>
                    </Toolbar>
                </AppBar>
            )}
            <Container sx={{ pt: showHeader ? 10 : 0 }}>
                {children}
            </Container>
            {showHeader && (
                <footer style={{ textAlign: 'center', padding: '20px', background: '#f1f1f1' }}>
                    <Typography variant="body2">© 2025 Cyber Threat Intelligence System</Typography>
                </footer>
            )}
        </div>
    );
};

export default Layout; 