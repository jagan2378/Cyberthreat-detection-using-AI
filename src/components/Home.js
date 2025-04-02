import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import './Home.css'; // Create a separate CSS file for home styles
import Logo from './Logo'; // Import your custom SVG logo
import { motion } from 'framer-motion';
import { Link as RouterLink } from 'react-router-dom';

const Home = () => {
    return (
        <Box sx={{ 
            position: 'relative', 
            overflow: 'hidden',
            background: 'linear-gradient(135deg, #0d0d26 0%, #1a1a40 100%)',
            minHeight: '100vh'
        }}>
            {/* Animated Background Particles */}
            <Box sx={{
                position: 'absolute',
                width: '100%',
                height: '100%',
                zIndex: 0,
                background: 'radial-gradient(circle at 50% 50%, rgba(0, 255, 157, 0.1) 0%, transparent 70%)'
            }}/>

            {/* Header Section */}
            <Box 
                component={motion.div}
                initial={{ y: -100 }}
                animate={{ y: 0 }}
                transition={{ duration: 0.8 }}
                className="header"
                sx={{
                    backdropFilter: 'blur(10px)',
                    backgroundColor: 'rgba(26, 26, 64, 0.8)',
                    borderBottom: '1px solid rgba(0, 255, 157, 0.1)'
                }}
            >
                <Logo />
                <Typography variant="h6" style={{ 
                    marginLeft: '10px', 
                    color: 'rgba(0, 255, 157, 0.9)',
                    fontWeight: 500,
                    letterSpacing: '1px'
                }}>
                    Cyber Threat Intelligence
                </Typography>
                <div style={{ flexGrow: 1 }} />
                <Button 
                    variant="outlined" 
                    sx={{
                        margin: '0 10px',
                        color: 'rgba(0, 255, 157, 0.9)',
                        borderColor: 'rgba(0, 255, 157, 0.3)',
                        '&:hover': {
                            borderColor: 'rgba(0, 255, 157, 0.7)',
                            backgroundColor: 'rgba(0, 255, 157, 0.05)'
                        }
                    }}
                    href="/"
                >
                    Home
                </Button>
                <Button variant="outlined" color="secondary" href="#about" style={{ margin: '0 10px' }}>About Us</Button>
                <Button variant="outlined" color="secondary" href="#features" style={{ margin: '0 10px' }}>Features</Button>
                <Button variant="outlined" color="secondary" href="#contact" style={{ margin: '0 10px' }}>Contact Us</Button>
                <Button variant="contained" color="primary" className="login-button" href="/login" style={{ margin: '0 10px' }}>
                    Login
                </Button>
            </Box>

            {/* Welcome Section */}
            <Box className="hero-section" id="welcome">
                <Typography variant="h2" className="hero-title">
                    Welcome to Cyber Threat Intelligence System
                </Typography>
                <Typography variant="body1" className="hero-subtitle">
                    Protecting your digital assets with real-time threat intelligence. Our platform offers comprehensive solutions to safeguard your organization against cyber threats.
                </Typography>
                <Button variant="contained" color="primary" className="hero-button" component={RouterLink} to="/login">
                    Get Started
                </Button>
            </Box>

            {/* About Us Section */}
            <Box id="about" sx={{ mt: 4, p: 2, textAlign: 'center' }}>
                <Typography variant="h4" gutterBottom>About Us</Typography>
                <Typography>
                    Our Cyber Threat Intelligence System is designed to provide organizations with the tools they need to protect their digital assets. We understand the importance of cybersecurity in today's digital landscape, and our platform offers a range of features to help you stay ahead of potential threats. Our team of experts continuously monitors the threat landscape to provide you with the most up-to-date information and insights. With our system, you can make informed decisions to safeguard your organization and ensure the safety of your data.
                </Typography>
            </Box>

            {/* Features Section */}
            <Box id="features" sx={{ mt: 4, p: 2, textAlign: 'center' }}>
                <Typography variant="h4" gutterBottom>Features</Typography>
                <Typography component="div"> {/* Ensure Typography does not render as <p> */}
                    Our platform offers a variety of features designed to enhance your cybersecurity posture. Key features include:
                </Typography>
                <Box component="ul" sx={{ pl: 2 }}>
                    <li>Real-time Threat Detection: Monitor and respond to threats as they occur.</li>
                    <li>Risk Analysis: Comprehensive assessments to identify vulnerabilities.</li>
                    <li>API Integration: Seamless integration with existing systems for enhanced functionality.</li>
                    <li>User-friendly Dashboard: Easy navigation and access to critical information.</li>
                    <li>Custom Alerts: Set up notifications for specific threat levels or incidents.</li>
                </Box>
            </Box>

            {/* Contact Us Section */}
            <Box id="contact" sx={{ mt: 4, p: 2,textAlign: 'center' }}>
                <Typography variant="h4" gutterBottom>Contact Us</Typography>
                <Typography>
                    We would love to hear from you! If you have any questions or need assistance, feel free to reach out to us through the following channels:
                </Typography>
                <Box component="ul" sx={{ pl: 2 }}>
                    <li>Email: support@cyberthreatintelligence.com</li>
                    <li>Phone: +1 (555) 123-4567</li>
                    <li>Twitter: @CyberThreatIntel</li>
                    <li>Instagram: @CyberThreatIntelligence</li>
                </Box>
            </Box>

            {/* Footer Section */}
            <Box className="footer" sx={{ mt: 4, p: 2, textAlign: 'center', backgroundColor: '#333', color: 'white' }}>
                <Typography variant="body2">© 2025 Cyber Threat Intelligence System. All rights reserved.</Typography>
                <Typography variant="body2">Follow us on social media for the latest updates!</Typography>
            </Box>

            {/* Replaced Particles with a simple background effect */}
            <Box
                sx={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    zIndex: -1,
                    background: 'linear-gradient(135deg, #0d0d2b 0%, #1a1a40 100%)',
                    overflow: 'hidden',
                }}
            >
                {/* Create some simple CSS dots as a fallback */}
                {Array.from({ length: 50 }).map((_, i) => (
                    <Box
                        key={i}
                        sx={{
                            position: 'absolute',
                            width: Math.random() * 5 + 2,
                            height: Math.random() * 5 + 2,
                            backgroundColor: 'rgba(0, 255, 157, 0.7)',
                            borderRadius: '50%',
                            top: `${Math.random() * 100}%`,
                            left: `${Math.random() * 100}%`,
                            animation: `pulse 4s infinite ease-in-out ${Math.random() * 5}s`,
                            '@keyframes pulse': {
                                '0%': { opacity: 0.3, transform: 'scale(1)' },
                                '50%': { opacity: 0.8, transform: 'scale(1.5)' },
                                '100%': { opacity: 0.3, transform: 'scale(1)' }
                            }
                        }}
                    />
                ))}
            </Box>
        </Box>
    );
};

export default Home;
