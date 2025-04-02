import React, { useState } from 'react';
import { TextField, Button, Box, Typography, InputAdornment } from '@mui/material';
import AuthHeader from '../AuthHeader';
import { Person, Email, Phone, Lock } from '@mui/icons-material';
import '../Home.css'; // Import to apply header styles

const SignUp = () => {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [phone, setPhone] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');

    const handleSignUp = (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            alert("Passwords do not match!");
            return;
        }
        
        fetch("/api/signup", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ username, email, phone, password }),
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            if (data.userId) {
                alert('Registration successful!');
                window.location.href = '/login';
            }
        })
        .catch(error => {
            console.error('Registration Error:', error);
            const errorMessage = error.response?.data?.message || 
                                error.message || 
                                'Registration failed. Please try again.';
            alert(errorMessage);
        });
    };

    return (
        <Box sx={{ minHeight: '100vh', background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)' }}>
            <AuthHeader />
            <Box sx={{ 
                maxWidth: 400, 
                mx: 'auto', 
                mt: 8,
                p: 4,
                borderRadius: 2,
                backgroundColor: 'rgba(255, 255, 255, 0.95)',
                boxShadow: '0 8px 32px 0 rgba(31, 38, 135, 0.37)'
            }}>
                <Typography variant="h4" gutterBottom sx={{ 
                    color: '#1a237e', 
                    fontWeight: 'bold',
                    textAlign: 'center',
                    mb: 4
                }}>
                    Create Account
                </Typography>
                <form onSubmit={handleSignUp}>
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Username"
                        required
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Person sx={{ color: '#1a237e' }} />
                                </InputAdornment>
                            ),
                        }}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                borderRadius: 2,
                                '&.Mui-focused fieldset': {
                                    borderColor: '#1a237e',
                                },
                            }
                        }}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Email"
                        type="email"
                        required
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Email sx={{ color: '#1a237e' }} />
                                </InputAdornment>
                            ),
                        }}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                borderRadius: 2,
                                '&.Mui-focused fieldset': {
                                    borderColor: '#1a237e',
                                },
                            }
                        }}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Phone Number"
                        type="tel"
                        required
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Phone sx={{ color: '#1a237e' }} />
                                </InputAdornment>
                            ),
                        }}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                borderRadius: 2,
                                '&.Mui-focused fieldset': {
                                    borderColor: '#1a237e',
                                },
                            }
                        }}
                        onChange={(e) => setPhone(e.target.value)}
                    />
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Password"
                        type="password"
                        required
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Lock sx={{ color: '#1a237e' }} />
                                </InputAdornment>
                            ),
                        }}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                borderRadius: 2,
                                '&.Mui-focused fieldset': {
                                    borderColor: '#1a237e',
                                },
                            }
                        }}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Confirm Password"
                        type="password"
                        required
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Lock sx={{ color: '#1a237e' }} />
                                </InputAdornment>
                            ),
                        }}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                borderRadius: 2,
                                '&.Mui-focused fieldset': {
                                    borderColor: '#1a237e',
                                },
                            }
                        }}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <Button 
                        type="submit" 
                        fullWidth
                        variant="contained"
                        sx={{
                            mt: 3,
                            py: 1.5,
                            borderRadius: 2,
                            background: 'linear-gradient(45deg, #1a237e 30%, #0d47a1 90%)',
                            '&:hover': {
                                transform: 'scale(1.02)',
                                boxShadow: '0 4px 20px rgba(26, 35, 126, 0.3)'
                            },
                            transition: 'all 0.3s ease'
                        }}
                    >
                        Sign Up
                    </Button>
                    <Typography sx={{ 
                        textAlign: 'center', 
                        mt: 2,
                        color: '#666',
                        '& a': {
                            color: '#1a237e',
                            fontWeight: 'bold',
                            textDecoration: 'none',
                            '&:hover': {
                                textDecoration: 'underline'
                            }
                        }
                    }}>
                        Already have an account? <a href="/login">Login here</a>
                    </Typography>
                </form>
            </Box>
        </Box>
    );
};

export default SignUp; 