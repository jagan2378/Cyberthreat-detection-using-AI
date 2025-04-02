import React, { useState } from 'react';
import { TextField, Button, Box, Typography, InputAdornment } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import AuthHeader from '../AuthHeader';
import { Email, Lock } from '@mui/icons-material';
import '../Home.css'; // Import to apply header styles
import axios from 'axios';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('http://localhost:5000/api/login', {
                email: email,
                password
            });
            
            localStorage.setItem('authToken', response.data.token);
            localStorage.setItem('userId', response.data.userId);
            navigate('/dashboard');
        } catch (err) {
            setError('Invalid credentials');
        }
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
                    User Login
                </Typography>
                {error && (
                    <Typography color="error" sx={{ mt: 1, textAlign: 'center' }}>
                        {error}
                    </Typography>
                )}
                <form onSubmit={handleSubmit}>
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Email"
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
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
                    />
                    <TextField
                        fullWidth
                        margin="normal"
                        label="Password"
                        type="password"
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
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
                        Login
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
                        New user? <a href="/signup">Create account</a>
                    </Typography>
                </form>
            </Box>
        </Box>
    );
};

export default Login; 