import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import Logo from './Logo';
import './Auth/Auth.css';

const AuthHeader = () => {
    return (
        <Box className="header">
            <Logo />
            <Typography variant="h6" style={{ marginLeft: '10px', color: 'white' }}>
                Cyber Threat Intelligence
            </Typography>
            <div style={{ flexGrow: 1 }} />
            <Button variant="outlined" color="secondary" href="/" style={{ margin: '0 10px' }}>Home</Button>
        </Box>
    );
};

export default AuthHeader; 