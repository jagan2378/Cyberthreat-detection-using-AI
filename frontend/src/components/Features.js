import React from 'react';
import { Box, Typography, Grid } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import AssessmentIcon from '@mui/icons-material/Assessment';
import ApiIcon from '@mui/icons-material/Api';

const Features = () => {
    return (
        <Box sx={{ mt: 4, textAlign: 'center' }}>
            <Typography variant="h4" gutterBottom>Features</Typography>
            <Grid container spacing={4}>
                <Grid item xs={12} sm={4}>
                    <Box sx={{ textAlign: 'center' }}>
                        <SecurityIcon fontSize="large" style={{ color: '#6a11cb' }} />
                        <Typography variant="h6">Real-time Threat Detection</Typography>
                        <Typography variant="body1">Stay ahead of threats with real-time monitoring.</Typography>
                    </Box>
                </Grid>
                <Grid item xs={12} sm={4}>
                    <Box sx={{ textAlign: 'center' }}>
                        <AssessmentIcon fontSize="large" style={{ color: '#2575fc' }} />
                        <Typography variant="h6">Risk Analysis</Typography>
                        <Typography variant="body1">Comprehensive risk assessments for informed decisions.</Typography>
                    </Box>
                </Grid>
                <Grid item xs={12} sm={4}>
                    <Box sx={{ textAlign: 'center' }}>
                        <ApiIcon fontSize="large" style={{ color: '#6a11cb' }} />
                        <Typography variant="h6">API Integration</Typography>
                        <Typography variant="body1">Seamless integration with multiple APIs for enhanced functionality.</Typography>
                    </Box>
                </Grid>
            </Grid>
        </Box>
    );
};

export default Features; 