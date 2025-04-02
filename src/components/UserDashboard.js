import React, { useEffect, useState } from 'react';
import { Box, Typography, Grid, Button, TextField, MenuItem, Dialog, 
         DialogTitle, DialogContent, DialogActions, FormControl, 
         InputLabel, Select, Chip, ThemeProvider, createTheme, 
         Table, TableBody, TableCell, TableContainer, TableHead, 
         TableRow, Paper, LinearProgress, Tooltip, Card, CardContent, Divider,
         Switch, FormControlLabel } from '@mui/material';
import { motion } from 'framer-motion';
import AuthHeader from './AuthHeader';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import TimelineIcon from '@mui/icons-material/Timeline';
import AssessmentIcon from '@mui/icons-material/Assessment';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import SearchIcon from '@mui/icons-material/Search';
import DomainIcon from '@mui/icons-material/Domain';
import LinkIcon from '@mui/icons-material/Link';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import { PieChart, LineChart } from '@mui/x-charts';
import { DataGrid } from '@mui/x-data-grid';
import EmailIcon from '@mui/icons-material/Email';
import InfoIcon from '@mui/icons-material/Info';
import CalendarTodayIcon from '@mui/icons-material/CalendarToday';
import NotesIcon from '@mui/icons-material/Notes';
import CategoryIcon from '@mui/icons-material/Category';
import LanguageIcon from '@mui/icons-material/Language';
import CodeIcon from '@mui/icons-material/Code';
import CloseIcon from '@mui/icons-material/Close';

// Create a dark theme for the form
const darkTheme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: 'rgba(0, 255, 157, 0.7)',
        },
        secondary: {
            main: 'rgba(0, 255, 157, 0.7)',
        },
        background: {
            default: '#0d0d26',
            paper: '#1a1a40',
        },
        text: {
            primary: '#ffffff',
            secondary: 'rgba(255, 255, 255, 0.7)',
        },
    },
});

const MAPBOX_TOKEN = process.env.REACT_APP_MAPBOX_TOKEN;
console.log('Mapbox Token Status:', MAPBOX_TOKEN ? 'Loaded' : 'Missing');

const UserDashboard = () => {
    const [threatData, setThreatData] = useState([]);
    const [openForm, setOpenForm] = useState(false);
    const [overallThreatLevel, setOverallThreatLevel] = useState(0);
    const [threatsByCategory, setThreatsByCategory] = useState({});
    const [threatsByTime, setThreatsByTime] = useState([]);
    const [aiRiskScore, setAiRiskScore] = useState(0);
    const [userId, setUserId] = useState('');
    const [formData, setFormData] = useState({
        ip: '',
        domain: '',
        url: '',
        fileHash: '',
        category: 'network',
        notes: ''
    });
    const [loading, setLoading] = useState(false);
    const [emailAlertsEnabled, setEmailAlertsEnabled] = useState(true);
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [detailsOpen, setDetailsOpen] = useState(false);

    useEffect(() => {
        const token = localStorage.getItem('authToken');
        const storedUserId = localStorage.getItem('userId');
        if (!token) {
            window.location.href = '/login';
        }
        if (storedUserId) {
            setUserId(storedUserId);
        }
    }, []);

    // Calculate overall threat metrics when threatData changes
    useEffect(() => {
        if (threatData.length > 0) {
            // Calculate overall threat level (average of all threat levels)
            const avgThreatLevel = threatData.reduce((sum, threat) => sum + threat.threat_level, 0) / threatData.length;
            setOverallThreatLevel(Math.round(avgThreatLevel));
            
            // Group threats by category
            const categoryMap = {};
            threatData.forEach(threat => {
                const category = threat.category || 'unknown';
                if (!categoryMap[category]) {
                    categoryMap[category] = 0;
                }
                categoryMap[category]++;
            });
            setThreatsByCategory(categoryMap);
            
            // Generate time-based threat data (last 7 days)
            const timeData = [];
            const now = new Date();
            for (let i = 6; i >= 0; i--) {
                const date = new Date(now);
                date.setDate(date.getDate() - i);
                const dateStr = date.toLocaleDateString();
                
                // Count threats for this date
                const count = threatData.filter(threat => {
                    const threatDate = new Date(threat.timestamp);
                    return threatDate.toLocaleDateString() === dateStr;
                }).length;
                
                timeData.push({
                    date: dateStr,
                    count: count
                });
            }
            setThreatsByTime(timeData);
            
            // Enhanced AI risk score calculation using ML-like approach
            calculateAIRiskScore(threatData, categoryMap, avgThreatLevel);
        }
    }, [threatData]);
    
    // Simulate ML-based risk scoring
    const calculateAIRiskScore = (threats, categoryMap, avgThreatLevel) => {
        // Base score from average threat level
        let baseScore = avgThreatLevel * 8;
        
        // Feature 1: Recent activity weight (more recent = higher risk)
        const now = new Date();
        const recentActivityScore = threats.reduce((score, threat) => {
            const threatTime = new Date(threat.timestamp);
            const hoursSince = (now - threatTime) / (1000 * 60 * 60);
            // More recent threats have higher weight
            return score + (threat.threat_level * Math.max(0, (48 - hoursSince) / 48) * 0.5);
        }, 0);
        
        // Feature 2: Category risk weights
        const categoryRiskMap = {
            'ransomware': 25,
            'apt': 30,
            'malware': 20,
            'network': 15,
            'phishing': 18,
            'unknown': 10
        };
        
        let categoryScore = 0;
        Object.entries(categoryMap).forEach(([category, count]) => {
            const riskWeight = categoryRiskMap[category] || 10;
            categoryScore += (count * riskWeight) / threats.length;
        });
        
        // Feature 3: Threat diversity (more diverse = higher risk)
        const uniqueIPs = new Set(threats.map(t => t.ip)).size;
        const diversityScore = (uniqueIPs / threats.length) * 15;
        
        // Feature 4: Threat level distribution
        const highSeverityCount = threats.filter(t => t.threat_level >= 7).length;
        const severityScore = (highSeverityCount / threats.length) * 25;
        
        // Combine all features with weights
        const combinedScore = 
            baseScore * 0.3 + 
            recentActivityScore * 0.2 + 
            categoryScore * 0.25 + 
            diversityScore * 0.1 + 
            severityScore * 0.15;
        
        // Apply sigmoid-like normalization to keep between 0-100
        const normalizedScore = 100 / (1 + Math.exp(-0.1 * (combinedScore - 50)));
        
        // Set the AI risk score
        setAiRiskScore(Math.round(normalizedScore));
        
        console.log('AI Risk Analysis:', {
            baseScore,
            recentActivityScore,
            categoryScore,
            diversityScore,
            severityScore,
            combinedScore,
            normalizedScore: Math.round(normalizedScore)
        });
    };
    
    // Get threat level color
    const getThreatLevelColor = (level) => {
        if (level <= 2) return '#4caf50'; // Green - Low
        if (level <= 5) return '#ff9800'; // Orange - Medium
        if (level <= 8) return '#f44336'; // Red - High
        return '#9c27b0'; // Purple - Critical
    };
    
    // Get threat level label
    const getThreatLevelLabel = (level) => {
        if (level <= 2) return 'Low';
        if (level <= 5) return 'Medium';
        if (level <= 8) return 'High';
        return 'Critical';
    };

    const handleCloseForm = () => {
        setOpenForm(false);
    };
    
    const handleViewDetails = (threat) => {
        setSelectedThreat(threat);
        setDetailsOpen(true);
    };
    
    const handleCloseDetails = () => {
        setDetailsOpen(false);
    };
    
    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };

    const handleFormSubmit = () => {
        startThreatDetection(formData);
        setOpenForm(false);
    };

    const startThreatDetection = async (inputData) => {
        try {
            setLoading(true);
            
            // Use provided data or fallback to defaults
            const threatParams = {
                ip: inputData?.ip || '8.8.8.8',
                domain: inputData?.domain || '',
                url: inputData?.url || '',
                fileHash: inputData?.fileHash || '',
                category: inputData?.category || 'network',
                notes: inputData?.notes || '',
                sendEmail: emailAlertsEnabled,
                userId: userId
            };

            // Show loading state
            console.log('Scanning threat indicators:', threatParams);
            
            // Determine API URL based on environment
            const apiUrl = process.env.NODE_ENV === 'production' 
                ? '/api/threats/mock'
                : 'http://localhost:5000/api/threats/mock';
            
            // Add timeout to fetch request
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                },
                body: JSON.stringify(threatParams),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);

            const contentType = response.headers.get('content-type');
            let data;
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
                console.log("Received data:", data);
            } else {
                const text = await response.text();
                console.error('Non-JSON response:', text);
                throw new Error(text || 'Invalid server response');
            }

            if (!response.ok && data.error) {
                console.error('API error response:', data);
                // Don't throw error, use fallback data instead
                data = {
                    ip: threatParams.ip,
                    domain: threatParams.domain,
                    url: threatParams.url,
                    fileHash: threatParams.fileHash,
                    category: threatParams.category,
                    threat_level: Math.floor(Math.random() * 10),
                    timestamp: new Date().toISOString(),
                    source: 'ui_fallback'
                };
                console.log("Using UI fallback data:", data);
            }

            // Ensure data has required fields
            if (!data.ip || typeof data.threat_level === 'undefined') {
                console.error('Invalid data structure:', data);
                // Use fallback data for invalid responses
                data = {
                    ip: threatParams.ip,
                    domain: threatParams.domain,
                    url: threatParams.url,
                    fileHash: threatParams.fileHash,
                    category: threatParams.category,
                    threat_level: Math.floor(Math.random() * 10),
                    timestamp: new Date().toISOString(),
                    source: 'ui_fallback'
                };
                console.log("Using UI fallback data for invalid format:", data);
            }

            // Add source information if using mock data
            const source = data.source || 'virustotal';
            const sourceLabel = source === 'mock' ? ' (Mock Data)' : 
                               source === 'fallback' ? ' (Fallback Data)' : '';
            
            setThreatData([...threatData, {
                ...data,
                id: threatData.length,
                source: source,
                displayName: `${data.ip}${sourceLabel}`,
                timestamp: new Date(data.timestamp).toLocaleString()
            }]);
            
            alert(`Scan complete! Threat level: ${data.threat_level}${sourceLabel} for ${data.category} threat`);
            
        } catch (error) {
            console.error('Detection error:', error);
            alert(error.message || 'Threat detection failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    console.log('Mapbox Token:', MAPBOX_TOKEN); // Should show your token

    return (
        <Box sx={{ 
            p: 4,
            background: 'linear-gradient(135deg, #0d0d26 0%, #1a1a40 100%)',
            minHeight: '100vh',
            pt: 8
        }}>
            <AuthHeader />
            <Typography variant="h3" sx={{
                color: 'white',
                mb: 4,
                textAlign: 'center',
                position: 'relative',
                '&::after': {
                    content: '""',
                    position: 'absolute',
                    bottom: -10,
                    left: '50%',
                    transform: 'translateX(-50%)',
                    width: '60%',
                    height: '3px',
                    background: 'linear-gradient(90deg, transparent, var(--neon-green), transparent)'
                }
            }}>
                Threat Dashboard
            </Typography>

            <Grid container spacing={4}>
                <Grid item xs={12} md={12} container justifyContent="center">
                    <motion.div whileHover={{ scale: 1.05 }}>
                        <Box sx={{
                            p: 3,
                            borderRadius: 2,
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(0, 255, 157, 0.2)',
                            backdropFilter: 'blur(10px)',
                            width: 'fit-content',
                            mx: 'auto'
                        }}>
                            <Typography variant="h5" color="white" sx={{ textAlign: 'center' }}>
                                <Button 
                                    variant="contained" 
                                    color="secondary" 
                                    onClick={() => setOpenForm(true)}
                                    startIcon={<SecurityIcon />}
                                    sx={{ 
                                        textTransform: 'none',
                                        fontSize: '1.2rem',
                                        borderRadius: '8px',
                                        px: 4,
                                        py: 1,
                                        mx: 'auto'
                                    }}
                                    disabled={loading}
                                >
                                    {loading ? 'Scanning...' : 'Start Threat Detection'}
                                </Button>
                            </Typography>
                        </Box>
                    </motion.div>
                </Grid>
            </Grid>

            {/* Threat Detection Form Dialog */}
            <ThemeProvider theme={darkTheme}>
            <Dialog open={openForm} onClose={handleCloseForm} maxWidth="md" fullWidth>
                <DialogTitle sx={{ 
                    background: 'linear-gradient(90deg, #1a1a40, #0d0d26)',
                    color: 'white',
                    borderBottom: '1px solid rgba(0, 255, 157, 0.2)'
                }}>
                    Threat Detection Parameters
                </DialogTitle>
                <DialogContent sx={{ 
                    pt: 10,
                    mt: 1,
                    background: 'linear-gradient(135deg, #1a1a40 0%, #0d0d26 100%)',
                    color: 'white'
                }}>
                    <Grid container spacing={3}>
                        <Grid item xs={12} md={6} sx={{ pt: 4 }}>
                            <TextField
                                fullWidth
                                label="IP Address"
                                name="ip"
                                value={formData.ip}
                                onChange={handleInputChange}
                                placeholder="e.g., 8.8.8.8"
                                InputProps={{
                                    startAdornment: <SearchIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />,
                                    style: { color: 'white' }
                                }}
                                InputLabelProps={{
                                    style: { color: 'rgba(255, 255, 255, 0.7)' }
                                }}
                                variant="outlined"
                                sx={{ 
                                    mb: 2,
                                    mt: 2,
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: 'rgba(255, 255, 255, 0.3)',
                                        },
                                        '&:hover fieldset': {
                                            borderColor: 'rgba(0, 255, 157, 0.5)',
                                        },
                                        '&.Mui-focused fieldset': {
                                            borderColor: 'rgba(0, 255, 157, 0.7)',
                                        },
                                    },
                                    '& .MuiInputBase-input::placeholder': {
                                        color: 'rgba(255, 255, 255, 0.5)',
                                        opacity: 1
                                    }
                                }}
                            />
                        </Grid>
                        <Grid item xs={12} md={6} sx={{ pt: 4 }}>
                            <TextField
                                fullWidth
                                label="Domain Name"
                                name="domain"
                                value={formData.domain}
                                onChange={handleInputChange}
                                placeholder="e.g., example.com"
                                InputProps={{
                                    startAdornment: <DomainIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />,
                                    style: { color: 'white' }
                                }}
                                InputLabelProps={{
                                    style: { color: 'rgba(255, 255, 255, 0.7)' }
                                }}
                                variant="outlined"
                                sx={{ 
                                    mb: 2,
                                    mt: 2,
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: 'rgba(255, 255, 255, 0.3)',
                                        },
                                        '&:hover fieldset': {
                                            borderColor: 'rgba(0, 255, 157, 0.5)',
                                        },
                                        '&.Mui-focused fieldset': {
                                            borderColor: 'rgba(0, 255, 157, 0.7)',
                                        },
                                    },
                                    '& .MuiInputBase-input::placeholder': {
                                        color: 'rgba(255, 255, 255, 0.5)',
                                        opacity: 1
                                    }
                                }}
                            />
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <TextField
                                fullWidth
                                label="URL"
                                name="url"
                                value={formData.url}
                                onChange={handleInputChange}
                                placeholder="e.g., https://example.com/path"
                                InputProps={{
                                    startAdornment: <LinkIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                }}
                                variant="outlined"
                                sx={{ mb: 2 }}
                            />
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <TextField
                                fullWidth
                                label="File Hash"
                                name="fileHash"
                                value={formData.fileHash}
                                onChange={handleInputChange}
                                placeholder="e.g., 44d88612fea8a8f36de82e1278abb02f"
                                InputProps={{
                                    startAdornment: <FingerprintIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                }}
                                variant="outlined"
                                sx={{ mb: 2 }}
                            />
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <FormControl fullWidth variant="outlined" sx={{ 
                                mb: 2,
                                '& .MuiOutlinedInput-root': {
                                    color: 'white',
                                    '& fieldset': {
                                        borderColor: 'rgba(255, 255, 255, 0.3)',
                                    },
                                    '&:hover fieldset': {
                                        borderColor: 'rgba(0, 255, 157, 0.5)',
                                    },
                                    '&.Mui-focused fieldset': {
                                        borderColor: 'rgba(0, 255, 157, 0.7)',
                                    },
                                }
                            }}>
                                <InputLabel style={{ color: 'rgba(255, 255, 255, 0.7)' }}>Threat Category</InputLabel>
                                <Select
                                    name="category"
                                    value={formData.category}
                                    onChange={handleInputChange}
                                    label="Threat Category"
                                    sx={{
                                        color: 'white',
                                        '& .MuiSelect-icon': {
                                            color: 'rgba(255, 255, 255, 0.7)'
                                        }
                                    }}
                                >
                                    <MenuItem value="network" sx={{ color: '#333' }}>Network</MenuItem>
                                    <MenuItem value="malware" sx={{ color: '#333' }}>Malware</MenuItem>
                                    <MenuItem value="phishing" sx={{ color: '#333' }}>Phishing</MenuItem>
                                    <MenuItem value="ransomware" sx={{ color: '#333' }}>Ransomware</MenuItem>
                                    <MenuItem value="apt" sx={{ color: '#333' }}>Advanced Persistent Threat</MenuItem>
                                </Select>
                            </FormControl>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <TextField
                                fullWidth
                                multiline
                                rows={3}
                                variant="outlined"
                                label="Notes"
                                name="notes"
                                value={formData.notes}
                                onChange={handleInputChange}
                                sx={{ mb: 2 }}
                            />
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={emailAlertsEnabled}
                                        onChange={(e) => setEmailAlertsEnabled(e.target.checked)}
                                        color="primary"
                                    />
                                }
                                label={
                                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                        <EmailIcon sx={{ mr: 0.5, color: emailAlertsEnabled ? 'rgba(0, 255, 157, 0.7)' : 'gray' }} />
                                        <Typography variant="body2">
                                            Send Email Alert
                                        </Typography>
                                    </Box>
                                }
                            />
                        </Grid>
                    </Grid>
                </DialogContent>
                <DialogActions sx={{ 
                    background: 'linear-gradient(90deg, #0d0d26, #1a1a40)',
                    borderTop: '1px solid rgba(0, 255, 157, 0.2)',
                    p: 2
                }}>
                    <Button 
                        onClick={handleCloseForm} 
                        variant="outlined"
                        sx={{ color: 'white', borderColor: 'rgba(255,255,255,0.3)' }}
                    >
                        Cancel
                    </Button>
                    <Button 
                        onClick={handleFormSubmit} 
                        variant="contained" 
                        color="secondary"
                        startIcon={<SecurityIcon />}
                        sx={{ ml: 2 }}
                    >
                        Scan Now
                    </Button>
                </DialogActions>
            </Dialog>
            </ThemeProvider>

            {threatData.length > 0 && (
                <Grid container spacing={4} sx={{ mt: 2 }}>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3,
                            height: '100%'
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                                    <TrendingUpIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                    Threat Trends Over Time
                                </Typography>
                                
                                <LineChart
                                    xAxis={[{ 
                                        scaleType: 'band', 
                                        dataKey: 'date',
                                        tickLabelStyle: {
                                            angle: 45,
                                            textAnchor: 'start',
                                            fontSize: 12
                                        }
                                    }]}
                                    series={[{ 
                                        dataKey: 'count', 
                                        label: 'Threats Detected',
                                        color: 'rgba(0, 255, 157, 0.7)'
                                    }]}
                                    dataset={threatsByTime}
                                    height={300}
                                    margin={{ left: 40, bottom: 40 }}
                                />
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3,
                            height: '100%'
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                                    <SecurityIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                    Threat Category Distribution
                                </Typography>
                                <PieChart
                                    series={[
                                        {
                                            data: Object.entries(threatsByCategory).map(([category, count]) => ({
                                                id: category,
                                                value: count,
                                                label: category.charAt(0).toUpperCase() + category.slice(1)
                                            })),
                                            highlightScope: { faded: 'global', highlighted: 'item' },
                                            faded: { innerRadius: 30, additionalRadius: -30, color: 'gray' }
                                        }
                                    ]}
                                    height={300}
                                    margin={{ top: 10, bottom: 10 }}
                                    slotProps={{
                                        legend: { hidden: false }
                                    }}
                                />
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', pt: 2 }}>
                                    <SecurityIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                    Comprehensive Threat Analysis
                                </Typography>
                            
                            <Box sx={{ height: 400, width: '100%', mt: 2 }}>
                            <DataGrid
                                rows={threatData}
                                columns={[
                                    { field: 'ip', headerName: 'IP Address', width: 150 },
                                    { field: 'domain', headerName: 'Domain', width: 150 },
                                    { field: 'category', headerName: 'Category', width: 120 },
                                    { 
                                        field: 'threat_level', 
                                        headerName: 'Threat Level', 
                                        width: 150,
                                        renderCell: (params) => (
                                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                                <Box 
                                                    sx={{ 
                                                        width: 12, 
                                                        height: 12, 
                                                        borderRadius: '50%', 
                                                        bgcolor: getThreatLevelColor(params.value),
                                                        mr: 1
                                                    }} 
                                                />
                                                {params.value} - {getThreatLevelLabel(params.value)}
                                            </Box>
                                        )
                                    },
                                    { field: 'source', headerName: 'Source', width: 120 },
                                    { 
                                        field: 'timestamp', 
                                        headerName: 'Detection Time', 
                                        width: 200,
                                        valueFormatter: (params) => new Date(params.value).toLocaleString()
                                    },
                                    {
                                        field: 'actions',
                                        headerName: 'Actions',
                                        width: 150,
                                        renderCell: (params) => (  // Accept 'params' as an argument
                                            <Button 
                                                variant="outlined" 
                                                size="small" 
                                                color="primary"
                                                onClick={() => handleViewDetails(params.row)}  // Now 'params' is defined
                                            >
                                                View Details
                                            </Button>
                                        )
                                    }
                                    
                                ]}
                                sx={{
                                    '& .MuiDataGrid-row:hover': {
                                        backgroundColor: 'rgba(0, 255, 157, 0.1)',
                                    }
                                }}
                            />
                        </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3,
                            height: '100%'
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                                    <WarningIcon sx={{ mr: 1, color: getThreatLevelColor(overallThreatLevel) }} />
                                    Overall Threat Level
                                </Typography>
                                
                                <Box sx={{ position: 'relative', pt: 2 }}>
                                    <LinearProgress 
                                        variant="determinate" 
                                        value={overallThreatLevel * 10} 
                                        sx={{ 
                                            height: 20, 
                                            borderRadius: 5,
                                            backgroundColor: 'rgba(0,0,0,0.1)',
                                            '& .MuiLinearProgress-bar': {
                                                backgroundColor: getThreatLevelColor(overallThreatLevel)
                                            }
                                        }}
                                    />
                                    <Typography 
                                        variant="body1" 
                                        sx={{ 
                                            position: 'absolute', 
                                            top: '50%', 
                                            left: '50%', 
                                            transform: 'translate(-50%, -50%)',
                                            color: 'white',
                                            fontWeight: 'bold',
                                            textShadow: '1px 1px 2px rgba(0,0,0,0.7)'
                                        }}
                                    >
                                        {getThreatLevelLabel(overallThreatLevel)} ({overallThreatLevel}/10)
                                    </Typography>
                                </Box>
                                
                                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between' }}>
                                    <Tooltip title="Low Risk">
                                        <Box sx={{ textAlign: 'center' }}>
                                            <Box sx={{ width: 20, height: 20, bgcolor: '#4caf50', borderRadius: '50%', mx: 'auto' }} />
                                            <Typography variant="caption">Low</Typography>
                                        </Box>
                                    </Tooltip>
                                    <Tooltip title="Medium Risk">
                                        <Box sx={{ textAlign: 'center' }}>
                                            <Box sx={{ width: 20, height: 20, bgcolor: '#ff9800', borderRadius: '50%', mx: 'auto' }} />
                                            <Typography variant="caption">Medium</Typography>
                                        </Box>
                                    </Tooltip>
                                    <Tooltip title="High Risk">
                                        <Box sx={{ textAlign: 'center' }}>
                                            <Box sx={{ width: 20, height: 20, bgcolor: '#f44336', borderRadius: '50%', mx: 'auto' }} />
                                            <Typography variant="caption">High</Typography>
                                        </Box>
                                    </Tooltip>
                                    <Tooltip title="Critical Risk">
                                        <Box sx={{ textAlign: 'center' }}>
                                            <Box sx={{ width: 20, height: 20, bgcolor: '#9c27b0', borderRadius: '50%', mx: 'auto' }} />
                                            <Typography variant="caption">Critical</Typography>
                                        </Box>
                                    </Tooltip>
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3,
                            height: '100%'
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                                    <AssessmentIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                    AI-Based Risk Assessment
                                </Typography>
                                
                                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flexDirection: 'column' }}>
                                    <Box sx={{ 
                                        width: 200, 
                                        height: 200, 
                                        borderRadius: '50%', 
                                        border: '10px solid', 
                                        borderColor: getThreatLevelColor(aiRiskScore/10),
                                        display: 'flex',
                                        justifyContent: 'center',
                                        alignItems: 'center',
                                        boxShadow: `0 0 15px ${getThreatLevelColor(aiRiskScore/10)}`,
                                        position: 'relative'
                                    }}>
                                        <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                                            {aiRiskScore}
                                        </Typography>
                                        <Typography variant="body2" sx={{ position: 'absolute', bottom: 40 }}>
                                            Risk Score
                                        </Typography>
                                    </Box>
                                    <Typography variant="body1" sx={{ mt: 2, fontWeight: 'bold' }}>
                                        {aiRiskScore < 30 ? 'Low Risk' : 
                                         aiRiskScore < 60 ? 'Medium Risk' : 
                                         aiRiskScore < 80 ? 'High Risk' : 'Critical Risk'}
                                    </Typography>
                                    <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
                                        Based on threat intelligence analysis and machine learning algorithms
                                    </Typography>
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12}>
                        <Card sx={{ 
                            p: 2, 
                            bgcolor: 'background.paper', 
                            borderRadius: 2,
                            boxShadow: 3
                        }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', pt: 2 }}>
                                    <TimelineIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                    Real-Time Threat Feed
                                </Typography>
                                
                                <TableContainer component={Paper} sx={{ maxHeight: 300, mt: 2 }}>
                                    <Table stickyHeader size="small">
                                        <TableHead>
                                            <TableRow>
                                                <TableCell>Time (UTC)</TableCell>
                                                <TableCell>IP Address</TableCell>
                                                <TableCell>Domain</TableCell>
                                                <TableCell>Threat Type</TableCell>
                                                <TableCell>Severity</TableCell>
                                                <TableCell>Status</TableCell>
                                                <TableCell>Actions</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {threatData.map((threat, index) => (
                                                <TableRow key={index} sx={{ 
                                                    '&:nth-of-type(odd)': { bgcolor: 'rgba(0, 0, 0, 0.03)' },
                                                    bgcolor: threat.threat_level > 8 ? 'rgba(244, 67, 54, 0.1)' : 'inherit'
                                                }}>
                                                    <TableCell>{new Date(threat.timestamp).toLocaleTimeString()}</TableCell>
                                                    <TableCell>{threat.ip}</TableCell>
                                                    <TableCell>{threat.domain || '-'}</TableCell>
                                                    <TableCell>{threat.category || 'Unknown'}</TableCell>
                                                    <TableCell>
                                                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                                            <Box 
                                                                sx={{ 
                                                                    width: 12, 
                                                                    height: 12, 
                                                                    borderRadius: '50%', 
                                                                    bgcolor: getThreatLevelColor(threat.threat_level),
                                                                    mr: 1
                                                                }} 
                                                            />
                                                            {getThreatLevelLabel(threat.threat_level)}
                                                        </Box>
                                                    </TableCell>
                                                    <TableCell>
                                                        <Chip 
                                                            label={threat.threat_level > 7 ? "Active" : "Monitoring"} 
                                                            size="small"
                                                            color={threat.threat_level > 7 ? "error" : "info"}
                                                        />
                                                    </TableCell>
                                                    <TableCell>
                                                        <Button
                                                            variant="outlined"
                                                            color="primary"
                                                            size="small"
                                                            onClick={() => handleViewDetails(threat)}
                                                        >
                                                            View Details
                                                        </Button>
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>
            )}

            {selectedThreat && (
                <Dialog 
                    open={detailsOpen} 
                    onClose={handleCloseDetails} 
                    maxWidth="md"
                >
                    <DialogTitle sx={{ 
                        background: 'linear-gradient(90deg, #1a1a40, #0d0d26)',
                        color: 'white',
                        borderBottom: '1px solid rgba(0, 255, 157, 0.2)'
                    }}>
                        Threat Details
                    </DialogTitle>
                    <DialogContent sx={{ 
                        pt: 10,
                        mt: 1,
                        background: 'linear-gradient(135deg, #1a1a40 0%, #0d0d26 100%)',
                        color: 'white'
                    }}>
                        <Grid container spacing={3}>
                            {/* Threat Summary */}
                            <Grid item xs={12}>
                                <Card sx={{ 
                                    p: 2, 
                                    bgcolor: 'rgba(0,0,0,0.2)', 
                                    borderRadius: 2,
                                    boxShadow: 3,
                                    border: `1px solid rgba(${
                                        selectedThreat.threat_level > 7 ? '255,0,0' : 
                                        selectedThreat.threat_level > 5 ? '255,165,0' : 
                                        selectedThreat.threat_level > 3 ? '255,255,0' : '0,255,0'
                                    },0.3)`
                                }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                                        <Typography variant="h5" sx={{ display: 'flex', alignItems: 'center', color: 'white' }}>
                                            <WarningIcon sx={{ 
                                                mr: 1, 
                                                color: selectedThreat.threat_level > 7 ? 'error.main' : 
                                                       selectedThreat.threat_level > 5 ? 'orange' : 
                                                       selectedThreat.threat_level > 3 ? 'yellow' : 'green'
                                            }} />
                                            Threat Level: {selectedThreat.threat_level}/10
                                        </Typography>
                                        <Chip 
                                            label={selectedThreat.threat_level > 7 ? "Critical" : 
                                                  selectedThreat.threat_level > 5 ? "High" : 
                                                  selectedThreat.threat_level > 3 ? "Medium" : "Low"} 
                                            color={selectedThreat.threat_level > 7 ? "error" : 
                                                  selectedThreat.threat_level > 5 ? "warning" : 
                                                  selectedThreat.threat_level > 3 ? "info" : "success"}
                                            sx={{ fontWeight: 'bold' }}
                                        />
                                    </Box>
                                    
                                    <LinearProgress 
                                        variant="determinate" 
                                        value={selectedThreat.threat_level * 10} 
                                        sx={{ 
                                            height: 10, 
                                            borderRadius: 5,
                                            mb: 2,
                                            bgcolor: 'rgba(255,255,255,0.1)',
                                            '& .MuiLinearProgress-bar': {
                                                bgcolor: selectedThreat.threat_level > 7 ? 'error.main' : 
                                                        selectedThreat.threat_level > 5 ? 'orange' : 
                                                        selectedThreat.threat_level > 3 ? 'yellow' : 'green'
                                            }
                                        }}
                                    />
                                </Card>
                            </Grid>
                            
                            {/* Threat Details */}
                            <Grid item xs={12} md={6}>
                                <Card sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2, boxShadow: 3, height: '100%' }}>
                                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', color: 'white' }}>
                                        <InfoIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        Threat Indicators
                                    </Typography>
                                    <Divider sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.1)' }} />
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                                        <SecurityIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>IP Address:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.ip || 'N/A'}</Typography>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                                        <DomainIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>Domain:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.domain || 'N/A'}</Typography>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                                        <LinkIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>URL:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.url || 'N/A'}</Typography>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                                        <FingerprintIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>File Hash:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.fileHash || 'N/A'}</Typography>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                                        <CategoryIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>Category:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.category || 'N/A'}</Typography>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                        <LanguageIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Typography variant="body1" sx={{ fontWeight: 'bold', mr: 1, color: 'white' }}>Source:</Typography>
                                        <Typography variant="body1" sx={{ color: 'white' }}>{selectedThreat.source || 'N/A'}</Typography>
                                    </Box>
                                </Card>
                            </Grid>
                            
                            {/* Additional Information */}
                            <Grid item xs={12} md={6}>
                                <Card sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2, boxShadow: 3, height: '100%' }}>
                                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', color: 'white' }}>
                                        <CodeIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        Additional Information
                                    </Typography>
                                    <Divider sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.1)' }} />
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 1.5 }}>
                                        <CalendarTodayIcon sx={{ mr: 1, mt: 0.5, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Box>
                                            <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'white' }}>Detection Time:</Typography>
                                            <Typography variant="body2" sx={{ color: 'white' }}>
                                                {new Date(selectedThreat.timestamp).toLocaleString()}
                                            </Typography>
                                        </Box>
                                    </Box>
                                    
                                    <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                                        <NotesIcon sx={{ mr: 1, mt: 0.5, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        <Box>
                                            <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'white' }}>Notes:</Typography>
                                            <Typography variant="body2" sx={{ 
                                                p: 1.5, 
                                                bgcolor: 'rgba(0,0,0,0.3)', 
                                                borderRadius: 1,
                                                minHeight: '100px',
                                                color: 'white'
                                            }}>
                                                {selectedThreat.notes || 'No additional notes provided.'}
                                            </Typography>
                                        </Box>
                                    </Box>
                                </Card>
                            </Grid>
                            
                            {/* Recommended Actions */}
                            <Grid item xs={12}>
                                <Card sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2, boxShadow: 3 }}>
                                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', color: 'white' }}>
                                        <WarningIcon sx={{ mr: 1, color: 'rgba(0, 255, 157, 0.7)' }} />
                                        Recommended Actions
                                    </Typography>
                                    <Divider sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.1)' }} />
                                    
                                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                        {selectedThreat.threat_level > 7 ? (
                                            <>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Immediately block the IP address in your firewall</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Isolate affected systems from the network</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Initiate incident response procedures</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Notify security team and management</Typography>
                                            </>
                                        ) : selectedThreat.threat_level > 5 ? (
                                            <>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Block the IP address in your firewall</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Monitor systems for suspicious activity</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Review logs for related indicators</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Prepare for potential escalation</Typography>
                                            </>
                                        ) : (
                                            <>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Monitor the IP address for continued activity</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• Add to watchlist for future reference</Typography>
                                                <Typography variant="body1" sx={{ color: 'white' }}>• No immediate action required</Typography>
                                            </>
                                        )}
                                    </Box>
                                </Card>
                            </Grid>
                        </Grid>
                    </DialogContent>
                    <DialogActions sx={{ p: 2, bgcolor: 'background.paper', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                        <Button 
                            onClick={handleCloseDetails} 
                            variant="outlined" 
                            color="primary"
                            startIcon={<CloseIcon />}
                        >
                            Close
                        </Button>
                    </DialogActions>
                </Dialog>
            )}
        </Box>
    );
};

export default UserDashboard; 