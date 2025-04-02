import React, { useState, useEffect } from 'react';
import { Box, Typography, Switch, List, ListItem, ListItemText, ListItemIcon, Divider, Paper, Badge, Chip, Button, Dialog, DialogTitle, DialogContent, DialogActions, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import { Notifications as NotificationsIcon, Email as EmailIcon, Warning as WarningIcon, Security as SecurityIcon, Check as CheckIcon } from '@mui/icons-material';

const Notifications = () => {
    const [emailEnabled, setEmailEnabled] = useState(true);
    const [browserEnabled, setBrowserEnabled] = useState(true);
    const [notifications, setNotifications] = useState([]);
    const [openDialog, setOpenDialog] = useState(false);
    const [notificationFrequency, setNotificationFrequency] = useState('realtime');
    const [notificationThreshold, setNotificationThreshold] = useState(7);

    // Simulate fetching notifications
    useEffect(() => {
        // Mock notifications data
        const mockNotifications = [
            {
                id: 1,
                type: 'threat',
                severity: 'critical',
                message: 'Critical threat detected from IP 45.33.22.156',
                timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
                read: false
            },
            {
                id: 2,
                type: 'system',
                severity: 'info',
                message: 'Weekly security report is now available',
                timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), // 2 hours ago
                read: true
            },
            {
                id: 3,
                type: 'threat',
                severity: 'high',
                message: 'Multiple login attempts detected from unusual location',
                timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(), // 5 hours ago
                read: false
            },
            {
                id: 4,
                type: 'system',
                severity: 'warning',
                message: 'System update available with security patches',
                timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), // 1 day ago
                read: true
            }
        ];
        
        setNotifications(mockNotifications);
    }, []);

    const handleEmailToggle = () => {
        setEmailEnabled(!emailEnabled);
    };

    const handleBrowserToggle = () => {
        setBrowserEnabled(!browserEnabled);
    };

    const handleOpenSettings = () => {
        setOpenDialog(true);
    };

    const handleCloseSettings = () => {
        setOpenDialog(false);
    };

    const handleSaveSettings = () => {
        // Save notification settings
        console.log('Saving notification settings:', {
            email: emailEnabled,
            browser: browserEnabled,
            frequency: notificationFrequency,
            threshold: notificationThreshold
        });
        setOpenDialog(false);
    };

    const handleMarkAllRead = () => {
        setNotifications(notifications.map(notification => ({
            ...notification,
            read: true
        })));
    };

    const handleMarkAsRead = (id) => {
        setNotifications(notifications.map(notification => 
            notification.id === id ? { ...notification, read: true } : notification
        ));
    };

    const getNotificationIcon = (type, severity) => {
        if (type === 'threat') {
            return severity === 'critical' ? 
                <WarningIcon sx={{ color: '#f44336' }} /> : 
                <SecurityIcon sx={{ color: '#ff9800' }} />;
        }
        return <NotificationsIcon sx={{ color: '#2196f3' }} />;
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'critical': return '#f44336';
            case 'high': return '#ff9800';
            case 'warning': return '#ffeb3b';
            case 'info': return '#2196f3';
            default: return '#757575';
        }
    };

    return (
        <Box sx={{ mt: 2, p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h5" sx={{ display: 'flex', alignItems: 'center' }}>
                    <NotificationsIcon sx={{ mr: 1 }} />
                    Notifications
                    <Badge 
                        badgeContent={notifications.filter(n => !n.read).length} 
                        color="error" 
                        sx={{ ml: 1 }}
                    />
                </Typography>
                <Box>
                    <Button 
                        variant="outlined" 
                        size="small" 
                        onClick={handleMarkAllRead}
                        sx={{ mr: 1 }}
                    >
                        Mark All Read
                    </Button>
                    <Button 
                        variant="contained" 
                        size="small" 
                        onClick={handleOpenSettings}
                    >
                        Settings
                    </Button>
                </Box>
            </Box>
            
            <Paper elevation={2} sx={{ mb: 3, p: 2 }}>
                <Typography variant="h6" gutterBottom>Notification Preferences</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <EmailIcon sx={{ mr: 1 }} />
                    <Typography sx={{ flexGrow: 1 }}>Email Notifications</Typography>
                    <Switch checked={emailEnabled} onChange={handleEmailToggle} />
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <NotificationsIcon sx={{ mr: 1 }} />
                    <Typography sx={{ flexGrow: 1 }}>Browser Notifications</Typography>
                    <Switch checked={browserEnabled} onChange={handleBrowserToggle} />
                </Box>
            </Paper>
            
            <Typography variant="h6" gutterBottom>Recent Notifications</Typography>
            <Paper elevation={2}>
                <List sx={{ width: '100%', bgcolor: 'background.paper' }}>
                    {notifications.length > 0 ? (
                        notifications.map((notification, index) => (
                            <React.Fragment key={notification.id}>
                                <ListItem 
                                    alignItems="flex-start"
                                    sx={{ 
                                        bgcolor: notification.read ? 'inherit' : 'rgba(33, 150, 243, 0.08)',
                                        '&:hover': {
                                            bgcolor: 'rgba(0, 0, 0, 0.04)'
                                        }
                                    }}
                                    secondaryAction={
                                        !notification.read && (
                                            <Button 
                                                size="small" 
                                                onClick={() => handleMarkAsRead(notification.id)}
                                            >
                                                <CheckIcon fontSize="small" />
                                            </Button>
                                        )
                                    }
                                >
                                    <ListItemIcon>
                                        {getNotificationIcon(notification.type, notification.severity)}
                                    </ListItemIcon>
                                    <ListItemText
                                        primary={
                                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                                {notification.message}
                                                <Chip 
                                                    label={notification.severity.toUpperCase()} 
                                                    size="small" 
                                                    sx={{ 
                                                        ml: 1, 
                                                        bgcolor: getSeverityColor(notification.severity),
                                                        color: notification.severity === 'warning' ? 'black' : 'white'
                                                    }} 
                                                />
                                            </Box>
                                        }
                                        secondary={
                                            <React.Fragment>
                                                {new Date(notification.timestamp).toLocaleString()}
                                            </React.Fragment>
                                        }
                                    />
                                </ListItem>
                                {index < notifications.length - 1 && <Divider variant="inset" component="li" />}
                            </React.Fragment>
                        ))
                    ) : (
                        <ListItem>
                            <ListItemText primary="No notifications" />
                        </ListItem>
                    )}
                </List>
            </Paper>
            
            {/* Notification Settings Dialog */}
            <Dialog open={openDialog} onClose={handleCloseSettings}>
                <DialogTitle>Notification Settings</DialogTitle>
                <DialogContent>
                    <FormControl fullWidth sx={{ mb: 2 }}>
                        <InputLabel>Notification Frequency</InputLabel>
                        <Select
                            value={notificationFrequency}
                            onChange={(e) => setNotificationFrequency(e.target.value)}
                        >
                            <MenuItem value="realtime">Real-time</MenuItem>
                            <MenuItem value="hourly">Hourly Digest</MenuItem>
                            <MenuItem value="daily">Daily Digest</MenuItem>
                        </Select>
                    </FormControl>
                    
                    <FormControl fullWidth>
                        <InputLabel>Minimum Threat Level</InputLabel>
                        <Select
                            value={notificationThreshold}
                            onChange={(e) => setNotificationThreshold(e.target.value)}
                        >
                            <MenuItem value={5}>Medium+ (Level 5+)</MenuItem>
                            <MenuItem value={7}>High+ (Level 7+)</MenuItem>
                            <MenuItem value={9}>Critical Only (Level 9+)</MenuItem>
                        </Select>
                    </FormControl>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseSettings}>Cancel</Button>
                    <Button onClick={handleSaveSettings} variant="contained">Save</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
};

export default Notifications; 