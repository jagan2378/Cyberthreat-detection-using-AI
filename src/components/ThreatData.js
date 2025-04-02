import React, { useEffect, useState } from 'react';
import { Box, Typography } from '@mui/material';

const ThreatData = () => {
    const [threats, setThreats] = useState([]);

    useEffect(() => {
        fetch('/api/threats')
            .then(response => response.json())
            .then(data => setThreats(data));
    }, []);

    return (
        <Box>
            <Typography variant="h5" gutterBottom>
                Threat Data
            </Typography>
            {threats.length > 0 ? (
                threats.map(threat => (
                    <Typography key={threat.name}>
                        {threat.name}: Level {threat.level}
                    </Typography>
                ))
            ) : (
                <Typography>No threats available.</Typography>
            )}
        </Box>
    );
};

export default ThreatData; 