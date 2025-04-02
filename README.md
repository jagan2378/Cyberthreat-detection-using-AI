# Cyber Threat Intelligence System

## Overview
This project is a web-based Cyber Threat Intelligence System for real-time threat detection and risk analysis.

## Technologies Used
- Frontend: React.js, Chart.js
- Backend: Flask
- Database: MongoDB (not implemented in this example)
- APIs: VirusTotal, AlienVault OTX, AbuseIPDB

## Getting Started
1. Clone the repository.
2. Navigate to the `frontend` and `backend` directories and install dependencies.
3. Run the application using Docker.

Step 5: Increase Docker's Timeout Settings
If the issue is related to timeouts, you can try increasing the timeout settings in Docker:
Open Docker Desktop.
Go to Settings (gear icon).
Navigate to Docker Engine.
Add or modify the following settings in the JSON configuration:

```
{
  "debug": true,
  "experimental": false,
  "features": {
    "buildkit": true
  },
  "network": {
    "timeout": 300
  }
}
## run command
 docker compose up --build


 ## Check MongoDB user documents:
 
 docker-compose exec mongo mongosh cyber_threat_db --eval 'db.users.find()'
