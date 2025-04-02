from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
import smtplib  # For sending emails
import jwt
import datetime
from bson import ObjectId
import bcrypt
import traceback
import requests
from flask_jwt_extended import (
    jwt_required, 
    get_jwt_identity, 
    JWTManager,
    create_access_token,
    get_jwt
)
import os
import logging
import re
import pymongo
import time
from pymongo.errors import ConnectionFailure, OperationFailure
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

def check_password(plain_password, hashed_password):
    """
    Check if a plain text password matches a hashed password
    
    Args:
        plain_password (str): The plain text password
        hashed_password (str or bytes): The hashed password from the database
    
    Returns:
        bool: True if the password matches, False otherwise
    """
    try:
        # Ensure plain_password is bytes
        if isinstance(plain_password, str):
            plain_password = plain_password.encode('utf-8')
        
        # Ensure hashed_password is bytes
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        
        # Handle $2a$ vs $2b$ prefix difference
        if hashed_password.startswith(b'$2a$'):
            hashed_password = b'$2b$' + hashed_password[4:]
        
        return bcrypt.checkpw(plain_password, hashed_password)
    except Exception as e:
        print(f"Password check error: {str(e)}")
        return False

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {"origins": "*"},
    r"/signup": {"origins": "http://localhost:3000"}
})  # Temporarily allow all origins

# Connect to MongoDB
mongo_user = os.environ.get('MONGO_INITDB_ROOT_USERNAME', 'admin')
mongo_password = os.environ.get('MONGO_INITDB_ROOT_PASSWORD', 'secret')
mongo_host = os.environ.get('MONGO_HOST', 'mongo')
mongo_uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:27017/cyber_threat_db?authSource=admin"

def connect_to_mongodb(max_retries=10, retry_delay=10):
    for attempt in range(max_retries):
        try:
            client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=10000,
                socketTimeoutMS=45000
            )
            # Test connection
            client.admin.command('ping')
            print(f"Successfully connected to MongoDB on attempt {attempt+1}")
            
            # Ensure the database and collections exist
            db = client.get_database('cyber_threat_db')
            if 'users' not in db.list_collection_names():
                db.create_collection('users')
                print("Created users collection")
            
            if 'threats' not in db.list_collection_names():
                db.create_collection('threats')
                print("Created threats collection")
            
            return client
        except (ConnectionFailure, OperationFailure) as e:
            print(f"MongoDB connection attempt {attempt+1} failed: {str(e)}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("All connection attempts failed")
                # Continue with a non-functional DB connection
                # This allows the app to start even if DB is down
                print("WARNING: Application starting with non-functional database connection")
                client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1000)
                return client

client = connect_to_mongodb()
db = client.get_database()
users = db.users

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=24)
jwt = JWTManager(app)

# Email configuration
EMAIL_SENDER = os.environ.get('EMAIL_SENDER', 'default@example.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
EMAIL_RECEIVER = os.environ.get('EMAIL_RECEIVER', EMAIL_SENDER)  # Default to sender if not specified
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))

def send_email_alert(threat, user_id=None):
    """
    Send an email alert for high-severity threats
    
    Args:
        threat (dict): Threat information including severity, IP, etc.
        user_id (str, optional): User ID to send the email to. If None, uses EMAIL_RECEIVER from env.
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Determine recipient email
        recipient_email = EMAIL_RECEIVER  # Default fallback
        
        # If user_id is provided, get the user's email from MongoDB
        if user_id:
            try:
                user = users.find_one({'_id': ObjectId(user_id)})
                if user and 'email' in user:
                    recipient_email = user['email']
                    app.logger.info(f"Sending email to user: {recipient_email}")
                else:
                    app.logger.warning(f"User not found or no email for ID: {user_id}, using default recipient")
            except Exception as e:
                app.logger.error(f"Error retrieving user email: {str(e)}")
        
        # Create email content
        subject = f"URGENT: Cyber Threat Detected - {threat.get('category', 'Unknown')} - Immediate Action Required"
        
        # Format the severity level with appropriate emoji
        severity = threat.get('threat_level', 0)
        if severity <= 3:
            severity_text = "🟢 LOW"
        elif severity <= 6:
            severity_text = "🟡 MEDIUM"
        elif severity <= 8:
            severity_text = "🟠 HIGH"
        else:
            severity_text = "🔴 CRITICAL"
        
        message = f"""
        ALERT: A high-severity cybersecurity threat has been detected.
        
        🔹 **IP Address:** {threat.get('ip', 'Unknown')}
        🔹 **Domain:** {threat.get('domain', 'N/A')}
        🔹 **URL:** {threat.get('url', 'N/A')}
        🔹 **File Hash:** {threat.get('fileHash', 'N/A')}
        🔹 **Severity Level:** {severity_text} ({threat.get('threat_level', 0)}/10)
        🔹 **Detection Time:** {threat.get('timestamp', 'Unknown')}
        🔹 **Source:** {threat.get('source', 'Internal Analysis')}
        🔹 **Notes:** {threat.get('notes', 'No additional notes')}
        
        ⚠ **Recommended Action:**
        ✔ Block the IP in firewall settings.
        ✔ Investigate the network logs for suspicious activity.
        ✔ Alert the incident response team.
        ✔ Review the attached threat intelligence report.
        
        Stay vigilant,
        Cyber Threat Intelligence System
        """
        
        # Create email message
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg.attach(MIMEText(message, "plain"))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        server.quit()
        
        app.logger.info(f"Email alert sent successfully to {recipient_email} for threat: {threat.get('ip')}")
        return True
    except Exception as e:
        app.logger.error(f"Error sending email alert: {str(e)}")
        return False

# User authentication
@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint that returns a JWT token"""
    try:
        data = request.get_json()
        app.logger.debug(f"Request data: {data}")
        
        # Initialize user to None
        user = None
        
        # Find user by email
        user = users.find_one({'email': data['email']})
        app.logger.debug(f"User lookup result: {user}")
        
        # Check if user exists and password is correct
        if user and check_password(data['password'], user['password']):
            # Create access token
            access_token = create_access_token(identity=str(user['_id']))
            
            return jsonify({
                'token': access_token,
                'userId': str(user['_id']),
                'email': user['email'],
                'name': user.get('name', 'User')
            }), 200
        # Fallback for development: allow login with test@example.com/password123
        elif data.get('email') == 'test@example.com' and data.get('password') == 'password123':
            app.logger.warning("Using fallback authentication for test@example.com")
            # Create a temporary user ID
            temp_id = "000000000000000000000000"
            access_token = create_access_token(identity=temp_id)
            
            return jsonify({
                'token': access_token,
                'userId': temp_id,
                'email': 'test@example.com',
                'name': 'Test User (Fallback)'
            }), 200
        else:
            app.logger.warning(f"Login failed for email: {data.get('email')}")
            return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    """Signup endpoint that creates a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(k in data for k in ['email', 'password']):
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Check if user already exists
        existing_user = users.find_one({'email': data['email']})
        if existing_user:
            return jsonify({'message': 'User already exists'}), 409
        
        # Hash password
        # Ensure password is bytes before hashing
        password_bytes = data['password'].encode('utf-8') if isinstance(data['password'], str) else data['password']
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        
        # Create user document
        user = {
            'email': data['email'],
            'password': hashed_password,
            'name': data.get('name', ''),
            'created_at': datetime.datetime.utcnow()
        }
        
        # Insert user into database
        result = users.insert_one(user)
        
        # Create JWT token
        token = create_access_token(identity=str(result.inserted_id))
        
        return jsonify({
            'token': token,
            'userId': str(result.inserted_id),
            'email': data['email'],
            'name': data.get('name', '')
        }), 201
    except Exception as e:
        app.logger.error(f"Signup error: {str(e)}")
        return jsonify({'message': 'Server error during signup', 'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    # Retrieve threats from MongoDB
    threats = list(db.threats.find({}))
    return jsonify(threats)

@app.route('/api/threats', methods=['POST'])
def add_threat():
    threat_data = request.json
    db.threats.insert_one(threat_data)
    
    # Check if the threat level is high/critical
    if threat_data['level'] >= 4:  # Assuming 4 is high
        send_email_alert(threat_data)
    
    return jsonify({"message": "Threat added successfully!"}), 201

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    try:
        # Check MongoDB connection
        db_status = "Connected"
        try:
            client.admin.command('ping')
        except Exception as e:
            db_status = f"Error: {str(e)}"
        
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'db_status': db_status,
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/threats/check', methods=['POST'])
@jwt_required()
def check_threat():
    try:
        # Log the request
        app.logger.info("Received threat check request")
        
        current_user_id = get_jwt_identity()
        app.logger.debug(f"User ID: {current_user_id}")
        
        data = request.get_json()
        app.logger.debug(f"Request data: {data}")
        
        if not data or 'ip' not in data:
            return jsonify({'error': 'Missing IP address'}), 400
            
        ip = data['ip']
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return jsonify({'error': 'Invalid IP format'}), 400
            
        # Check if we should use mock data (for testing or when API is unavailable)
        use_mock = os.environ.get('USE_MOCK_API', 'false').lower() == 'true'
        
        if use_mock:
            app.logger.info(f"Using mock data for IP: {ip}")
            # Generate mock threat data
            # Use a more stable hash function
            import hashlib
            hash_obj = hashlib.md5(ip.encode())
            threat_level = int(hash_obj.hexdigest(), 16) % 10
            
            threat_record = {
                'ip': ip,
                'threat_level': threat_level,
                'userId': current_user_id,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'source': 'mock'
            }
            
            try:
                # Store in database with error handling
                db.threats.insert_one(threat_record)
            except Exception as e:
                app.logger.error(f"Database insert error: {str(e)}")
                # Continue even if DB insert fails
                pass
            
            return jsonify(threat_record), 200
        
        # Initialize results from multiple APIs
        api_results = []
        
        # 1. VirusTotal API
        vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': os.environ.get('VIRUSTOTAL_API_KEY')}
        
        app.logger.debug(f"Making VirusTotal API request for IP: {ip}")
        
        try:
            vt_response = requests.get(vt_url, headers=headers, timeout=5)
            if vt_response.status_code == 200:
                vt_data = vt_response.json()
                threat_stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                vt_threat_level = threat_stats.get('malicious', 0)
                api_results.append({
                    'source': 'virustotal',
                    'threat_level': vt_threat_level,
                    'details': threat_stats
                })
            else:
                app.logger.error(f"VirusTotal API error: {vt_response.status_code}")
        except Exception as e:
            app.logger.error(f"VirusTotal API request failed: {str(e)}")
        
        # 2. AbuseIPDB API (simulated)
        try:
            abuse_url = f"https://api.abuseipdb.com/api/v2/check"
            abuse_headers = {
                'Key': os.environ.get('ABUSEIPDB_API_KEY', ''),
                'Accept': 'application/json'
            }
            abuse_params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            # Simulate AbuseIPDB response if no API key
            if not os.environ.get('ABUSEIPDB_API_KEY'):
                # Generate deterministic but random-looking score based on IP
                import hashlib
                hash_obj = hashlib.md5(f"abuse{ip}".encode())
                abuse_score = int(hash_obj.hexdigest(), 16) % 100
                
                api_results.append({
                    'source': 'abuseipdb',
                    'threat_level': min(abuse_score // 10, 10),  # Convert 0-100 to 0-10
                    'details': {'abuseConfidenceScore': abuse_score}
                })
            else:
                abuse_response = requests.get(abuse_url, headers=abuse_headers, params=abuse_params, timeout=5)
                if abuse_response.status_code == 200:
                    abuse_data = abuse_response.json()
                    abuse_score = abuse_data.get('data', {}).get('abuseConfidenceScore', 0)
                    api_results.append({
                        'source': 'abuseipdb',
                        'threat_level': min(abuse_score // 10, 10),  # Convert 0-100 to 0-10
                        'details': abuse_data.get('data', {})
                    })
            
        except Exception as e:
            app.logger.error(f"AbuseIPDB API request failed: {str(e)}")
        
        # 3. AlienVault OTX API (simulated)
        try:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            
            # Simulate OTX response
            import hashlib
            hash_obj = hashlib.md5(f"otx{ip}".encode())
            pulse_count = int(hash_obj.hexdigest(), 16) % 20
            
            api_results.append({
                'source': 'alienvault_otx',
                'threat_level': min(pulse_count // 2, 10),  # Convert pulse count to 0-10 scale
                'details': {'pulse_count': pulse_count}
            })
            
        except Exception as e:
            app.logger.error(f"AlienVault OTX API request failed: {str(e)}")
        
        # Calculate weighted average threat level from all sources
        if api_results:
            total_threat = sum(result['threat_level'] for result in api_results)
            avg_threat_level = round(total_threat / len(api_results))
        else:
            # Fallback if all APIs failed
            avg_threat_level = 1
        
        threat_record = {
            'ip': ip,
            'threat_level': avg_threat_level,
            'userId': current_user_id,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source': 'multi_api',
            'api_results': api_results
        }
        
        db.threats.insert_one(threat_record)
        
        if avg_threat_level > 5:
            send_email_alert({
                'ip': ip,
                'threat_level': avg_threat_level,
                'userId': current_user_id
            })
            
        return jsonify(threat_record), 200
        
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"VirusTotal API error: {str(e)}")
        app.logger.debug(f"API Response: {vt_response.text}")
        return jsonify({'error': f'VirusTotal API error: {str(e)}'}), 500
    except pymongo.errors.PyMongoError as e:
        app.logger.error(f"MongoDB error: {str(e)}")
        return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        app.logger.error(f"Threat check error: {str(e)}")
        app.logger.debug(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/api/debug/virustotal', methods=['GET'])
def debug_virustotal():
    """Debug endpoint to check VirusTotal API configuration"""
    try:
        api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        masked_key = api_key[:4] + '*' * (len(api_key) - 8) + api_key[-4:] if len(api_key) > 8 else '****'
        
        # Make a simple request to VirusTotal API
        test_ip = '8.8.8.8'  # Google DNS
        vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{test_ip}'
        headers = {'x-apikey': api_key}
        
        response = requests.get(vt_url, headers=headers)
        
        return jsonify({
            'status': 'success' if response.status_code == 200 else 'error',
            'api_key_present': bool(api_key),
            'api_key_masked': masked_key,
            'response_code': response.status_code,
            'response_message': response.reason,
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/debug/db', methods=['GET'])
def debug_db():
    """Debug endpoint to check database connectivity"""
    try:
        # Test database connection
        db_status = "Connected"
        collections = db.list_collection_names()
        
        # Test insert
        test_doc = {"test": True, "timestamp": datetime.datetime.utcnow()}
        insert_result = db.test_collection.insert_one(test_doc)
        insert_id = str(insert_result.inserted_id)
        
        # Test query
        count = db.test_collection.count_documents({})
        
        return jsonify({
            "status": "success",
            "db_connected": db_status,
            "collections": collections,
            "test_insert_id": insert_id,
            "test_collection_count": count
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/threats/mock', methods=['POST'])
def mock_threat():
    """Simple endpoint that returns mock threat data without DB or auth"""
    try:
        data = request.get_json()
        ip = data.get('ip', '8.8.8.8')
        domain = data.get('domain', '')
        url = data.get('url', '')
        file_hash = data.get('fileHash', '')
        category = data.get('category', 'network')
        notes = data.get('notes', '')
        send_email = data.get('sendEmail', True)
        user_id = data.get('userId', None)
        
        # Generate a simple threat level based on the last octet
        last_octet = int(ip.split('.')[-1])
        threat_level = last_octet % 10
        
        # Adjust threat level based on additional parameters
        if domain:
            threat_level = (threat_level + len(domain) % 5) % 10
        if url:
            threat_level = (threat_level + 2) % 10
        if file_hash:
            threat_level = (threat_level + 3) % 10
        
        # Create a static response
        mock_response = {
            'ip': ip,
            'domain': domain,
            'url': url,
            'fileHash': file_hash,
            'category': category,
            'notes': notes,
            'threat_level': threat_level,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source': 'static_mock',
            'status': 'success'
        }
        
        # Send email alert for high-severity threats (level > 7)
        if threat_level > 7 and send_email:
            app.logger.info(f"High severity threat detected ({threat_level}/10). Sending email alert.")
            send_email_alert(mock_response, user_id)
        
        return jsonify(mock_response), 200
    except Exception as e:
        app.logger.error(f"Mock threat error: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/test/email', methods=['GET'])
def test_email():
    """Test endpoint to verify email sending functionality"""
    try:
        # Get user ID from query parameter if provided
        user_id = request.args.get('userId', None)
        
        # Create a test threat
        test_threat = {
            'ip': '192.168.1.1',
            'domain': 'test-domain.com',
            'category': 'Test Alert',
            'threat_level': 9,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source': 'Test System',
            'notes': 'This is a test email alert. No action required.'
        }
        
        # Send test email
        success = send_email_alert(test_threat, user_id)
        
        # Get recipient email for response
        recipient = EMAIL_RECEIVER
        if user_id:
            try:
                user = users.find_one({'_id': ObjectId(user_id)})
                if user and 'email' in user:
                    recipient = user['email']
            except:
                pass
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Test email sent successfully',
                'recipient': recipient
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to send test email',
                'smtp_server': SMTP_SERVER,
                'smtp_port': SMTP_PORT
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

# Test MongoDB connection
try:
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
    print(f"Database name: {client.list_database_names()}")
except Exception as e:
    print("MongoDB connection error:", e)

app.logger.setLevel(logging.DEBUG)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 