import time
import sys
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

# MongoDB connection parameters
mongo_user = os.environ.get('MONGO_INITDB_ROOT_USERNAME', 'admin')
mongo_password = os.environ.get('MONGO_INITDB_ROOT_PASSWORD', 'secret')
mongo_host = os.environ.get('MONGO_HOST', 'mongo')
mongo_uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:27017/admin?authSource=admin"

# Maximum number of connection attempts
max_attempts = 30
attempt = 0

print("Waiting for MongoDB to be ready...")

while attempt < max_attempts:
    attempt += 1
    try:
        # Try to connect to MongoDB
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        # Check if the connection is successful
        client.admin.command('ping')
        print(f"MongoDB is ready! Connected successfully on attempt {attempt}")
        
        # Try to access the cyber_threat_db database
        db = client.get_database('cyber_threat_db')
        collections = db.list_collection_names()
        print(f"Available collections: {collections}")
        
        # Check if we can access the users collection
        if 'users' in collections:
            count = db.users.count_documents({})
            print(f"Found {count} users in the database")
        else:
            print("Users collection not found, it will be created by the application")
        
        sys.exit(0)
    except (ConnectionFailure, OperationFailure) as e:
        print(f"Attempt {attempt}/{max_attempts}: MongoDB not ready yet: {str(e)}")
        if attempt < max_attempts:
            print(f"Waiting 2 seconds before next attempt...")
            time.sleep(2)
        else:
            print("Maximum attempts reached. MongoDB might not be ready.")
            # Exit with a non-zero code, but don't fail the container
            # This allows the Flask app to start anyway
            sys.exit(0) 