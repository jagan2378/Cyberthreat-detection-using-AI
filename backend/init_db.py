from pymongo import MongoClient
import os

def init_db():
    mongo_user = os.environ.get('MONGO_INITDB_ROOT_USERNAME', 'admin')
    mongo_password = os.environ.get('MONGO_INITDB_ROOT_PASSWORD', 'secret')
    mongo_host = os.environ.get('MONGO_HOST', 'mongo')
    
    # Connect with admin credentials
    client = MongoClient(f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:27017/admin")
    
    # Create database and collections
    db = client.cyber_threat_db
    
    # Create collections if they don't exist
    if 'users' not in db.list_collection_names():
        db.create_collection('users')
        print("Created users collection")
    
    if 'threats' not in db.list_collection_names():
        db.create_collection('threats')
        print("Created threats collection")
    
    print("Database initialization complete")

if __name__ == "__main__":
    init_db() 