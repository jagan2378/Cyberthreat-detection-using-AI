// This script initializes the MongoDB database with required collections
print('Start MongoDB initialization...');

// Create admin user if it doesn't exist
if (db.getUser("admin") == null) {
    print('Creating admin user...');
    db.createUser({
        user: "admin",
        pwd: "secret",
        roles: [{ role: "root", db: "admin" }]
    });
    print('Admin user created successfully');
} else {
    print('Admin user already exists');
}

// Connect to the database
db = db.getSiblingDB('cyber_threat_db');

// Create collections if they don't exist
if (!db.getCollectionNames().includes('users')) {
    db.createCollection('users');
    print('Created users collection');
}

if (!db.getCollectionNames().includes('threats')) {
    db.createCollection('threats');
    print('Created threats collection');
}

// Create indexes
db.users.createIndex({ "email": 1 }, { unique: true });
print('Created index on users.email');

db.threats.createIndex({ "timestamp": 1 });
print('Created index on threats.timestamp');

// Create a test user for login testing
try {
    // Add admin user
    db.users.insertOne({
        email: "test@example.com",
        password: "$2b$12$K3JNi5xUQEiKSfRYYCtcpehzGgh8.PHnxgLCLfIu4ZrKHKIpvZRHe",
        name: "Test User",
        created_at: new Date()
    });
    print('Created test user: test@example.com / password123');
    
} catch (e) {
    // User might already exist
    print('Note: Test user creation error (might already exist): ' + e.message);
}

print('MongoDB initialization completed'); 