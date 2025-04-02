#!/bin/bash

echo "Stopping containers..."
docker-compose down

echo "Removing MongoDB volume..."
docker volume rm cyberthreat_mongo-data

echo "Starting containers..."
docker-compose up -d

echo "MongoDB has been reset. A new database will be initialized." 