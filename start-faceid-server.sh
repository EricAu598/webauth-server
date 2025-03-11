#!/bin/bash

# Start Face ID Login Testing Server

# Check if Redis is running
redis_running=$(redis-cli ping 2>/dev/null)
if [ "$redis_running" != "PONG" ]; then
  echo "Redis is not running. Starting Redis..."
  redis-server --daemonize yes
  sleep 2
  
  # Check again if Redis started successfully
  redis_running=$(redis-cli ping 2>/dev/null)
  if [ "$redis_running" != "PONG" ]; then
    echo "Failed to start Redis. Please start it manually with 'redis-server'"
    exit 1
  else
    echo "Redis started successfully."
  fi
else
  echo "Redis is already running."
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
  echo "Node.js is not installed. Please install Node.js to run this server."
  exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
  echo "Installing dependencies..."
  npm install
fi

# Create public directory if it doesn't exist
if [ ! -d "public" ]; then
  echo "Creating public directory..."
  mkdir -p public
fi

# Start the server
echo "Starting Face ID Login Testing Server..."
node faceid-test-server.js 