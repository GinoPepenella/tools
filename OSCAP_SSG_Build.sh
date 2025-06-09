#!/bin/bash

# SCAP Security Guide build script

# Set working directory
CONTENT_MASTER_DIR="/root/Desktop/content-master"
BUILD_DIR="$CONTENT_MASTER_DIR/build"

# Step 1: Install Dependencies
echo "Installing dependencies..."
yum install -y cmake make gcc python3-pip openscap || { echo "Failed to install packages"; exit 1; }

# Install required Python modules
echo "Installing required Python modules..."
pip3 install jinja2 || { echo "Failed to install jinja2"; exit 1; }

# Step 2: Set up the build environment
echo "Setting up build environment..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR" || { echo "Failed to enter build directory"; exit 1; }

# Step 3: Configure with CMake
echo "Configuring the project with CMake..."
cmake .. || { echo "CMake configuration failed"; exit 1; }

# Step 4: Build SCAP Security Guide content
echo "Building SCAP Security Guide content..."
make -j$(nproc) || { echo "Build failed"; exit 1; }

echo "SCAP Security Guide content built successfully!"
