#!/bin/bash

# Function to check the status of a command and handle failures
check_command() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

# 1. Ensure we have sudo/root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or use sudo"
    exit 1
fi

# 2. Install dependencies
echo "Installing required dependencies..."
sudo dnf install -y cmake make gcc python3-lxml python3-jinja2 openscap-scanner git
check_command "Installing dependencies"

# 3. Clone the ComplianceAsCode (SCAP Security Guide) repository
if [ ! -d "content" ]; then
    echo "Cloning the ComplianceAsCode repository..."
    git clone https://github.com/ComplianceAsCode/content.git
    check_command "Cloning the repository"
else
    echo "Repository already exists. Pulling the latest updates..."
    cd content
    git pull origin master
    check_command "Updating the repository"
fi

# 4. Navigate to the repository folder
cd content || exit

# 5. Check if a build directory already exists
if [ -d "build" ]; then
    echo "Build directory already exists. Removing old build directory..."
    rm -rf build
    check_command "Removing old build directory"
fi

# 6. Create the build directory
echo "Creating a new build directory..."
mkdir build
check_command "Creating build directory"

cd build || exit

# 7. Run CMake to configure the build
echo "Configuring the build using CMake..."
cmake ..
check_command "CMake configuration"

# 8. Build the SCAP Security Guide content
echo "Building SCAP content..."
make -j$(nproc)
check_command "Building SCAP content"

# 9. Check if the build was successful by verifying if the DataStream files were created
if [ -f "ssg-rhel9-ds.xml" ]; then
    echo "SCAP DataStream file for RHEL 9 has been successfully created."
else
    echo "Error: SCAP DataStream file for RHEL 9 not found!"
    exit 1
fi

# 10. Run an example OpenSCAP scan (RHEL 9 profile)
echo "Running a sample OpenSCAP scan using the built SCAP content for RHEL 9..."
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results rhel9-results.xml ./ssg-rhel9-ds.xml
check_command "OpenSCAP scan"

echo "OpenSCAP scan completed successfully. Results are saved in 'rhel9-results.xml'."
