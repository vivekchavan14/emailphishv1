#!/usr/bin/env python3
"""
Setup script for the refactored phishing email detection system
"""

import os
import subprocess
import sys
import shutil

def install_requirements():
    """Install required Python packages"""
    print("📦 Installing required packages...")
    
    requirements = [
        'fastapi>=0.100.0',
        'uvicorn[standard]>=0.23.0',
        'pydantic>=2.0.0',
        'scikit-learn>=1.3.0',
        'pandas>=2.0.0',
        'numpy>=1.24.0',
        'scipy>=1.10.0',
        'python-multipart>=0.0.6'
    ]
    
    for package in requirements:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ Installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def check_models():
    """Check if required model files exist"""
    print("\n🔍 Checking for required model files...")
    
    required_files = [
        'backend/model.pkl',
        'backend/vectorizer.pkl',
        'backend/default_model.pkl'
    ]
    
    existing_files = []
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            existing_files.append(file_path)
            print(f"✅ Found: {file_path}")
        else:
            missing_files.append(file_path)
            print(f"⚠️  Missing: {file_path}")
    
    if missing_files:
        print(f"\n❌ Missing {len(missing_files)} model files. You'll need to:")
        print("   1. Train a new model, OR")
        print("   2. Copy your existing model files to the backend/ directory")
        return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating required directories...")
    
    directories = [
        'logs',
        'data',
        'tests',
        'temp'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created/verified: {directory}/")

def create_environment_file():
    """Create a sample .env file"""
    print("\n⚙️  Creating environment configuration...")
    
    env_content = """# Refactored Phishing Detection Environment Configuration
# Server settings
HOST=127.0.0.1
PORT=8000
DEBUG=True

# Model settings
MODEL_PATH=backend/model.pkl
VECTORIZER_PATH=backend/vectorizer.pkl
DEFAULT_MODEL_PATH=backend/default_model.pkl

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/phishing_detection.log

# Security
API_KEY_REQUIRED=False
# API_KEY=your-secret-api-key-here

# Enhanced features
ENABLE_DOMAIN_WHITELIST=True
ENABLE_CONTEXT_AWARENESS=True
ENABLE_CONFIDENCE_ADJUSTMENT=True
"""
    
    env_file_path = '.env.example'
    with open(env_file_path, 'w') as f:
        f.write(env_content)
    
    print(f"✅ Created {env_file_path}")
    print("   Copy this to .env and modify as needed")

def create_startup_script():
    """Create startup scripts"""
    print("\n🚀 Creating startup scripts...")
    
    # Linux/Mac startup script
    startup_script = """#!/bin/bash
# Startup script for Enhanced Phishing Detection API

echo "🚀 Starting Enhanced Phishing Detection API..."

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
fi

# Check if models exist
if [ ! -f "backend/model.pkl" ] && [ ! -f "backend/default_model.pkl" ]; then
    echo "❌ No model files found! Please train a model first."
    echo "   Run: python train_model.py"
    exit 1
fi

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)/backend"

# Start the server
echo "🌐 Starting server on http://localhost:8000"
echo "📖 API documentation: http://localhost:8000/docs"
echo "🔍 Health check: http://localhost:8000/"

cd backend
python app_refactored.py
"""
    
    with open('start_server.sh', 'w') as f:
        f.write(startup_script)
    
    os.chmod('start_server.sh', 0o755)
    print("✅ Created start_server.sh")
    
    # Windows startup script
    windows_script = """@echo off
REM Startup script for Enhanced Phishing Detection API

echo 🚀 Starting Enhanced Phishing Detection API...

REM Check if virtual environment exists
if exist "venv\\Scripts\\activate.bat" (
    echo 📦 Activating virtual environment...
    call venv\\Scripts\\activate.bat
)

REM Check if models exist
if not exist "backend\\model.pkl" if not exist "backend\\default_model.pkl" (
    echo ❌ No model files found! Please train a model first.
    echo    Run: python train_model.py
    pause
    exit /b 1
)

REM Set environment variables
set PYTHONPATH=%PYTHONPATH%;%CD%\\backend

REM Start the server
echo 🌐 Starting server on http://localhost:8000
echo 📖 API documentation: http://localhost:8000/docs
echo 🔍 Health check: http://localhost:8000/

cd backend
python app_refactored.py
pause
"""
    
    with open('start_server.bat', 'w') as f:
        f.write(windows_script)
    
    print("✅ Created start_server.bat")

def create_test_script():
    """Create a comprehensive test script"""
    print("\n🧪 Creating test scripts...")
    
    test_api_script = """#!/usr/bin/env python3
\"\"\"
API Test Script for Enhanced Phishing Detection
\"\"\"

import requests
import json
import time

API_BASE_URL = "http://localhost:8000"

# Test emails
TEST_EMAILS = {
    "legitimate": [
        "From: orders@zomato.com\\nSubject: Order Confirmed\\n\\nYour order has been confirmed.",
        "From: noreply@paytm.com\\nSubject: Payment Receipt\\n\\nPayment successful.",
    ],
    "phishing": [
        "Subject: URGENT Account Suspended\\n\\nClick here immediately: http://fake-bank.tk/verify",
        "Subject: You Won $10000\\n\\nClaim your prize: http://scam-site.xyz/winner",
    ]
}

def test_api_endpoint(endpoint, method="GET", data=None):
    \"\"\"Test an API endpoint\"\"\"
    url = f"{API_BASE_URL}{endpoint}"
    
    try:
        if method == "POST":
            response = requests.post(url, json=data, timeout=10)
        else:
            response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None

def main():
    print("🧪 Testing Enhanced Phishing Detection API")
    print("=" * 50)
    
    # Test server health
    print("\\n1. Testing server health...")
    health = test_api_endpoint("/")
    if health:
        print("✅ Server is running")
        print(f"   Version: {health.get('version', 'Unknown')}")
        print(f"   Model: {health.get('model_type', 'Unknown')}")
    else:
        print("❌ Server is not responding. Make sure it's running!")
        return
    
    # Test model info
    print("\\n2. Testing model information...")
    model_info = test_api_endpoint("/model_info")
    if model_info:
        print(f"✅ Model type: {model_info.get('model_type', 'Unknown')}")
        print(f"   Features: {len(model_info.get('features', []))}")
    
    # Test legitimate emails
    print("\\n3. Testing legitimate emails...")
    for i, email in enumerate(TEST_EMAILS["legitimate"], 1):
        print(f"\\n   Test {i}: Legitimate email")
        result = test_api_endpoint("/predict", "POST", {"email": email})
        if result:
            prediction = result.get("prediction", "Unknown")
            confidence = result.get("confidence", 0)
            is_legit = result.get("is_legitimate_sender", False)
            
            print(f"   Prediction: {prediction}")
            print(f"   Confidence: {confidence:.1%}")
            print(f"   Legitimate sender: {is_legit}")
            
            if prediction == "Safe Email":
                print("   ✅ CORRECT")
            else:
                print("   ❌ FALSE POSITIVE")
    
    # Test phishing emails
    print("\\n4. Testing phishing emails...")
    for i, email in enumerate(TEST_EMAILS["phishing"], 1):
        print(f"\\n   Test {i}: Phishing email")
        result = test_api_endpoint("/predict", "POST", {"email": email})
        if result:
            prediction = result.get("prediction", "Unknown")
            confidence = result.get("confidence", 0)
            
            print(f"   Prediction: {prediction}")
            print(f"   Confidence: {confidence:.1%}")
            
            if prediction == "Phishing Email":
                print("   ✅ CORRECT")
            else:
                print("   ❌ FALSE NEGATIVE")
    
    print("\\n" + "=" * 50)
    print("🎉 API testing completed!")

if __name__ == "__main__":
    main()
"""
    
    with open('test_api.py', 'w') as f:
        f.write(test_api_script)
    
    os.chmod('test_api.py', 0o755)
    print("✅ Created test_api.py")

def main():
    """Main setup function"""
    print("🛠️  Setting up Enhanced Phishing Detection System")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not os.path.exists('backend'):
        print("❌ Error: backend/ directory not found!")
        print("   Please run this script from the project root directory.")
        return False
    
    # Install requirements
    if not install_requirements():
        print("❌ Failed to install requirements")
        return False
    
    # Create directories
    create_directories()
    
    # Create configuration files
    create_environment_file()
    
    # Create startup scripts
    create_startup_script()
    
    # Create test scripts
    create_test_script()
    
    # Check for models
    models_exist = check_models()
    
    print("\n" + "=" * 60)
    print("✅ Setup completed successfully!")
    print("=" * 60)
    
    print("\n🎯 NEXT STEPS:")
    print("1. Copy your trained models to backend/ directory:")
    print("   - model.pkl")
    print("   - vectorizer.pkl")
    print("   - default_model.pkl (optional)")
    
    print("\n2. Start the server:")
    print("   Linux/Mac: ./start_server.sh")
    print("   Windows:   start_server.bat")
    print("   Manual:    cd backend && python app_refactored.py")
    
    print("\n3. Test the API:")
    print("   python test_api.py")
    print("   Or visit: http://localhost:8000/docs")
    
    print("\n4. Key improvements in this version:")
    print("   ✅ Whitelist for 50+ legitimate domains")
    print("   ✅ Context-aware phishing detection")
    print("   ✅ Reduced false positives for business emails")
    print("   ✅ Enhanced confidence scoring")
    print("   ✅ Better handling of Zomato, Zepto, PayTM, etc.")
    
    if not models_exist:
        print("\n⚠️  WARNING: Model files are missing!")
        print("   The API won't work until you provide trained models.")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)