#!/usr/bin/env python3
"""
Production server startup script with proper initialization
"""

import sys
import os
import time
from pathlib import Path

# Add paths for imports
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir / "api"))
sys.path.append(str(current_dir / "models"))
sys.path.append(str(current_dir / "data"))

def main():
    """Start the production API server"""
    print("=" * 60)
    print("STARTING PRODUCTION PHISHING DETECTION API")
    print("=" * 60)
    
    # Change to the correct directory
    os.chdir(current_dir)
    print(f"Working directory: {os.getcwd()}")
    
    try:
        # Import and start the server
        import uvicorn
        from api.production_api import app
        
        print("Starting server on http://localhost:8000")
        print("API Documentation will be available at: http://localhost:8000/api/docs")
        print("Health check: http://localhost:8000/api/v2/health")
        print("=" * 60)
        
        # Start the server
        uvicorn.run(
            "api.production_api:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            access_log=True,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())