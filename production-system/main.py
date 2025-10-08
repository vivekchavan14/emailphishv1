"""
Main entry point for Render deployment
Production Phishing Detection API
"""

import os
import sys
from pathlib import Path

# Add paths for imports
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir / "api"))
sys.path.append(str(current_dir / "models"))
sys.path.append(str(current_dir / "data"))

# Import the FastAPI app
from api.production_api import app

# For Render deployment, we use the app directly
# Render will automatically detect this as the ASGI application

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)