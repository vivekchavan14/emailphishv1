#!/usr/bin/env python3
"""
Main entry point for the Production Phishing Detection API
Run with: python main.py or uvicorn main:app
"""

from app import app
import uvicorn
import os

if __name__ == "__main__":
    # Configuration for different environments
    host = "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1"
    port = int(os.environ.get("PORT", 10000))  # Render default port is 10000
    
    print("=" * 60)
    print("Production Phishing Detection API v3.0.0")
    print("=" * 60)
    print(f"Starting server on {host}:{port}")
    print("\nFeatures:")
    print("• Advanced email phishing detection with ML models")
    print("• URL phishing analysis with 30+ features")
    print("• Real-time analysis with caching")
    print("• Comprehensive threat pattern recognition")
    print("• Production-ready with error handling")
    print("\nAPI Endpoints:")
    print(f"• Health Check: http://{host}:{port}/health")
    print(f"• Email Analysis: http://{host}:{port}/analyze/email")
    print(f"• URL Analysis: http://{host}:{port}/analyze/url")
    print(f"• Bulk Analysis: http://{host}:{port}/analyze/bulk")
    print("=" * 60)
    
    # Run the server
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False,  # Set to True for development
        access_log=True,
        log_level="info"
    )