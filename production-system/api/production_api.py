"""
Production API Server for Phishing Detection

Modern FastAPI server with comprehensive validation, proper error handling,
and production-optimized ML models.
"""

import os
import sys
from pathlib import Path

# Add parent directories to path
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir.parent / "models"))
sys.path.append(str(current_dir.parent / "data"))

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import logging
from typing import Optional, Dict, Any, List
import time
from datetime import datetime
import json

# Import our production components
from production_ml_models import ProductionMLModels
from dataset_manager import ProductionDatasetManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Production Phishing Detection API",
    description="High-precision phishing detection with modern ML models",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS configuration for browser extension and web apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for model management
ml_models = None
model_loaded = False
model_metrics = {}
prediction_cache = {}
cache_size_limit = 1000

class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis"""
    
    email: str = Field(..., min_length=10, max_length=50000, 
                      description="Email content to analyze")
    sender: Optional[str] = Field(None, max_length=500,
                                 description="Email sender address")
    subject: Optional[str] = Field(None, max_length=500,
                                  description="Email subject line")
    priority: Optional[str] = Field("normal", pattern="^(low|normal|high|critical)$",
                                   description="Analysis priority level")
    
    @validator('email')
    def validate_email_content(cls, v):
        """Validate email content"""
        if not v.strip():
            raise ValueError('Email content cannot be empty')
        
        # Basic sanitization
        v = v.replace('\x00', '')  # Remove null bytes
        
        return v

class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis"""
    
    url: str = Field(..., min_length=7, max_length=2000,
                    description="URL to analyze")
    context: Optional[str] = Field(None, max_length=1000,
                                  description="Additional context about the URL")

class BulkAnalysisRequest(BaseModel):
    """Request model for bulk email analysis"""
    
    emails: List[EmailAnalysisRequest] = Field(..., max_items=50,
                                              description="List of emails to analyze")

class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    
    prediction: str
    confidence: float
    safe_confidence: float
    analysis_time: float
    reasons: List[str]
    model_info: Dict[str, Any]
    timestamp: str

class ModelStatusResponse(BaseModel):
    """Response model for model status"""
    
    loaded: bool
    model_count: int
    last_trained: Optional[str]
    performance_metrics: Dict[str, Any]
    system_info: Dict[str, Any]

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize models and components on startup"""
    global ml_models, model_loaded, model_metrics
    
    logger.info("Starting Production Phishing Detection API...")
    
    try:
        # Initialize ML models
        ml_models = ProductionMLModels()
        
        # Check for existing trained models
        model_dir = Path("trained_models")
        if model_dir.exists():
            # Find latest model timestamp
            model_files = list(model_dir.glob("model_metadata_*.json"))
            if model_files:
                latest_file = max(model_files, key=lambda x: x.stat().st_mtime)
                timestamp = latest_file.name.replace("model_metadata_", "").replace(".json", "")
                
                if ml_models.load_models(timestamp):
                    model_loaded = True
                    logger.info(f"Loaded existing models with timestamp {timestamp}")
                    
                    # Load model metrics
                    with open(latest_file, 'r') as f:
                        model_metrics = json.load(f)
                else:
                    logger.warning("Failed to load existing models, will train new ones")
        
        if not model_loaded:
            logger.info("No existing models found, will train on first request")
        
        logger.info("API startup completed successfully")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        # Don't fail startup, allow training on first request
        ml_models = ProductionMLModels()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Production Phishing Detection API...")
    
    # Clear prediction cache
    prediction_cache.clear()
    
    logger.info("Shutdown completed")

# Utility functions
def get_cache_key(email_content: str) -> str:
    """Generate cache key for email content"""
    import hashlib
    return hashlib.md5(email_content.encode()).hexdigest()

def clean_prediction_cache():
    """Clean old cache entries if cache is full"""
    global prediction_cache
    
    if len(prediction_cache) > cache_size_limit:
        # Remove oldest 20% of entries
        remove_count = int(cache_size_limit * 0.2)
        oldest_keys = list(prediction_cache.keys())[:remove_count]
        for key in oldest_keys:
            del prediction_cache[key]

async def ensure_models_ready():
    """Ensure models are trained and ready for prediction"""
    global ml_models, model_loaded
    
    if not model_loaded:
        logger.info("Models not loaded, training new models...")
        
        try:
            # Initialize dataset manager and train models
            data_manager = ProductionDatasetManager()
            datasets = data_manager.prepare_production_datasets()
            splits = data_manager.get_train_test_split(datasets)
            
            # Train models
            email_results = ml_models.train_email_model(
                splits['email']['X_train'], splits['email']['y_train'],
                splits['email']['X_test'], splits['email']['y_test']
            )
            
            url_results = ml_models.train_url_model(
                splits['url']['X_train'], splits['url']['y_train'],
                splits['url']['X_test'], splits['url']['y_test']
            )
            
            # Create ensemble
            ml_models.create_ensemble_model(email_results, url_results)
            
            # Save models
            timestamp = ml_models.save_models()
            model_loaded = True
            
            global model_metrics
            model_metrics = {
                'email_results': email_results,
                'url_results': url_results,
                'timestamp': timestamp
            }
            
            logger.info(f"Models trained and saved with timestamp {timestamp}")
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise HTTPException(status_code=500, detail=f"Model training failed: {str(e)}")

# API Endpoints
@app.get("/", response_class=JSONResponse)
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Production Phishing Detection API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "analyze_email": "/api/v2/analyze/email",
            "analyze_url": "/api/v2/analyze/url",
            "bulk_analysis": "/api/v2/analyze/bulk",
            "model_status": "/api/v2/model/status",
            "health": "/api/v2/health"
        }
    }

@app.get("/api/v2/health", response_class=JSONResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model_loaded,
        "cache_size": len(prediction_cache)
    }

@app.get("/api/v2/model/status", response_model=ModelStatusResponse)
async def get_model_status():
    """Get current model status and performance metrics"""
    
    system_info = {
        "python_version": sys.version,
        "cache_size": len(prediction_cache),
        "uptime": time.time()
    }
    
    return ModelStatusResponse(
        loaded=model_loaded,
        model_count=len(ml_models.models) if ml_models else 0,
        last_trained=model_metrics.get('timestamp'),
        performance_metrics=model_metrics,
        system_info=system_info
    )

@app.post("/api/v2/analyze/email", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze an email for phishing indicators
    
    - **email**: Email content to analyze
    - **sender**: Optional sender email address
    - **subject**: Optional email subject
    - **priority**: Analysis priority (low, normal, high, critical)
    """
    
    start_time = time.time()
    
    try:
        await ensure_models_ready()
        
        # Check cache first
        cache_key = get_cache_key(request.email)
        if cache_key in prediction_cache:
            cached_result = prediction_cache[cache_key]
            cached_result['analysis_time'] = time.time() - start_time
            cached_result['from_cache'] = True
            return AnalysisResponse(**cached_result)
        
        # Analyze email
        result = ml_models.predict_email(request.email)
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        # Prepare response
        analysis_time = time.time() - start_time
        
        response_data = {
            'prediction': result['prediction'],
            'confidence': result['confidence'],
            'safe_confidence': result['safe_confidence'],
            'analysis_time': analysis_time,
            'reasons': result['reasons'],
            'model_info': {
                'model_used': result['model_used'],
                'feature_count': len(result.get('feature_analysis', {})),
                'version': '2.0.0'
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache the result (without timing info)
        cache_data = response_data.copy()
        cache_data['from_cache'] = False
        prediction_cache[cache_key] = cache_data
        
        # Clean cache if needed
        background_tasks.add_task(clean_prediction_cache)
        
        return AnalysisResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/v2/analyze/url")
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a URL for phishing indicators
    
    Note: URL analysis requires the URL model to be trained.
    Currently returns placeholder response.
    """
    
    start_time = time.time()
    
    try:
        await ensure_models_ready()
        
        # Placeholder URL analysis (would need URL feature extraction)
        # For now, return basic analysis
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        
        # Basic URL safety checks
        suspicious_indicators = []
        safety_score = 0.1  # Default low risk
        
        if parsed.netloc:
            # Check for IP addresses
            import re
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                suspicious_indicators.append("Uses IP address instead of domain name")
                safety_score += 0.4
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
            if any(tld in parsed.netloc.lower() for tld in suspicious_tlds):
                suspicious_indicators.append("Uses suspicious top-level domain")
                safety_score += 0.3
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
            if any(shortener in parsed.netloc.lower() for shortener in shorteners):
                suspicious_indicators.append("Uses URL shortening service")
                safety_score += 0.2
        
        prediction = "suspicious" if safety_score > 0.5 else "safe"
        
        return {
            "prediction": prediction,
            "confidence": min(safety_score, 0.95),
            "safe_confidence": 1.0 - min(safety_score, 0.95),
            "analysis_time": time.time() - start_time,
            "reasons": suspicious_indicators if suspicious_indicators else ["No obvious suspicious indicators found"],
            "url_components": {
                "scheme": parsed.scheme,
                "domain": parsed.netloc,
                "path": parsed.path,
                "query": parsed.query
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")

@app.post("/api/v2/analyze/bulk")
async def analyze_bulk_emails(request: BulkAnalysisRequest):
    """
    Analyze multiple emails in bulk
    
    - **emails**: List of emails to analyze (max 50)
    """
    
    start_time = time.time()
    
    try:
        await ensure_models_ready()
        
        results = []
        
        for i, email_request in enumerate(request.emails):
            try:
                # Check cache
                cache_key = get_cache_key(email_request.email)
                if cache_key in prediction_cache:
                    result = prediction_cache[cache_key].copy()
                    result['index'] = i
                    result['from_cache'] = True
                else:
                    # Analyze email
                    analysis = ml_models.predict_email(email_request.email)
                    
                    if 'error' not in analysis:
                        result = {
                            'index': i,
                            'prediction': analysis['prediction'],
                            'confidence': analysis['confidence'],
                            'safe_confidence': analysis['safe_confidence'],
                            'reasons': analysis['reasons'],
                            'from_cache': False
                        }
                        
                        # Cache result
                        prediction_cache[cache_key] = result.copy()
                        
                    else:
                        result = {
                            'index': i,
                            'error': analysis['error']
                        }
                
                results.append(result)
                
            except Exception as e:
                results.append({
                    'index': i,
                    'error': str(e)
                })
        
        return {
            "results": results,
            "total_processed": len(results),
            "processing_time": time.time() - start_time,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")

@app.post("/api/v2/model/retrain")
async def retrain_models(background_tasks: BackgroundTasks):
    """
    Trigger model retraining
    
    Note: This is a long-running operation that runs in the background
    """
    
    def retrain_task():
        global ml_models, model_loaded, model_metrics
        
        try:
            logger.info("Starting model retraining...")
            
            # Clear current models
            ml_models = ProductionMLModels()
            model_loaded = False
            
            # Retrain models
            data_manager = ProductionDatasetManager()
            datasets = data_manager.prepare_production_datasets()
            splits = data_manager.get_train_test_split(datasets)
            
            email_results = ml_models.train_email_model(
                splits['email']['X_train'], splits['email']['y_train'],
                splits['email']['X_test'], splits['email']['y_test']
            )
            
            url_results = ml_models.train_url_model(
                splits['url']['X_train'], splits['url']['y_train'],
                splits['url']['X_test'], splits['url']['y_test']
            )
            
            ml_models.create_ensemble_model(email_results, url_results)
            timestamp = ml_models.save_models()
            
            model_loaded = True
            model_metrics = {
                'email_results': email_results,
                'url_results': url_results,
                'timestamp': timestamp
            }
            
            # Clear prediction cache
            prediction_cache.clear()
            
            logger.info(f"Model retraining completed with timestamp {timestamp}")
            
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")
    
    background_tasks.add_task(retrain_task)
    
    return {
        "message": "Model retraining started in background",
        "status": "initiated",
        "timestamp": datetime.now().isoformat()
    }

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Endpoint not found",
            "message": "The requested endpoint does not exist",
            "available_endpoints": [
                "/api/v2/analyze/email",
                "/api/v2/analyze/url",
                "/api/v2/analyze/bulk",
                "/api/v2/model/status",
                "/api/v2/health"
            ]
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.now().isoformat()
        }
    )

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "production_api:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disable reload in production
        access_log=True,
        log_level="info"
    )