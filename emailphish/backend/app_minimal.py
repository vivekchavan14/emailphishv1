from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import logging
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Production Phishing Detection API",
    description="Email phishing detection with ML models",
    version="3.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for models
email_model = None
email_vectorizer = None
model_metadata = {}

# Legitimate domains for reducing false positives
LEGITIMATE_DOMAINS = {
    'amazon.com', 'google.com', 'microsoft.com', 'apple.com', 'facebook.com',
    'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com',
    'gmail.com', 'outlook.com', 'yahoo.com', 'github.com', 'stackoverflow.com'
}

# Threat patterns for high precision detection
THREAT_PATTERNS = {
    'urgent_threats': [
        r'account.*suspended', r'account.*locked', r'immediate.*action',
        r'urgent.*verification', r'expires.*hours', r'final.*notice'
    ],
    'financial_scams': [
        r'won.*million', r'lottery.*winner', r'tax.*refund', r'prize.*claim'
    ],
    'credential_harvesting': [
        r'verify.*password.*immediately', r'confirm.*identity.*now'
    ]
}

def create_email_dataset() -> pd.DataFrame:
    """Create realistic email dataset"""
    
    # Legitimate emails
    legitimate_emails = [
        "Thank you for shopping with Amazon! Your order will be delivered soon.",
        "Netflix: Your subscription renews on March 15th. Enjoy unlimited streaming!",
        "Google: Your account security checkup is complete. No action needed.",
        "Microsoft: Your Office 365 subscription is active.",
        "PayPal: You sent $25.00 to John Doe. Transaction complete.",
        "GitHub: Your pull request has been merged successfully.",
        "LinkedIn: You have 3 new connection requests.",
        "Apple: Your iCloud storage is 75% full. Upgrade for more space.",
        "Spotify: Discover new music based on your listening history.",
        "Facebook: You have 5 new notifications waiting."
    ]
    
    # Phishing emails
    phishing_emails = [
        "URGENT: Your account has been suspended! Click here immediately to verify your password or lose access forever.",
        "Congratulations! You've won $1,000,000 in the international lottery! Claim your prize now.",
        "Security Alert: Unusual activity detected on your PayPal account. Verify immediately or account will be locked.",
        "Final Notice: Your account expires in 2 hours! Update payment information NOW to avoid suspension.",
        "IMMEDIATE ACTION REQUIRED: Your Amazon account shows suspicious login attempts.",
        "Tax Refund Alert: You're eligible for $2,847 refund. Click here to claim before deadline.",
        "Bank Alert: Your account will be closed due to inactivity. Login immediately to reactivate.",
        "Prize Notification: You've been selected for Apple iPhone giveaway. Claim within 24 hours.",
        "Urgent Security Update: Your Microsoft account needs immediate verification.",
        "Last Chance: Your subscription expires today! Renew now with 90% discount."
    ]
    
    emails = legitimate_emails + phishing_emails
    labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
    
    return pd.DataFrame({'email': emails, 'label': labels})

def train_email_model():
    """Train simple email classification model"""
    global email_model, email_vectorizer
    
    logger.info("Training email model...")
    df = create_email_dataset()
    
    # Train TF-IDF vectorizer
    email_vectorizer = TfidfVectorizer(
        max_features=1000,
        ngram_range=(1, 2),
        stop_words='english',
        lowercase=True
    )
    X = email_vectorizer.fit_transform(df['email'])
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Train Random Forest model
    email_model = RandomForestClassifier(
        n_estimators=100, 
        random_state=42
    )
    email_model.fit(X_train, y_train)
    
    # Test accuracy
    y_pred = email_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"Email model accuracy: {accuracy:.3f}")
    
    return accuracy

# Request/Response models
class EmailAnalysisRequest(BaseModel):
    email: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLAnalysisRequest(BaseModel):
    url: str

def analyze_email_content(email_text: str) -> Dict:
    """Analyze email content for phishing indicators"""
    if not email_model or not email_vectorizer:
        return {'error': 'Email model not available'}
    
    try:
        # Vectorize email
        email_vector = email_vectorizer.transform([email_text])
        
        # Get prediction
        prediction = email_model.predict(email_vector)[0]
        confidence = max(email_model.predict_proba(email_vector)[0])
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(confidence)
        }
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return {'error': str(e)}

def analyze_url_basic(url: str) -> Dict:
    """Basic URL analysis"""
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        
        suspicious_score = 0.0
        reasons = []
        
        # Basic checks
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            suspicious_score += 0.4
            reasons.append("Uses IP address instead of domain name")
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(tld in domain for tld in suspicious_tlds):
            suspicious_score += 0.3
            reasons.append("Uses suspicious top-level domain")
        
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
        if any(shortener in domain for shortener in shorteners):
            suspicious_score += 0.2
            reasons.append("Uses URL shortening service")
        
        prediction = "phishing" if suspicious_score > 0.5 else "safe"
        
        return {
            'prediction': prediction,
            'confidence': min(suspicious_score, 0.95),
            'reasons': reasons if reasons else ["No obvious suspicious indicators found"]
        }
        
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        return {'error': str(e)}

def generate_reasons(email_text: str, email_result: Dict) -> List[str]:
    """Generate human-readable reasons"""
    reasons = []
    email_lower = email_text.lower()
    
    if email_result.get('prediction') == 'phishing':
        # Check threat patterns
        for category, patterns in THREAT_PATTERNS.items():
            count = sum(1 for pattern in patterns 
                       if re.search(pattern, email_lower, re.IGNORECASE))
            if count > 0:
                reasons.append(f"Contains {count} {category.replace('_', ' ')} indicators")
        
        if email_lower.count('!') > 3:
            reasons.append("Excessive use of exclamation marks")
    else:
        # Legitimacy indicators
        brand_count = sum(1 for domain in LEGITIMATE_DOMAINS 
                         if domain.split('.')[0] in email_lower)
        if brand_count > 0:
            reasons.append(f"Mentions {brand_count} known legitimate brands")
    
    if not reasons:
        reasons.append("Classified by ML model based on content patterns")
    
    return reasons[:5]

# API Routes
@app.get("/")
async def root():
    return {
        "service": "Production Phishing Detection API",
        "version": "3.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "analyze_email": "/analyze/email", 
            "analyze_url": "/analyze/url"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models": {
            "email_model": "loaded" if email_model else "not_loaded"
        }
    }

@app.post("/predict")
async def predict_email(request: EmailAnalysisRequest):
    """Email phishing prediction - legacy endpoint"""
    
    try:
        start_time = time.time()
        
        # Analyze email content
        email_result = analyze_email_content(request.email)
        if 'error' in email_result:
            raise HTTPException(status_code=500, detail=email_result['error'])
        
        # Generate reasons
        reasons = generate_reasons(request.email, email_result)
        
        # Format response to match extension expectations
        prediction_label = "Phishing Email" if email_result['prediction'] == 'phishing' else "Safe Email"
        
        result = {
            "prediction": prediction_label,
            "confidence": round(email_result['confidence'], 3),
            "phishing_confidence": round(email_result['confidence'], 3) if email_result['prediction'] == 'phishing' else round(1 - email_result['confidence'], 3),
            "safe_confidence": round(1 - email_result['confidence'], 3) if email_result['prediction'] == 'phishing' else round(email_result['confidence'], 3),
            "reasons": reasons,
            "analysis_time": round(time.time() - start_time, 3),
            "model_type": "Email Content Analysis",
            "timestamp": datetime.now().isoformat()
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/email")
async def analyze_email(request: EmailAnalysisRequest):
    """Email phishing analysis"""
    return await predict_email(request)

@app.post("/analyze/url")
async def analyze_url(request: URLAnalysisRequest):
    """Basic URL analysis"""
    
    try:
        result = analyze_url_basic(request.url)
        
        return {
            "url": request.url,
            **result,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Initialize models on startup
@app.on_event("startup")
async def startup_event():
    """Initialize models when the app starts"""
    try:
        logger.info("Starting up Production Phishing Detection API v3.0.0")
        accuracy = train_email_model()
        
        global model_metadata
        model_metadata = {
            'email_model_accuracy': accuracy,
            'startup_time': datetime.now().isoformat()
        }
        
        logger.info("API ready for requests")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        # Continue without crashing - will return errors for requests

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)