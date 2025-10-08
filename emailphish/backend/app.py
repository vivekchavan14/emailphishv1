from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pickle
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from scipy.sparse import hstack
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import logging
import re
import string
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from datetime import datetime
import warnings

# Import URL phishing detection features
from url_phishing_features import FeatureExtraction

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
    description="Advanced email and URL phishing detection with ML models",
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
email_models = {}
url_model = None
email_vectorizer = None
url_feature_extractor = None
model_metadata = {}
prediction_cache = {}
cache_size_limit = 1000

# Legitimate domains for reducing false positives
LEGITIMATE_DOMAINS = {
    'amazon.com', 'google.com', 'microsoft.com', 'apple.com', 'facebook.com',
    'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com',
    'nykaa.com', 'flipkart.com', 'myntra.com', 'zomato.com', 'swiggy.com',
    'paytm.com', 'phonepe.com', 'gmail.com', 'outlook.com', 'yahoo.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org'
}

# Threat patterns for high precision detection
THREAT_PATTERNS = {
    'urgent_threats': [
        r'account.*suspended', r'account.*locked', r'account.*restricted',
        r'immediate.*action', r'urgent.*verification', r'expires.*hours',
        r'final.*notice', r'last.*warning', r'act.*immediately'
    ],
    'financial_scams': [
        r'won.*million', r'lottery.*winner', r'inheritance.*claim',
        r'tax.*refund', r'unclaimed.*money', r'prize.*claim'
    ],
    'credential_harvesting': [
        r'verify.*password.*immediately', r'confirm.*identity.*now',
        r'update.*security.*urgent', r'login.*credentials.*expire'
    ]
}

class EmailFeatureExtractor:
    """Extract sophisticated features from email content"""
    
    def __init__(self):
        self.business_terms = [
            'order', 'purchase', 'invoice', 'receipt', 'subscription',
            'newsletter', 'unsubscribe', 'customer', 'support', 'service'
        ]
        
        self.professional_terms = [
            'thank you', 'please', 'regarding', 'sincerely', 'best regards',
            'team', 'company', 'organization'
        ]
    
    def extract_features(self, email_text: str) -> np.ndarray:
        """Extract comprehensive email features"""
        features = []
        email_lower = email_text.lower()
        
        # Basic text features
        features.append(len(email_text))  # Text length
        features.append(len(email_text.split()))  # Word count
        features.append(len(set(email_text.split())))  # Unique words
        
        # Character ratios
        if len(email_text) > 0:
            features.append(sum(1 for c in email_text if c.isupper()) / len(email_text))
            features.append(sum(1 for c in email_text if c.isdigit()) / len(email_text))
            features.append(sum(1 for c in email_text if c in string.punctuation) / len(email_text))
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"\\[\\]]+', email_text)
        features.append(len(urls))
        
        suspicious_url_count = 0
        legitimate_url_count = 0
        
        for url in urls:
            domain = urlparse(url.lower()).netloc
            if any(legit in domain for legit in LEGITIMATE_DOMAINS):
                legitimate_url_count += 1
            elif any(susp in domain for susp in ['.tk', '.ml', '.ga', '.cf']):
                suspicious_url_count += 1
        
        features.append(suspicious_url_count)
        features.append(legitimate_url_count)
        
        # Threat patterns
        for category, patterns in THREAT_PATTERNS.items():
            threat_count = sum(1 for pattern in patterns 
                             if re.search(pattern, email_lower, re.IGNORECASE))
            features.append(threat_count)
        
        # Legitimacy indicators
        business_count = sum(1 for term in self.business_terms if term in email_lower)
        professional_count = sum(1 for term in self.professional_terms if term in email_lower)
        brand_count = sum(1 for domain in LEGITIMATE_DOMAINS 
                         if domain.split('.')[0] in email_lower)
        
        features.extend([business_count, professional_count, brand_count])
        
        # Suspicious patterns
        features.append(email_lower.count('!'))
        features.append(email_lower.count('?'))
        features.append(len(re.findall(r'[A-Z]{3,}', email_text)))
        
        return np.array(features)

class MLModelTrainer:
    """Train and manage ML models"""
    
    def __init__(self):
        self.email_feature_extractor = EmailFeatureExtractor()
        
    def create_email_dataset(self) -> pd.DataFrame:
        """Create realistic email dataset"""
        
        # Legitimate emails (marketing, business)
        legitimate_emails = [
            "Thank you for shopping with Amazon! Your order will be delivered soon.",
            "Netflix: Your subscription renews on March 15th. Enjoy unlimited streaming!",
            "Nykaa: Exclusive 50% off on skincare products. Shop now!",
            "Google: Your account security checkup is complete. No action needed.",
            "Microsoft: Your Office 365 subscription is active.",
            "PayPal: You sent $25.00 to John Doe. Transaction complete.",
            "Flipkart: Your order has been shipped. Track your package here.",
            "Zomato: Your food order is being prepared. Estimated delivery: 30 mins.",
            "LinkedIn: You have 3 new connection requests.",
            "GitHub: Your pull request has been merged successfully.",
            "Spotify: Discover new music based on your listening history.",
            "Apple: Your iCloud storage is 75% full. Upgrade for more space.",
            "Facebook: You have 5 new notifications waiting.",
            "Instagram: Your post has received 50 likes.",
            "Twitter: Weekly summary of your account activity.",
            "YouTube: New videos from channels you subscribe to.",
            "Myntra: End of season sale - up to 70% off on fashion.",
            "Swiggy: Rate your recent order and get 20% off next time.",
            "Uber: Your trip receipt for $12.50 is ready.",
            "Ola: Thanks for riding with us. Rate your driver.",
            "WhatsApp: Your chat backup was successful.",
            "Telegram: New message in your group chat.",
            "Discord: Join the conversation in your server.",
            "Reddit: Trending posts from your favorite communities.",
            "Stack Overflow: Your question received a new answer."
        ]
        
        # Phishing emails (high precision patterns)
        phishing_emails = [
            "URGENT: Your account has been suspended! Click here immediately to verify your password or lose access forever.",
            "Congratulations! You've won $1,000,000 in the international lottery! Claim your prize now by providing your bank details.",
            "Security Alert: Unusual activity detected on your PayPal account. Verify your identity immediately or account will be locked.",
            "Final Notice: Your account expires in 2 hours! Update your payment information NOW to avoid permanent suspension.",
            "IMMEDIATE ACTION REQUIRED: Your Amazon account shows suspicious login attempts. Confirm your identity to prevent closure.",
            "Tax Refund Alert: You're eligible for $2,847 refund. Click here to claim before deadline expires.",
            "Bank Alert: Your account will be closed due to inactivity. Login immediately to reactivate.",
            "Prize Notification: You've been selected for Apple iPhone giveaway. Claim within 24 hours or forfeit.",
            "Urgent Security Update: Your Microsoft account needs immediate verification. Click here or risk data loss.",
            "Last Chance: Your subscription expires today! Renew now with 90% discount - limited time offer.",
            "Account Verification Required: Your Google account shows unusual activity from unknown device. Verify immediately.",
            "BREAKING: Your cryptocurrency wallet shows unauthorized transactions. Secure your funds now!",
            "Emergency: Your Netflix account has been hacked. Change password immediately to prevent data theft.",
            "Important: Your social security number has been compromised. Take immediate action to protect your identity.",
            "Alert: Your credit card has been charged $500. If this wasn't you, click here to dispute immediately.",
            "Urgent: IRS investigation pending on your account. Respond within 48 hours to avoid legal action.",
            "Warning: Your computer is infected with virus. Download security software immediately.",
            "Critical: Your Facebook account will be deleted in 24 hours. Verify your identity to prevent closure.",
            "Action Required: Your Instagram account shows suspicious activity. Confirm ownership immediately.",
            "Final Warning: Your email account storage is full. Upgrade now or lose all your emails forever."
        ]
        
        # Create DataFrame
        emails = legitimate_emails + phishing_emails
        labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
        
        return pd.DataFrame({
            'email': emails,
            'label': labels
        })
    
    def train_email_models(self, df: pd.DataFrame) -> Dict:
        """Train email classification models"""
        
        # Extract features
        X = np.array([self.email_feature_extractor.extract_features(email) 
                      for email in df['email']])
        y = df['label'].values
        
        # Train TF-IDF vectorizer
        vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english',
            lowercase=True
        )
        X_tfidf = vectorizer.fit_transform(df['email'])
        
        # Combine custom features with TF-IDF
        X_combined = hstack([X_tfidf, X])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train models
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=150, max_depth=8, random_state=42
            ),
            'logistic_regression': LogisticRegression(
                C=10, max_iter=2000, random_state=42
            )
        }
        
        results = {}
        trained_models = {}
        
        for name, model in models.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            results[name] = {
                'accuracy': accuracy,
                'model': model
            }
            trained_models[name] = model
            
            logger.info(f"{name} accuracy: {accuracy:.3f}")
        
        # Select best model
        best_model_name = max(results.keys(), key=lambda k: results[k]['accuracy'])
        best_model = results[best_model_name]['model']
        
        return {
            'models': trained_models,
            'vectorizer': vectorizer,
            'best_model': best_model,
            'best_model_name': best_model_name,
            'feature_extractor': self.email_feature_extractor,
            'results': results
        }
    
    def train_url_model(self) -> Dict:
        """Train URL phishing model using the external dataset"""
        
        try:
            # Load URL dataset
            df = pd.read_csv('url_phishing_dataset.csv')
            
            # Initialize feature extractor
            feature_extractor = FeatureExtraction()
            
            # Extract features (this might take a while)
            logger.info("Extracting URL features...")
            
            features = []
            labels = []
            
            for idx, row in df.iterrows():
                if idx >= 1000:  # Limit for faster training
                    break
                    
                try:
                    url_features = feature_extractor.getFeaturesList(row['URL'])
                    features.append(url_features)
                    labels.append(row['label'])
                except Exception as e:
                    logger.warning(f"Failed to extract features for URL {idx}: {e}")
                    continue
            
            X = np.array(features)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train Random Forest model
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"URL model accuracy: {accuracy:.3f}")
            
            return {
                'model': model,
                'feature_extractor': feature_extractor,
                'accuracy': accuracy
            }
            
        except Exception as e:
            logger.error(f"URL model training failed: {e}")
            return None

# Initialize models on startup
def initialize_models():
    """Initialize and train models"""
    global email_models, url_model, email_vectorizer, url_feature_extractor, model_metadata
    
    logger.info("Initializing models...")
    
    # Initialize trainer
    trainer = MLModelTrainer()
    
    # Train email models
    logger.info("Training email models...")
    email_dataset = trainer.create_email_dataset()
    email_training_result = trainer.train_email_models(email_dataset)
    
    email_models = email_training_result['models']
    email_vectorizer = email_training_result['vectorizer']
    
    # Train URL model
    logger.info("Training URL model...")
    url_training_result = trainer.train_url_model()
    
    if url_training_result:
        url_model = url_training_result['model']
        url_feature_extractor = url_training_result['feature_extractor']
    
    # Save models
    models_to_save = {
        'email_models': email_models,
        'email_vectorizer': email_vectorizer,
        'url_model': url_model,
        'email_feature_extractor': trainer.email_feature_extractor,
        'url_feature_extractor': url_feature_extractor,
        'timestamp': datetime.now().isoformat()
    }
    
    with open('production_models.pkl', 'wb') as f:
        pickle.dump(models_to_save, f)
    
    model_metadata = {
        'email_models_count': len(email_models),
        'url_model_loaded': url_model is not None,
        'training_timestamp': datetime.now().isoformat()
    }
    
    logger.info("Model initialization complete!")

# Request/Response models
class EmailAnalysisRequest(BaseModel):
    email: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLAnalysisRequest(BaseModel):
    url: str
    context: Optional[str] = None

class BulkAnalysisRequest(BaseModel):
    emails: List[EmailAnalysisRequest]

# Helper functions
def extract_urls_from_email(text: str) -> List[str]:
    """Extract URLs from email content"""
    url_pattern = r'https?://[^\s<>"\\[\\]]+'
    return re.findall(url_pattern, text)

def analyze_email_content(email_text: str) -> Dict:
    """Analyze email content for phishing indicators"""
    try:
        # Use TF-IDF features
        email_tfidf = email_vectorizer.transform([email_text])
        
        # Extract custom features
        trainer = MLModelTrainer()
        custom_features = trainer.email_feature_extractor.extract_features(email_text).reshape(1, -1)
        
        # Combine features
        combined_features = hstack([email_tfidf, custom_features])
        
        # Get predictions from all models
        predictions = {}
        for name, model in email_models.items():
            pred = model.predict(combined_features)[0]
            proba = model.predict_proba(combined_features)[0]
            predictions[name] = {
                'prediction': int(pred),
                'confidence': float(max(proba))
            }
        
        # Use best model (Random Forest typically performs best)
        best_pred = predictions.get('random_forest', predictions[list(predictions.keys())[0]])
        
        return {
            'prediction': 'phishing' if best_pred['prediction'] == 1 else 'safe',
            'confidence': best_pred['confidence'],
            'all_predictions': predictions
        }
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return {'error': str(e)}

def analyze_url_content(url: str) -> Dict:
    """Analyze URL for phishing indicators"""
    if not url_model or not url_feature_extractor:
        return {'error': 'URL model not available'}
    
    try:
        # Extract URL features
        features = url_feature_extractor.getFeaturesList(url)
        features_array = np.array(features).reshape(1, -1)
        
        # Get prediction
        prediction = url_model.predict(features_array)[0]
        confidence = max(url_model.predict_proba(features_array)[0])
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(confidence),
            'features': features
        }
        
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        return {'error': str(e)}

def generate_analysis_reasons(email_text: str, email_result: Dict, url_results: List[Dict]) -> List[str]:
    """Generate human-readable reasons for analysis"""
    reasons = []
    email_lower = email_text.lower()
    
    # Email-based reasons
    if email_result.get('prediction') == 'phishing':
        # Check for specific threat patterns
        urgent_threats = sum(1 for pattern in THREAT_PATTERNS['urgent_threats']
                           if re.search(pattern, email_lower, re.IGNORECASE))
        if urgent_threats > 0:
            reasons.append(f"Uses {urgent_threats} urgent threat language patterns")
        
        financial_scams = sum(1 for pattern in THREAT_PATTERNS['financial_scams']
                             if re.search(pattern, email_lower, re.IGNORECASE))
        if financial_scams > 0:
            reasons.append(f"Contains {financial_scams} financial scam indicators")
        
        if email_lower.count('!') > 3:
            reasons.append("Excessive use of exclamation marks")
        
        if sum(1 for c in email_text if c.isupper()) / len(email_text) > 0.3:
            reasons.append("Excessive use of capital letters (suspicious)")
    else:
        # Legitimacy indicators
        business_terms = ['order', 'purchase', 'invoice', 'receipt', 'subscription']
        business_count = sum(1 for term in business_terms if term in email_lower)
        if business_count > 0:
            reasons.append(f"Contains {business_count} legitimate business terms")
        
        brand_count = sum(1 for domain in LEGITIMATE_DOMAINS 
                         if domain.split('.')[0] in email_lower)
        if brand_count > 0:
            reasons.append(f"Mentions {brand_count} known legitimate brands")
    
    # URL-based reasons
    phishing_urls = [r for r in url_results if r.get('prediction') == 'phishing']
    safe_urls = [r for r in url_results if r.get('prediction') == 'safe']
    
    if phishing_urls:
        reasons.append(f"Contains {len(phishing_urls)} suspicious URLs")
    if safe_urls:
        reasons.append(f"Contains {len(safe_urls)} legitimate URLs")
    
    if not reasons:
        if email_result.get('prediction') == 'phishing':
            reasons.append("Classified as phishing by ML model based on text patterns")
        else:
            reasons.append("No suspicious patterns detected - appears legitimate")
    
    return reasons[:5]  # Return top 5 reasons

# API Routes
@app.get("/")
async def root():
    return {
        "service": "Production Phishing Detection API",
        "version": "3.0.0",
        "status": "operational",
        "endpoints": {
            "analyze_email": "/analyze/email",
            "analyze_url": "/analyze/url",
            "bulk_analysis": "/analyze/bulk",
            "health": "/health",
            "model_status": "/model/status"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models": {
            "email_models": len(email_models) if email_models else 0,
            "url_model": "loaded" if url_model else "not_loaded",
            "email_vectorizer": "loaded" if email_vectorizer else "not_loaded"
        },
        "cache_size": len(prediction_cache)
    }

@app.get("/model/status")
async def get_model_status():
    return {
        "models_loaded": bool(email_models and url_model),
        "email_models_count": len(email_models) if email_models else 0,
        "url_model_available": url_model is not None,
        "training_timestamp": model_metadata.get('training_timestamp'),
        "system_info": {
            "cache_size": len(prediction_cache),
            "python_version": sys.version
        }
    }

@app.post("/predict")
async def predict_email(request: EmailAnalysisRequest):
    """Legacy endpoint for backward compatibility"""
    return await analyze_email(request)

@app.post("/analyze/email")
async def analyze_email(request: EmailAnalysisRequest):
    """Comprehensive email phishing analysis"""
    
    start_time = time.time()
    
    try:
        # Check cache
        import hashlib
        cache_key = hashlib.md5(request.email.encode()).hexdigest()
        
        if cache_key in prediction_cache:
            result = prediction_cache[cache_key]
            result['analysis_time'] = time.time() - start_time
            result['from_cache'] = True
            return result
        
        # Analyze email content
        email_result = analyze_email_content(request.email)
        if 'error' in email_result:
            raise HTTPException(status_code=500, detail=email_result['error'])
        
        # Extract and analyze URLs
        urls = extract_urls_from_email(request.email)
        url_results = []
        
        for url in urls[:3]:  # Limit to first 3 URLs for performance
            url_result = analyze_url_content(url)
            if 'error' not in url_result:
                url_result['url'] = url
                url_results.append(url_result)
        
        # Generate comprehensive analysis
        reasons = generate_analysis_reasons(request.email, email_result, url_results)
        
        # Combine results with weighted scoring
        final_prediction = email_result['prediction']
        final_confidence = email_result['confidence']
        
        # Adjust confidence based on URL analysis
        if url_results:
            phishing_urls = [r for r in url_results if r['prediction'] == 'phishing']
            if phishing_urls and email_result['prediction'] == 'safe':
                # Increase suspicion if URLs are malicious
                final_confidence = min(final_confidence * 0.7, 0.95)
                if len(phishing_urls) >= 2:
                    final_prediction = 'phishing'
            elif not phishing_urls and email_result['prediction'] == 'phishing':
                # Decrease suspicion if URLs are clean
                final_confidence = max(final_confidence * 0.8, 0.1)
        
        result = {
            "prediction": final_prediction,
            "confidence": round(final_confidence, 3),
            "safe_confidence": round(1 - final_confidence, 3),
            "analysis_time": round(time.time() - start_time, 3),
            "reasons": reasons,
            "model_info": {
                "version": "3.0.0",
                "email_models": len(email_models),
                "url_model": "available" if url_model else "unavailable"
            },
            "timestamp": datetime.now().isoformat(),
            "from_cache": False
        }
        
        # Cache result
        prediction_cache[cache_key] = result.copy()
        
        # Clean cache if needed
        if len(prediction_cache) > cache_size_limit:
            # Remove oldest 20% of entries
            remove_count = int(cache_size_limit * 0.2)
            oldest_keys = list(prediction_cache.keys())[:remove_count]
            for key in oldest_keys:
                del prediction_cache[key]
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/url")
async def analyze_url(request: URLAnalysisRequest):
    """Analyze a single URL for phishing"""
    
    try:
        result = analyze_url_content(request.url)
        
        if 'error' in result:
            # Fallback to basic URL analysis
            parsed = urlparse(request.url.lower())
            domain = parsed.netloc
            
            suspicious_indicators = []
            safety_score = 0.1
            
            # Basic checks
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                suspicious_indicators.append("Uses IP address instead of domain name")
                safety_score += 0.4
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
            if any(tld in domain for tld in suspicious_tlds):
                suspicious_indicators.append("Uses suspicious top-level domain")
                safety_score += 0.3
            
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
            if any(shortener in domain for shortener in shorteners):
                suspicious_indicators.append("Uses URL shortening service")
                safety_score += 0.2
            
            prediction = "phishing" if safety_score > 0.5 else "safe"
            
            result = {
                "prediction": prediction,
                "confidence": min(safety_score, 0.95),
                "safe_confidence": 1.0 - min(safety_score, 0.95),
                "reasons": suspicious_indicators if suspicious_indicators else ["No obvious suspicious indicators found"],
                "model_info": {"fallback": True}
            }
        
        return {
            "url": request.url,
            **result,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/bulk")
async def analyze_bulk_emails(request: BulkAnalysisRequest):
    """Analyze multiple emails in bulk"""
    
    start_time = time.time()
    results = []
    
    try:
        for i, email_request in enumerate(request.emails[:10]):  # Limit to 10 emails
            try:
                result = await analyze_email(email_request)
                results.append({
                    "index": i,
                    **result
                })
            except Exception as e:
                results.append({
                    "index": i,
                    "error": str(e)
                })
        
        return {
            "results": results,
            "total_processed": len(results),
            "processing_time": round(time.time() - start_time, 3),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Initialize models on startup
@app.on_event("startup")
async def startup_event():
    """Initialize models when the app starts"""
    try:
        # Try to load existing models first
        if os.path.exists('production_models.pkl'):
            logger.info("Loading existing models...")
            with open('production_models.pkl', 'rb') as f:
                saved_models = pickle.load(f)
            
            global email_models, url_model, email_vectorizer, url_feature_extractor, model_metadata
            email_models = saved_models.get('email_models', {})
            email_vectorizer = saved_models.get('email_vectorizer')
            url_model = saved_models.get('url_model')
            url_feature_extractor = saved_models.get('url_feature_extractor')
            
            model_metadata = {
                'email_models_count': len(email_models),
                'url_model_loaded': url_model is not None,
                'loaded_from_cache': True
            }
            
            logger.info(f"Loaded {len(email_models)} email models and URL model: {url_model is not None}")
        else:
            logger.info("No existing models found, training new models...")
            initialize_models()
    except Exception as e:
        logger.error(f"Model initialization failed: {e}")
        # Continue without models - will return errors but app won't crash

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)