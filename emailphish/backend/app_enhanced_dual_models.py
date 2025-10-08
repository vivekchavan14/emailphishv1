from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import re
import numpy as np
from scipy.sparse import hstack
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import logging
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# Add parent directory to path to import URL detector
sys.path.append('..')
from url_domain_detector import URLPhishingDetector, URLFeatureExtractor

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define email input schema
class EmailInput(BaseModel):
    email: str

# Initialize FastAPI app
app = FastAPI(title="Enhanced Dual-Model Phishing Detection API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Loading models and preprocessing components...")

# Load Email Classification Model (Model 1)
try:
    model_path = 'model.pkl' if os.path.exists('model.pkl') else '../model.pkl'
    vectorizer_path = 'vectorizer.pkl' if os.path.exists('vectorizer.pkl') else '../vectorizer.pkl'
    
    with open(model_path, 'rb') as model_file:
        email_model = pickle.load(model_file)
    
    with open(vectorizer_path, 'rb') as vectorizer_file:
        email_vectorizer = pickle.load(vectorizer_file)
    
    print("Email classification model (Model 1) loaded successfully")
except Exception as e:
    print(f"Error loading email models: {e}")
    print("Creating basic fallback email model...")
    # Create a basic fallback model
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.feature_extraction.text import TfidfVectorizer
    email_model = MultinomialNB()
    email_vectorizer = TfidfVectorizer(max_features=1000)

# Load URL/Domain Classification Model (Model 2)
url_detector = URLPhishingDetector()
url_model_loaded = url_detector.load_model()

if not url_model_loaded:
    print("URL model not found. Training new URL model...")
    try:
        X, y = url_detector.load_dataset()
        url_detector.train_model(X, y)
        url_detector.save_model()
        print("URL classification model (Model 2) trained and saved successfully")
    except Exception as e:
        print(f"Error training URL model: {e}")
        print("Using fallback URL analysis")
        url_detector = None
else:
    print("URL classification model (Model 2) loaded successfully")

def extract_urls_from_email(email_text: str) -> List[str]:
    """Extract URLs from email content"""
    url_patterns = [
        r'https?://[^\s<>"\[\]]+',  # HTTP/HTTPS URLs
        r'www\.[^\s<>"\[\]]+',      # www URLs
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\[\]]*)?'  # Domain-based URLs
    ]
    
    urls = []
    for pattern in url_patterns:
        matches = re.findall(pattern, email_text, re.IGNORECASE)
        urls.extend(matches)
    
    # Clean and deduplicate URLs
    clean_urls = []
    for url in urls:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'http://' + url
            elif '.' in url and not url.startswith('//'):
                url = 'http://' + url
        
        # Basic validation
        if '.' in url and len(url) > 4:
            clean_urls.append(url)
    
    return list(set(clean_urls))

def extract_domains_from_email(email_text: str) -> List[str]:
    """Extract domain names from email content"""
    domain_patterns = [
        r'from[:\s]+[^@\s]*@([^\s<>\[\]]+)',  # From header
        r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Any email domain
        r'https?://(?:www\.)?([^/\s<>\[\]]+)',  # URL domains
        r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',  # Plain domain mentions
    ]
    
    domains = set()
    email_lower = email_text.lower()
    
    for pattern in domain_patterns:
        matches = re.findall(pattern, email_lower, re.IGNORECASE)
        for match in matches:
            domain = match.strip('.,;!?')
            if ('.' in domain and 
                len(domain) > 3 and 
                not domain.startswith('.') and 
                not domain.endswith('.')):
                domains.add(domain)
    
    return list(domains)

def analyze_email_content(email_text: str) -> Dict:
    """Analyze email content for suspicious patterns (Model 1 features)"""
    suspicious_patterns = {
        'urgent_language': [
            r'\b(urgent|immediate|asap|act now|limited time)\b',
            r'\b(expires? (today|tomorrow|soon))\b',
            r'\b(account (suspended|blocked|limited))\b',
            r'\b(verify (immediately|now|your account))\b'
        ],
        'money_patterns': [
            r'\$\d+(?:,\d{3})*(?:\.\d{2})?\s*(prize|reward|refund)',
            r'\b(claim your|you won|congratulations.*winner)\b',
            r'\b(inheritance|lottery|jackpot)\b'
        ],
        'credential_patterns': [
            r'\b(confirm|verify|update).*?(password|credentials|login)\b',
            r'\b(social security|credit card|banking).*?(details|information)\b'
        ]
    }
    
    results = {}
    email_lower = email_text.lower()
    
    for category, patterns in suspicious_patterns.items():
        count = 0
        for pattern in patterns:
            matches = re.findall(pattern, email_lower, re.IGNORECASE)
            count += len(matches)
        results[category] = count
    
    return results

def analyze_urls_with_ml(urls: List[str]) -> Tuple[List[Dict], float]:
    """Analyze URLs using ML model (Model 2)"""
    url_analyses = []
    total_risk_score = 0.0
    
    for url in urls:
        try:
            if url_detector and url_detector.model:
                # Use ML model for URL analysis
                is_malicious, confidence, reasons = url_detector.predict_url(url)
            else:
                # Fallback analysis
                is_malicious, confidence, reasons = fallback_url_analysis(url)
            
            analysis = {
                'url': url,
                'is_malicious': is_malicious,
                'confidence': confidence,
                'reasons': reasons,
                'model_used': 'ML' if url_detector and url_detector.model else 'Fallback'
            }
            url_analyses.append(analysis)
            
            # Calculate risk contribution
            if is_malicious:
                total_risk_score += confidence * 0.8
            else:
                total_risk_score += (1 - confidence) * 0.2
                
        except Exception as e:
            logger.warning(f"Error analyzing URL {url}: {e}")
            # Add default analysis for failed URLs
            analysis = {
                'url': url,
                'is_malicious': False,
                'confidence': 0.5,
                'reasons': ['Analysis failed'],
                'model_used': 'Error'
            }
            url_analyses.append(analysis)
    
    # Normalize risk score
    avg_risk_score = total_risk_score / len(urls) if urls else 0.0
    
    return url_analyses, avg_risk_score

def fallback_url_analysis(url: str) -> Tuple[bool, float, List[str]]:
    """Fallback URL analysis when ML model is unavailable"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        suspicious_indicators = []
        score = 0.0
        
        # Check for IP addresses
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.7
            suspicious_indicators.append("Uses IP address instead of domain name")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 0.6
            suspicious_indicators.append("Uses suspicious top-level domain")
        
        # Check for phishing keywords in URL
        phishing_keywords = ['verify', 'secure', 'account', 'update', 'login', 'banking']
        if any(keyword in url.lower() for keyword in phishing_keywords):
            score += 0.4
            suspicious_indicators.append("Contains phishing-related keywords")
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
        if any(shortener in domain for shortener in shorteners):
            score += 0.5
            suspicious_indicators.append("Uses URL shortening service")
        
        is_malicious = score > 0.5
        confidence = min(score, 1.0)
        
        if not suspicious_indicators:
            suspicious_indicators.append("No obvious suspicious patterns detected")
        
        return is_malicious, confidence, suspicious_indicators
        
    except Exception as e:
        logger.error(f"Error in fallback URL analysis: {e}")
        return False, 0.0, ["URL analysis failed"]

def extract_enhanced_email_features(emails: List[str]) -> np.ndarray:
    """Extract enhanced email features for Model 1"""
    num_emails = len(emails)
    
    # Initialize feature arrays (5 features to match original model)
    num_links = np.zeros((num_emails, 1))
    contains_urgent = np.zeros((num_emails, 1))
    contains_money = np.zeros((num_emails, 1))
    contains_suspicious_domains = np.zeros((num_emails, 1))
    email_length = np.zeros((num_emails, 1))
    
    for i, email in enumerate(emails):
        # Extract URLs and analyze with Model 2
        urls = extract_urls_from_email(email)
        num_links[i] = len(urls)
        
        # Analyze URLs with ML model
        url_analyses, url_risk_score = analyze_urls_with_ml(urls)
        
        # Count suspicious URLs based on ML model results
        suspicious_url_count = sum(1 for analysis in url_analyses if analysis['is_malicious'])
        contains_suspicious_domains[i] = suspicious_url_count
        
        # Analyze email content patterns
        content_analysis = analyze_email_content(email)
        contains_urgent[i] = min(content_analysis['urgent_language'], 10)
        contains_money[i] = min(content_analysis['money_patterns'] + content_analysis['credential_patterns'], 10)
        
        # Email length
        email_length[i] = len(email)
    
    return np.hstack([num_links, contains_urgent, contains_money, 
                     contains_suspicious_domains, email_length])

@app.post("/predict")
async def predict_with_dual_models(email: EmailInput):
    """Enhanced prediction using both Email Model (1) and URL Model (2)"""
    email_text = email.email
    
    try:
        # Model 1: Email Content Analysis
        email_vector = email_vectorizer.transform([email_text])
        additional_features = extract_enhanced_email_features([email_text])
        combined_features = hstack([email_vector, additional_features])
        
        # Get email model prediction
        email_prediction = email_model.predict(combined_features)[0]
        email_prediction_proba = email_model.predict_proba(combined_features)[0]
        
        email_phishing_confidence = float(email_prediction_proba[1])
        email_safe_confidence = float(email_prediction_proba[0])
        
        # Model 2: URL/Domain Analysis
        urls = extract_urls_from_email(email_text)
        domains = extract_domains_from_email(email_text)
        
        url_analyses, url_risk_score = analyze_urls_with_ml(urls)
        
        # Combine both model results
        # Weight: 60% email content, 40% URL/domain analysis
        combined_phishing_confidence = (email_phishing_confidence * 0.6) + (url_risk_score * 0.4)
        combined_safe_confidence = 1.0 - combined_phishing_confidence
        
        # Final prediction
        final_prediction = 1 if combined_phishing_confidence > 0.5 else 0
        prediction_label = "Phishing Email" if final_prediction == 1 else "Safe Email"
        
        # Generate comprehensive reasons
        reasons = []
        
        # Email-based reasons
        email_features = additional_features[0]
        if email_features[0] > 2:  # num_links
            reasons.append(f"Contains {int(email_features[0])} links")
        if email_features[1] > 0:  # urgent language
            reasons.append(f"Uses {int(email_features[1])} urgent/threatening language patterns")
        if email_features[2] > 0:  # money/credentials
            reasons.append(f"Contains {int(email_features[2])} money/credential related terms")
        
        # URL-based reasons from Model 2
        malicious_urls = [analysis for analysis in url_analyses if analysis['is_malicious']]
        if malicious_urls:
            reasons.append(f"Contains {len(malicious_urls)} suspicious URLs (ML-detected)")
            for url_analysis in malicious_urls[:2]:  # Show top 2 malicious URLs
                if url_analysis['reasons']:
                    reasons.append(f"Suspicious URL: {url_analysis['url'][:50]}... - {url_analysis['reasons'][0]}")
        
        # Domain analysis
        if domains:
            reasons.append(f"Analyzed {len(domains)} domains: {', '.join(domains[:3])}")
        
        if not reasons:
            if final_prediction == 0:
                reasons.append("No suspicious patterns detected by either model")
            else:
                reasons.append("Classified as suspicious by ML analysis")
        
        return {
            "prediction": prediction_label,
            "confidence": round(combined_phishing_confidence, 3),
            "phishing_confidence": round(combined_phishing_confidence, 3),
            "safe_confidence": round(combined_safe_confidence, 3),
            "reasons": reasons,
            "model_breakdown": {
                "email_model": {
                    "prediction": "Phishing" if email_prediction == 1 else "Safe",
                    "confidence": round(email_phishing_confidence, 3),
                    "weight": 0.6
                },
                "url_model": {
                    "risk_score": round(url_risk_score, 3),
                    "urls_analyzed": len(urls),
                    "malicious_urls": len(malicious_urls),
                    "weight": 0.4
                }
            },
            "url_analysis": {
                "urls_found": len(urls),
                "domains_found": len(domains),
                "suspicious_urls": len(malicious_urls),
                "detailed_analysis": url_analyses[:3]  # Show first 3 URLs
            },
            "model_type": "Dual-Model Enhanced Detection (Email + URL/Domain ML)"
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Prediction failed: {str(e)}")
        return {
            "error": f"Prediction failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

@app.post("/analyze_url")
async def analyze_url_only(request: dict):
    """Analyze a single URL using Model 2"""
    url = request.get('url', '')
    
    if not url:
        return {"error": "URL parameter is required"}
    
    try:
        if url_detector and url_detector.model:
            is_malicious, confidence, reasons = url_detector.predict_url(url)
            model_type = "ML Model"
        else:
            is_malicious, confidence, reasons = fallback_url_analysis(url)
            model_type = "Fallback Analysis"
        
        return {
            "url": url,
            "is_malicious": bool(is_malicious),
            "confidence": round(float(confidence), 3),
            "classification": "Malicious" if is_malicious else "Safe",
            "reasons": reasons,
            "model_type": f"URL/Domain Analysis ({model_type})"
        }
    except Exception as e:
        return {
            "error": f"URL analysis failed: {str(e)}",
            "url": url
        }

@app.get("/")
async def root():
    return {
        "status": "online",
        "model_type": "Enhanced Dual-Model Phishing Detection",
        "version": "3.0",
        "models": {
            "email_model": "Available" if email_model else "Not Available",
            "url_model": "Available" if (url_detector and url_detector.model) else "Fallback Only"
        },
        "features": [
            "Email content analysis using ML (Model 1)",
            "Dynamic URL/domain classification using ML (Model 2)", 
            "Combined dual-model risk scoring",
            "No static domain whitelisting",
            "Real-time comprehensive analysis"
        ]
    }

@app.get("/model_info")
async def model_info():
    info = {
        "dual_model_system": True,
        "email_model": {
            "type": type(email_model).__name__ if email_model else "Not Available",
            "features": [
                "Email content vectorization (TF-IDF)",
                "Suspicious link detection", 
                "Urgent language patterns",
                "Money/credential harvesting detection",
                "Email structure analysis"
            ]
        },
        "url_model": {
            "type": "RandomForest ML Model" if (url_detector and url_detector.model) else "Fallback Analysis",
            "features": [
                "30+ comprehensive URL features",
                "Domain structure analysis",
                "TLD reputation analysis", 
                "URL pattern recognition",
                "Brand impersonation detection"
            ]
        },
        "integration": {
            "email_weight": 0.6,
            "url_weight": 0.4,
            "dynamic_analysis": True,
            "static_whitelisting": False
        }
    }
    
    return info

@app.post("/train_models")
async def train_models_endpoint():
    """Endpoint to retrain models if needed"""
    try:
        results = {}
        
        # Train URL model if needed
        if not url_detector or not url_detector.model:
            logger.info("Training URL model...")
            url_detector = URLPhishingDetector()
            X, y = url_detector.load_dataset()
            accuracy, cv_score = url_detector.train_model(X, y)
            url_detector.save_model()
            
            results['url_model'] = {
                'status': 'trained',
                'accuracy': accuracy,
                'cv_score': cv_score
            }
        else:
            results['url_model'] = {
                'status': 'already_loaded'
            }
        
        results['email_model'] = {
            'status': 'pre_trained' if email_model else 'not_available'
        }
        
        return {
            "status": "success",
            "results": results,
            "message": "Model training completed"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1"
    
    print(f"Starting Enhanced Dual-Model Phishing Detection Server on {host}:{port}")
    print("Features:")
    print("- Model 1: Email content analysis")
    print("- Model 2: Dynamic URL/domain classification") 
    print("- No static domain whitelisting")
    print("- Combined ML-based risk assessment")
    uvicorn.run("app_enhanced_dual_models:app", host=host, port=port, reload=False)