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

# Add parent directory to path to import exact URL detector
sys.path.append('..')
from url_detector_exact import ExactURLPhishingDetector

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define email input schema
class EmailInput(BaseModel):
    email: str

class URLInput(BaseModel):
    url: str

# Initialize FastAPI app
app = FastAPI(title="Unified Email & URL Phishing Detection API")

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
    model_path = 'model.pkl'
    vectorizer_path = 'vectorizer.pkl'
    
    with open(model_path, 'rb') as model_file:
        email_model = pickle.load(model_file)
    
    with open(vectorizer_path, 'rb') as vectorizer_file:
        email_vectorizer = pickle.load(vectorizer_file)
    
    print("Email classification model loaded successfully")
except Exception as e:
    print(f"Error loading email models: {e}")
    print("Creating basic fallback email model...")
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.feature_extraction.text import TfidfVectorizer
    email_model = MultinomialNB()
    email_vectorizer = TfidfVectorizer(max_features=1000)

# Load Exact URL/Domain Classification Model (Model 2)
url_detector = ExactURLPhishingDetector()
url_model_loaded = url_detector.load_model()

if not url_model_loaded:
    print("Exact URL model not found. Training new model with repository data...")
    try:
        X, y = url_detector.load_dataset()
        accuracy, cv_score = url_detector.train_model(X, y)
        url_detector.save_model()
        print(f"Exact URL model trained successfully - Accuracy: {accuracy:.4f}, CV: {cv_score:.4f}")
    except Exception as e:
        print(f"Error training exact URL model: {e}")
        print("URL detection will use fallback analysis")
        url_detector = None
else:
    print("Exact URL classification model loaded successfully")

def extract_urls_from_email(email_text: str) -> List[str]:
    """Extract URLs from email content"""
    url_patterns = [
        r'https?://[^\s<>"\[\]]+',  
        r'www\.[^\s<>"\[\]]+',      
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\[\]]*)?'
    ]
    
    urls = []
    for pattern in url_patterns:
        matches = re.findall(pattern, email_text, re.IGNORECASE)
        urls.extend(matches)
    
    # Clean and deduplicate URLs
    clean_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'http://' + url
            elif '.' in url and not url.startswith('//'):
                url = 'http://' + url
        
        if '.' in url and len(url) > 4:
            clean_urls.append(url)
    
    return list(set(clean_urls))

def extract_domains_from_email(email_text: str) -> List[str]:
    """Extract domain names from email content"""
    domain_patterns = [
        r'from[:\s]+[^@\s]*@([^\s<>\[\]]+)',  
        r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  
        r'https?://(?:www\.)?([^/\s<>\[\]]+)',  
        r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',  
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
    """Analyze email content for suspicious patterns"""
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

def analyze_urls_with_exact_model(urls: List[str]) -> Tuple[List[Dict], float]:
    """Analyze URLs using the exact ML model from the repository"""
    url_analyses = []
    total_risk_score = 0.0
    
    for url in urls:
        try:
            if url_detector and url_detector.model:
                # Use exact ML model for URL analysis
                is_malicious, confidence, reasons = url_detector.predict_url(url)
                model_type = "Exact Repository ML Model"
            else:
                # Fallback analysis
                is_malicious, confidence, reasons = fallback_url_analysis(url)
                model_type = "Fallback Analysis"
            
            analysis = {
                'url': url,
                'is_malicious': bool(is_malicious),
                'confidence': float(confidence),
                'reasons': reasons,
                'model_used': model_type
            }
            url_analyses.append(analysis)
            
            # Calculate risk contribution
            if is_malicious:
                total_risk_score += confidence * 0.8
            else:
                total_risk_score += (1 - confidence) * 0.2
                
        except Exception as e:
            logger.warning(f"Error analyzing URL {url}: {e}")
            analysis = {
                'url': url,
                'is_malicious': False,
                'confidence': 0.5,
                'reasons': ['Analysis failed'],
                'model_used': 'Error'
            }
            url_analyses.append(analysis)
    
    avg_risk_score = total_risk_score / len(urls) if urls else 0.0
    return url_analyses, avg_risk_score

def fallback_url_analysis(url: str) -> Tuple[bool, float, List[str]]:
    """Basic fallback URL analysis when exact model unavailable"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        suspicious_indicators = []
        score = 0.0
        
        # Basic checks
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.7
            suspicious_indicators.append("Uses IP address")
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 0.6
            suspicious_indicators.append("Suspicious TLD")
        
        phishing_keywords = ['verify', 'secure', 'account', 'update', 'login', 'banking']
        if any(keyword in url.lower() for keyword in phishing_keywords):
            score += 0.4
            suspicious_indicators.append("Phishing keywords")
        
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
        if any(shortener in domain for shortener in shorteners):
            score += 0.5
            suspicious_indicators.append("URL shortener")
        
        is_malicious = score > 0.5
        confidence = min(score, 1.0)
        
        if not suspicious_indicators:
            suspicious_indicators.append("No obvious suspicious patterns")
        
        return bool(is_malicious), float(confidence), suspicious_indicators
        
    except Exception as e:
        return False, 0.0, ["Analysis failed"]

def extract_enhanced_email_features(emails: List[str]) -> np.ndarray:
    """Extract enhanced email features for Model 1"""
    num_emails = len(emails)
    
    # Initialize feature arrays
    num_links = np.zeros((num_emails, 1))
    contains_urgent = np.zeros((num_emails, 1))
    contains_money = np.zeros((num_emails, 1))
    contains_suspicious_domains = np.zeros((num_emails, 1))
    email_length = np.zeros((num_emails, 1))
    
    for i, email in enumerate(emails):
        # Extract URLs and analyze with exact Model 2
        urls = extract_urls_from_email(email)
        num_links[i] = len(urls)
        
        # Analyze URLs with exact ML model
        url_analyses, url_risk_score = analyze_urls_with_exact_model(urls)
        
        # Count suspicious URLs based on exact ML model results
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
async def predict_email_phishing(email: EmailInput):
    """Enhanced prediction using both Email Model and Exact URL Model from repository"""
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
        
        # Model 2: Exact URL/Domain Analysis from Repository
        urls = extract_urls_from_email(email_text)
        domains = extract_domains_from_email(email_text)
        
        url_analyses, url_risk_score = analyze_urls_with_exact_model(urls)
        
        # Combine both model results with proper weighting
        combined_phishing_confidence = (email_phishing_confidence * 0.6) + (url_risk_score * 0.4)
        combined_safe_confidence = 1.0 - combined_phishing_confidence
        
        # Final prediction
        final_prediction = 1 if combined_phishing_confidence > 0.5 else 0
        prediction_label = "Phishing Email" if final_prediction == 1 else "Safe Email"
        
        # Generate detailed reasons
        reasons = []
        
        # Email-based reasons
        email_features = additional_features[0]
        if email_features[0] > 2:
            reasons.append(f"Contains {int(email_features[0])} links")
        if email_features[1] > 0:
            reasons.append(f"Uses {int(email_features[1])} urgent language patterns")
        if email_features[2] > 0:
            reasons.append(f"Contains {int(email_features[2])} money/credential terms")
        
        # Exact URL-based reasons from repository model
        malicious_urls = [analysis for analysis in url_analyses if analysis['is_malicious']]
        if malicious_urls:
            reasons.append(f"Contains {len(malicious_urls)} suspicious URLs (Repository ML detected)")
            for url_analysis in malicious_urls[:2]:
                if url_analysis['reasons']:
                    reasons.append(f"Suspicious: {url_analysis['url'][:40]}... - {url_analysis['reasons'][0]}")
        
        if domains:
            reasons.append(f"Analyzed {len(domains)} domains: {', '.join(domains[:3])}")
        
        if not reasons:
            reasons.append("No suspicious patterns detected by either model" if final_prediction == 0 
                         else "Classified as suspicious by ML analysis")
        
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
                    "weight": 0.6,
                    "type": "Email Content Analysis"
                },
                "url_model": {
                    "risk_score": round(url_risk_score, 3),
                    "urls_analyzed": len(urls),
                    "malicious_urls": len(malicious_urls),
                    "weight": 0.4,
                    "type": "Exact Repository ML Model (30 features)"
                }
            },
            "url_analysis": {
                "urls_found": len(urls),
                "domains_found": len(domains),
                "suspicious_urls": len(malicious_urls),
                "detailed_analysis": url_analyses[:3]
            },
            "model_type": "Unified Dual-Model (Email + Exact Repository URL Detection)"
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Prediction failed: {str(e)}")
        return {
            "error": f"Prediction failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

@app.post("/analyze_url")
async def analyze_single_url(request: URLInput):
    """Analyze a single URL using the exact repository model"""
    url = request.url
    
    if not url:
        return {"error": "URL parameter is required"}
    
    try:
        if url_detector and url_detector.model:
            is_malicious, confidence, reasons = url_detector.predict_url(url)
            model_type = "Exact Repository ML Model"
        else:
            is_malicious, confidence, reasons = fallback_url_analysis(url)
            model_type = "Fallback Analysis"
        
        return {
            "url": url,
            "is_malicious": bool(is_malicious),
            "confidence": round(float(confidence), 3),
            "classification": "Malicious" if is_malicious else "Safe",
            "reasons": reasons,
            "model_type": f"URL Analysis ({model_type})",
            "feature_count": 30,
            "dataset_source": "https://github.com/vaibhavbichave/Phishing-URL-Detection"
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
        "model_type": "Unified Email & URL Phishing Detection",
        "version": "4.0 - Exact Repository Implementation",
        "models": {
            "email_model": "Available" if email_model else "Not Available",
            "url_model": "Exact Repository ML Model" if (url_detector and url_detector.model) else "Fallback Only"
        },
        "features": [
            "Email content analysis using ML",
            "Exact URL detection using repository algorithms (30 features)", 
            "Real dataset from GitHub repository (11,000+ samples)",
            "Combined dual-model risk scoring",
            "No static domain whitelisting"
        ],
        "data_source": {
            "repository": "https://github.com/vaibhavbichave/Phishing-URL-Detection",
            "dataset": "phishing.csv (11,054 samples)",
            "features": 30,
            "algorithms": "Exact feature extraction from repository"
        }
    }

@app.get("/model_info")
async def model_info():
    feature_importance = []
    if url_detector and url_detector.model:
        feature_importance = url_detector.get_feature_importance()[:10]
    
    return {
        "unified_system": True,
        "email_model": {
            "type": type(email_model).__name__ if email_model else "Not Available",
            "features": [
                "TF-IDF email content vectorization",
                "Suspicious link detection", 
                "Urgent language patterns",
                "Money/credential harvesting detection",
                "Email structure analysis"
            ]
        },
        "url_model": {
            "type": "Exact Repository Implementation",
            "source": "https://github.com/vaibhavbichave/Phishing-URL-Detection",
            "algorithm": "Random Forest with exact feature extraction",
            "features": url_detector.feature_names if url_detector else [],
            "dataset_size": "11,054 samples",
            "feature_importance": [{"name": name, "score": float(score)} 
                                 for name, score in feature_importance]
        },
        "integration": {
            "email_weight": 0.6,
            "url_weight": 0.4,
            "exact_implementation": True,
            "repository_dataset": True
        }
    }

@app.post("/retrain_url_model")
async def retrain_url_model():
    """Retrain the URL model with the exact repository dataset"""
    try:
        global url_detector
        url_detector = ExactURLPhishingDetector()
        
        logger.info("Retraining URL model with exact repository data...")
        X, y = url_detector.load_dataset()
        accuracy, cv_score = url_detector.train_model(X, y)
        url_detector.save_model()
        
        return {
            "status": "success",
            "message": "URL model retrained successfully",
            "results": {
                "accuracy": round(accuracy, 4),
                "cross_validation_score": round(cv_score, 4),
                "dataset_samples": len(X),
                "features": 30,
                "source": "Exact repository implementation"
            }
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
    
    print(f"Starting Unified Phishing Detection Server on {host}:{port}")
    print("Features:")
    print("- Email content analysis (Model 1)")
    print("- Exact repository URL detection with 30 features (Model 2)")
    print("- Real dataset: 11,054+ samples from GitHub repository")
    print("- Combined ML-based risk assessment")
    print("- Source: https://github.com/vaibhavbichave/Phishing-URL-Detection")
    
    uvicorn.run("app:app", host=host, port=port, reload=False)