from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import logging
import re
import time
import pickle
import hashlib
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from datetime import datetime
import warnings
import ipaddress
import socket

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Optimized Phishing Detection API",
    description="Advanced email and URL phishing detection with enhanced ML models",
    version="4.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model storage
models = {
    'email_ensemble': None,
    'email_vectorizer': None,
    'url_model': None,
    'url_scaler': None,
    'model_metadata': {}
}

# Prediction cache for performance
prediction_cache = {}
CACHE_LIMIT = 1000

# Enhanced phishing patterns and legitimate indicators
PHISHING_PATTERNS = {
    'urgent_action': [
        r'urgent.*action.*required', r'immediate.*action.*needed', r'act.*now.*or.*lose',
        r'expires?.*today', r'expires?.*tomorrow', r'expires?.*hours', r'expires?.*minutes',
        r'limited.*time.*offer', r'last.*chance', r'final.*notice', r'final.*warning',
        r'suspended.*account', r'locked.*account', r'restricted.*account', r'terminated.*account'
    ],
    'financial_scams': [
        r'congratulations.*won', r'lottery.*winner', r'prize.*claim', r'jackpot.*winner',
        r'inheritance.*million', r'tax.*refund.*\$\d+', r'unclaimed.*money', r'cash.*prize',
        r'million.*dollars?.*won', r'selected.*winner', r'lucky.*winner', r'compensation.*fund'
    ],
    'credential_theft': [
        r'verify.*account.*immediately', r'confirm.*identity.*now', r'update.*payment.*info',
        r'verify.*credit.*card', r'confirm.*password', r'update.*security.*details',
        r'click.*here.*verify', r'login.*credentials.*expire', r'account.*information.*outdated'
    ],
    'threat_language': [
        r'legal.*action.*against', r'criminal.*charges', r'arrest.*warrant', r'court.*summons',
        r'police.*involved', r'fbi.*investigation', r'irs.*investigation', r'government.*agency'
    ],
    'fake_security': [
        r'security.*alert', r'suspicious.*activity.*detected', r'unauthorized.*access',
        r'multiple.*login.*attempts', r'unusual.*activity', r'security.*breach'
    ]
}

LEGITIMATE_INDICATORS = {
    'business_terms': [
        'order', 'purchase', 'receipt', 'invoice', 'subscription', 'newsletter',
        'unsubscribe', 'customer', 'support', 'service', 'account', 'billing',
        'thank you', 'welcome', 'confirmation', 'delivery', 'shipping'
    ],
    'professional_language': [
        'dear', 'sincerely', 'best regards', 'kind regards', 'yours truly',
        'please', 'regarding', 'furthermore', 'however', 'therefore'
    ],
    'legitimate_domains': {
        'amazon.com', 'google.com', 'microsoft.com', 'apple.com', 'facebook.com',
        'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com', 'uber.com',
        'airbnb.com', 'linkedin.com', 'twitter.com', 'instagram.com', 'youtube.com',
        'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'icloud.com'
    }
}

# URL shorteners and suspicious TLDs
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'j.mp', 'buff.ly',
    'dlvr.it', 'is.gd', 'tiny.cc', 'x.co', 'short.link', 'rebrand.ly'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
    '.stream', '.racing', '.bid', '.win', '.loan', '.cricket'
]

class EnhancedEmailFeatureExtractor:
    """Advanced email feature extraction"""
    
    def __init__(self):
        self.feature_names = [
            'length', 'word_count', 'unique_words_ratio', 'uppercase_ratio',
            'digit_ratio', 'punctuation_ratio', 'exclamation_count', 'question_count',
            'url_count', 'suspicious_url_count', 'legitimate_url_count',
            'urgent_patterns', 'financial_scam_patterns', 'credential_theft_patterns',
            'threat_language_patterns', 'fake_security_patterns', 'business_terms_count',
            'professional_language_count', 'legitimate_domain_mentions',
            'currency_mentions', 'number_sequences', 'capital_words_count'
        ]
    
    def extract_features(self, email_text: str) -> np.ndarray:
        """Extract comprehensive email features"""
        features = []
        email_lower = email_text.lower()
        
        # Basic text statistics
        features.append(len(email_text))  # length
        words = email_text.split()
        features.append(len(words))  # word_count
        features.append(len(set(words)) / max(len(words), 1))  # unique_words_ratio
        
        # Character ratios
        if len(email_text) > 0:
            features.append(sum(1 for c in email_text if c.isupper()) / len(email_text))
            features.append(sum(1 for c in email_text if c.isdigit()) / len(email_text))
            features.append(sum(1 for c in email_text if c in '.,!?;:()[]{}') / len(email_text))
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # Punctuation analysis
        features.append(email_text.count('!'))
        features.append(email_text.count('?'))
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', email_text)
        features.append(len(urls))
        
        suspicious_url_count = 0
        legitimate_url_count = 0
        
        for url in urls:
            parsed = urlparse(url.lower())
            domain = parsed.netloc
            
            if any(shortener in domain for shortener in URL_SHORTENERS):
                suspicious_url_count += 1
            elif any(susp_tld in domain for susp_tld in SUSPICIOUS_TLDS):
                suspicious_url_count += 1
            elif any(legit in domain for legit in LEGITIMATE_INDICATORS['legitimate_domains']):
                legitimate_url_count += 1
        
        features.append(suspicious_url_count)
        features.append(legitimate_url_count)
        
        # Pattern matching
        for category, patterns in PHISHING_PATTERNS.items():
            pattern_count = sum(1 for pattern in patterns 
                              if re.search(pattern, email_lower, re.IGNORECASE))
            features.append(pattern_count)
        
        # Legitimate indicators
        business_count = sum(1 for term in LEGITIMATE_INDICATORS['business_terms'] 
                           if term in email_lower)
        features.append(business_count)
        
        professional_count = sum(1 for phrase in LEGITIMATE_INDICATORS['professional_language'] 
                               if phrase in email_lower)
        features.append(professional_count)
        
        domain_mentions = sum(1 for domain in LEGITIMATE_INDICATORS['legitimate_domains'] 
                            if domain.split('.')[0] in email_lower)
        features.append(domain_mentions)
        
        # Additional features
        features.append(len(re.findall(r'[\$£€¥₹]', email_text)))  # currency_mentions
        features.append(len(re.findall(r'\b\d{3,}\b', email_text)))  # number_sequences
        features.append(len(re.findall(r'\b[A-Z]{2,}\b', email_text)))  # capital_words
        
        return np.array(features)

class URLFeatureExtractor:
    """Optimized URL feature extraction based on the research repository"""
    
    def __init__(self):
        self.feature_names = [
            'using_ip', 'long_url', 'short_url', 'symbol_at', 'redirecting',
            'prefix_suffix', 'sub_domains', 'https', 'domain_reg_len', 'favicon',
            'non_std_port', 'https_domain_url', 'request_url', 'anchor_url',
            'links_in_script_tags', 'server_form_handler', 'info_email',
            'abnormal_url', 'website_forwarding', 'status_bar_cust',
            'disable_right_click', 'using_popup_window', 'iframe_redirection',
            'age_of_domain', 'dns_recording', 'website_traffic', 'page_rank',
            'google_index', 'links_pointing_to_page', 'stats_report'
        ]
    
    def extract_features(self, url: str) -> np.ndarray:
        """Extract URL features for phishing detection"""
        features = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            domain = ""
            parsed = None
        
        # 1. Using IP
        try:
            ipaddress.ip_address(domain)
            features.append(-1)  # Suspicious
        except:
            features.append(1)   # Safe
        
        # 2. Long URL
        if len(url) < 54:
            features.append(1)
        elif len(url) <= 75:
            features.append(0)
        else:
            features.append(-1)
        
        # 3. Short URL
        if any(shortener in domain for shortener in URL_SHORTENERS):
            features.append(-1)
        else:
            features.append(1)
        
        # 4. Symbol @
        if '@' in url:
            features.append(-1)
        else:
            features.append(1)
        
        # 5. Redirecting //
        if url.rfind('//') > 6:
            features.append(-1)
        else:
            features.append(1)
        
        # 6. Prefix Suffix
        if '-' in domain:
            features.append(-1)
        else:
            features.append(1)
        
        # 7. Sub Domains
        dot_count = domain.count('.')
        if dot_count <= 1:
            features.append(1)
        elif dot_count == 2:
            features.append(0)
        else:
            features.append(-1)
        
        # 8. HTTPS
        if parsed and parsed.scheme == 'https':
            features.append(1)
        else:
            features.append(-1)
        
        # 9-30: Simplified versions of remaining features
        # Domain registration length (simplified)
        features.append(-1)  # Unknown, assume suspicious
        
        # Favicon (simplified)
        features.append(1)   # Assume safe
        
        # Non-standard port
        if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
            features.append(-1)
        else:
            features.append(1)
        
        # HTTPS domain URL
        if 'https' in domain:
            features.append(-1)
        else:
            features.append(1)
        
        # Request URL (simplified)
        features.append(1)
        
        # Anchor URL (simplified)
        features.append(0)
        
        # Links in script tags (simplified)
        features.append(0)
        
        # Server form handler (simplified)
        features.append(-1)
        
        # Info email (simplified)
        if 'mail' in url.lower():
            features.append(-1)
        else:
            features.append(1)
        
        # Abnormal URL (simplified)
        features.append(1)
        
        # Website forwarding (simplified)
        features.append(0)
        
        # Status bar customization (simplified)
        features.append(1)
        
        # Disable right click (simplified)
        features.append(1)
        
        # Using popup window (simplified)
        features.append(1)
        
        # Iframe redirection (simplified)
        features.append(1)
        
        # Age of domain (simplified)
        features.append(-1)
        
        # DNS recording (simplified)
        features.append(-1)
        
        # Website traffic (simplified)
        features.append(0)
        
        # Page rank (simplified)
        features.append(-1)
        
        # Google index (simplified)
        features.append(1)
        
        # Links pointing to page (simplified)
        features.append(1)
        
        # Stats report (simplified)
        suspicious_domains = any(tld in domain for tld in SUSPICIOUS_TLDS)
        if suspicious_domains:
            features.append(-1)
        else:
            features.append(1)
        
        return np.array(features)

def create_enhanced_email_dataset() -> pd.DataFrame:
    """Create comprehensive email dataset with more examples"""
    
    # Legitimate emails (expanded dataset)
    legitimate_emails = [
        "Thank you for shopping with Amazon! Your order #12345 will be delivered soon. Track your package here.",
        "Netflix: Your subscription renews on March 15th. Enjoy unlimited streaming with no ads!",
        "Google: Your account security checkup is complete. No action needed. Your account is secure.",
        "Microsoft: Your Office 365 subscription is active. Download the latest updates for enhanced security.",
        "PayPal: You sent $25.00 to John Doe. Transaction ID: 1234567890. Transaction completed successfully.",
        "GitHub: Your pull request has been merged successfully. Thank you for your contribution to the project.",
        "LinkedIn: You have 3 new connection requests. Expand your professional network today.",
        "Apple: Your iCloud storage is 75% full. Upgrade for more space and keep your data safe.",
        "Spotify: Discover new music based on your listening history. Your Discover Weekly is ready!",
        "Facebook: You have 5 new notifications waiting. Check what your friends are up to.",
        "Uber: Your trip receipt for $12.50 is ready. Thanks for riding with Uber today.",
        "Airbnb: Your upcoming reservation in Paris is confirmed. Check-in details attached.",
        "Instagram: Your post has received 50 likes and 10 comments. See who liked your photo.",
        "Twitter: Weekly summary of your account activity. You gained 15 new followers this week.",
        "YouTube: New videos from channels you subscribe to. 5 new videos are waiting for you.",
        "Dropbox: Your files have been successfully synced. All your documents are up to date.",
        "Slack: You have new messages in 3 channels. Don't miss important team updates.",
        "Zoom: Your meeting recording is ready. Access it from your account dashboard.",
        "WhatsApp: New message from Mom. Open WhatsApp to read the message.",
        "Telegram: New message in Tech Discussion group. Join the conversation now.",
        "Discord: Join the conversation in Gaming Server. Your friends are online now.",
        "Reddit: Trending posts from your favorite communities. 5 hot posts this week.",
        "Stack Overflow: Your question received a new answer. Check if it solves your problem.",
        "Wikipedia: Your monthly reading summary is ready. You read 25 articles this month.",
        "Medium: New article from writers you follow. 3 new stories in your feed."
    ]
    
    # Phishing emails (expanded and varied)
    phishing_emails = [
        "URGENT: Your account has been suspended due to suspicious activity! Click here immediately to verify your password and personal information or lose access forever within 24 hours. This is your final warning!",
        "CONGRATULATIONS! You've won $1,000,000 in the international Microsoft lottery! To claim your prize, provide your bank account details and social security number immediately. Winner ID: MS-789456.",
        "SECURITY ALERT: Unusual activity detected on your PayPal account from unknown location. Verify your identity immediately by clicking here or your account will be permanently locked within 2 hours.",
        "FINAL NOTICE: Your Amazon Prime account expires in 2 hours! Update your payment information NOW to avoid permanent suspension and loss of all benefits. Click here before it's too late!",
        "IMMEDIATE ACTION REQUIRED: Your bank account shows suspicious login attempts from 5 different countries. Confirm your identity to prevent unauthorized access. Time sensitive - act now!",
        "TAX REFUND ALERT: IRS owes you $2,847.53 refund for overpaid taxes. Click here to claim your refund before the deadline expires. Processing time: 24-48 hours only.",
        "BANK ALERT: Your Wells Fargo account will be closed due to inactivity detected by our security system. Login immediately to reactivate and prevent permanent closure.",
        "PRIZE NOTIFICATION: You've been randomly selected for Apple iPhone 14 giveaway worth $999! Claim within 24 hours or forfeit your prize. Limited time offer - act fast!",
        "URGENT SECURITY UPDATE: Your Microsoft account needs immediate verification due to recent data breach. Click here or risk permanent data loss and identity theft.",
        "LAST CHANCE: Your Netflix subscription expires today! Renew now with exclusive 90% discount for loyal customers. Offer valid for next 6 hours only - don't miss out!",
        "ACCOUNT VERIFICATION REQUIRED: Your Google account shows unusual activity from unknown device in Russia. Verify immediately to prevent data theft and account compromise.",
        "CRYPTO WALLET ALERT: Your Bitcoin wallet shows unauthorized transactions totaling $5,000. Secure your funds now by verifying your identity. Time critical action required!",
        "EMERGENCY NOTICE: Your Social Security number has been compromised in recent data breach. Take immediate action to protect your identity and prevent fraud.",
        "CREDIT ALERT: Your credit card has been charged $500 for unauthorized purchase. If this wasn't you, click here to dispute immediately and protect your account.",
        "IRS INVESTIGATION: Tax investigation pending on your account due to discrepancies. Respond within 48 hours to avoid legal action and criminal charges.",
        "VIRUS WARNING: Your computer is infected with 18 malicious viruses. Download our security software immediately to prevent permanent data loss and identity theft.",
        "FACEBOOK SECURITY: Your account will be deleted in 24 hours due to policy violation. Verify your identity to prevent permanent closure and data loss.",
        "INSTAGRAM ACTION: Your account shows suspicious activity from unauthorized location. Confirm ownership immediately or face permanent suspension.",
        "EMAIL STORAGE FULL: Your Gmail account storage is 100% full. Upgrade now or lose all your emails forever. Immediate action required - don't delay!",
        "COURT SUMMONS: You have been selected for jury duty. Failure to respond within 72 hours will result in criminal charges and arrest warrant."
    ]
    
    # Create DataFrame
    emails = legitimate_emails + phishing_emails
    labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
    
    return pd.DataFrame({'email': emails, 'label': labels})

def load_url_dataset() -> pd.DataFrame:
    """Load URL dataset from the research repository"""
    try:
        # Load the phishing.csv dataset
        df = pd.read_csv('/home/vivek/vadapav/email-phish-project/Phishing-URL-Detection/phishing.csv')
        logger.info(f"Loaded URL dataset with {len(df)} samples")
        return df
    except Exception as e:
        logger.error(f"Failed to load URL dataset: {e}")
        # Create minimal fallback dataset
        return pd.DataFrame({
            'class': [1, -1, 1, -1],
            'UsingIP': [1, -1, 1, 1],
            'LongURL': [1, 0, -1, 1],
            'ShortURL': [1, -1, 1, 1]
        })

def train_email_models():
    """Train ensemble email classification models"""
    logger.info("Training email models...")
    
    # Create dataset
    df = create_enhanced_email_dataset()
    
    # Feature extraction
    feature_extractor = EnhancedEmailFeatureExtractor()
    X_features = np.array([feature_extractor.extract_features(email) for email in df['email']])
    
    # TF-IDF vectorization
    tfidf_vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 3),
        stop_words='english',
        lowercase=True,
        min_df=1,
        max_df=0.95
    )
    X_tfidf = tfidf_vectorizer.fit_transform(df['email'])
    
    # Combine features
    X_combined = hstack([X_tfidf, X_features])
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # Create ensemble of models
    rf_model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    gb_model = GradientBoostingClassifier(n_estimators=150, max_depth=8, random_state=42)
    lr_model = LogisticRegression(C=10, max_iter=1000, random_state=42)
    
    # Voting ensemble
    ensemble_model = VotingClassifier(
        estimators=[
            ('rf', rf_model),
            ('gb', gb_model),
            ('lr', lr_model)
        ],
        voting='soft'
    )
    
    # Train ensemble
    ensemble_model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = ensemble_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info(f"Email ensemble model accuracy: {accuracy:.3f}")
    
    # Store models
    models['email_ensemble'] = ensemble_model
    models['email_vectorizer'] = tfidf_vectorizer
    models['email_feature_extractor'] = feature_extractor
    
    return accuracy

def train_url_model():
    """Train URL classification model using the research dataset"""
    logger.info("Training URL model...")
    
    try:
        # Load dataset
        df = load_url_dataset()
        
        # Prepare features (exclude Index and class columns)
        feature_columns = [col for col in df.columns if col not in ['Index', 'class']]
        X = df[feature_columns].values
        y = df['class'].values
        
        # Convert labels to binary (assuming -1 is phishing, 1 is legitimate)
        y_binary = (y == -1).astype(int)  # 1 for phishing, 0 for legitimate
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Random Forest (best for this type of data)
        url_model = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        url_model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = url_model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"URL model accuracy: {accuracy:.3f}")
        
        # Store models
        models['url_model'] = url_model
        models['url_scaler'] = scaler
        models['url_feature_extractor'] = URLFeatureExtractor()
        
        return accuracy
        
    except Exception as e:
        logger.error(f"URL model training failed: {e}")
        return 0.0

# Request/Response models
class EmailAnalysisRequest(BaseModel):
    email: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLAnalysisRequest(BaseModel):
    url: str

class BulkAnalysisRequest(BaseModel):
    emails: List[EmailAnalysisRequest]

def analyze_email_enhanced(email_text: str) -> Dict:
    """Enhanced email analysis with ensemble model"""
    if not models['email_ensemble']:
        return {'error': 'Email model not available'}
    
    try:
        # Feature extraction
        custom_features = models['email_feature_extractor'].extract_features(email_text).reshape(1, -1)
        
        # TF-IDF features
        tfidf_features = models['email_vectorizer'].transform([email_text])
        
        # Combine features
        combined_features = hstack([tfidf_features, custom_features])
        
        # Predict with ensemble
        prediction = models['email_ensemble'].predict(combined_features)[0]
        probabilities = models['email_ensemble'].predict_proba(combined_features)[0]
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(max(probabilities)),
            'phishing_confidence': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
            'safe_confidence': float(probabilities[0]) if len(probabilities) > 1 else 1.0
        }
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return {'error': str(e)}

def analyze_url_enhanced(url: str) -> Dict:
    """Enhanced URL analysis with research-based model"""
    if not models['url_model']:
        return {'error': 'URL model not available'}
    
    try:
        # Extract features
        features = models['url_feature_extractor'].extract_features(url).reshape(1, -1)
        
        # Scale features
        features_scaled = models['url_scaler'].transform(features)
        
        # Predict
        prediction = models['url_model'].predict(features_scaled)[0]
        probabilities = models['url_model'].predict_proba(features_scaled)[0]
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(max(probabilities)),
            'phishing_confidence': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
            'safe_confidence': float(probabilities[0]) if len(probabilities) > 1 else 1.0
        }
        
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        return {'error': str(e)}

def generate_enhanced_reasons(email_text: str, email_result: Dict, url_results: List[Dict] = None) -> List[str]:
    """Generate detailed analysis reasons"""
    reasons = []
    email_lower = email_text.lower()
    
    if email_result.get('prediction') == 'phishing':
        # Check specific phishing patterns
        for category, patterns in PHISHING_PATTERNS.items():
            count = sum(1 for pattern in patterns 
                       if re.search(pattern, email_lower, re.IGNORECASE))
            if count > 0:
                category_name = category.replace('_', ' ').title()
                reasons.append(f"Contains {count} {category_name} indicators")
        
        # Additional suspicious indicators
        if email_text.count('!') > 5:
            reasons.append("Excessive use of exclamation marks")
        
        if len(re.findall(r'[A-Z]{3,}', email_text)) > 3:
            reasons.append("Excessive use of capital letters")
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', email_text)
        if urls:
            suspicious_count = sum(1 for url in urls 
                                 if any(shortener in url for shortener in URL_SHORTENERS)
                                 or any(tld in url for tld in SUSPICIOUS_TLDS))
            if suspicious_count > 0:
                reasons.append(f"Contains {suspicious_count} suspicious URLs")
    
    else:  # Safe email
        # Legitimacy indicators
        business_count = sum(1 for term in LEGITIMATE_INDICATORS['business_terms'] 
                           if term in email_lower)
        if business_count > 0:
            reasons.append(f"Contains {business_count} legitimate business terms")
        
        domain_mentions = sum(1 for domain in LEGITIMATE_INDICATORS['legitimate_domains'] 
                            if domain.split('.')[0] in email_lower)
        if domain_mentions > 0:
            reasons.append(f"References {domain_mentions} known legitimate services")
        
        professional_count = sum(1 for phrase in LEGITIMATE_INDICATORS['professional_language'] 
                               if phrase in email_lower)
        if professional_count > 0:
            reasons.append(f"Uses professional language patterns ({professional_count} indicators)")
    
    # Add URL analysis results if available
    if url_results:
        phishing_urls = [r for r in url_results if r.get('prediction') == 'phishing']
        safe_urls = [r for r in url_results if r.get('prediction') == 'safe']
        
        if phishing_urls:
            reasons.append(f"Contains {len(phishing_urls)} suspicious URLs")
        if safe_urls:
            reasons.append(f"Contains {len(safe_urls)} legitimate URLs")
    
    # Default reason if none found
    if not reasons:
        confidence = email_result.get('confidence', 0.5)
        if email_result.get('prediction') == 'phishing':
            reasons.append(f"ML model detected phishing patterns (confidence: {confidence:.1%})")
        else:
            reasons.append(f"ML model found no suspicious patterns (confidence: {confidence:.1%})")
    
    return reasons[:6]  # Return top 6 reasons

# API Routes
@app.get("/")
async def root():
    return {
        "service": "Optimized Phishing Detection API",
        "version": "4.0.0",
        "status": "operational",
        "features": [
            "Enhanced email phishing detection with ensemble models",
            "Advanced URL analysis with 30 research-based features",
            "Comprehensive threat pattern recognition",
            "Real-time analysis with performance caching",
            "High-accuracy ML models with detailed reasoning"
        ],
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "analyze_email": "/analyze/email",
            "analyze_url": "/analyze/url",
            "analyze_bulk": "/analyze/bulk"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models": {
            "email_model": "loaded" if models['email_ensemble'] else "not_loaded",
            "url_model": "loaded" if models['url_model'] else "not_loaded",
            "feature_extractors": "available"
        },
        "performance": {
            "cache_size": len(prediction_cache),
            "cache_limit": CACHE_LIMIT
        }
    }

@app.post("/predict")
async def predict_email(request: EmailAnalysisRequest):
    """Main prediction endpoint (legacy compatibility)"""
    
    try:
        start_time = time.time()
        
        # Check cache
        cache_key = hashlib.md5(request.email.encode()).hexdigest()
        if cache_key in prediction_cache:
            result = prediction_cache[cache_key]
            result['from_cache'] = True
            result['analysis_time'] = time.time() - start_time
            return result
        
        # Analyze email
        email_result = analyze_email_enhanced(request.email)
        if 'error' in email_result:
            raise HTTPException(status_code=500, detail=email_result['error'])
        
        # Extract and analyze URLs
        urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', request.email)
        url_results = []
        
        for url in urls[:3]:  # Limit to 3 URLs for performance
            url_result = analyze_url_enhanced(url)
            if 'error' not in url_result:
                url_result['url'] = url
                url_results.append(url_result)
        
        # Generate reasons
        reasons = generate_enhanced_reasons(request.email, email_result, url_results)
        
        # Combine results
        final_confidence = email_result['confidence']
        
        # Adjust confidence based on URL analysis
        if url_results:
            phishing_urls = [r for r in url_results if r['prediction'] == 'phishing']
            if phishing_urls and email_result['prediction'] == 'safe':
                # URLs are suspicious, increase phishing probability
                final_confidence = min(final_confidence * 0.6 + 0.3, 0.95)
                email_result['prediction'] = 'phishing'
            elif not phishing_urls and email_result['prediction'] == 'phishing':
                # URLs are safe, but keep email verdict (URLs might be legitimate redirects)
                pass
        
        # Format response for extension compatibility
        prediction_label = "Phishing Email" if email_result['prediction'] == 'phishing' else "Safe Email"
        
        result = {
            "prediction": prediction_label,
            "confidence": round(final_confidence, 3),
            "phishing_confidence": round(email_result.get('phishing_confidence', 0.0), 3),
            "safe_confidence": round(email_result.get('safe_confidence', 1.0), 3),
            "reasons": reasons,
            "analysis_time": round(time.time() - start_time, 3),
            "model_info": {
                "version": "4.0.0",
                "type": "Enhanced Ensemble Model",
                "url_analysis": len(url_results) > 0
            },
            "timestamp": datetime.now().isoformat(),
            "from_cache": False
        }
        
        # Cache result
        if len(prediction_cache) < CACHE_LIMIT:
            prediction_cache[cache_key] = result.copy()
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/email")
async def analyze_email_endpoint(request: EmailAnalysisRequest):
    """Email analysis endpoint"""
    return await predict_email(request)

@app.post("/analyze/url")
async def analyze_url_endpoint(request: URLAnalysisRequest):
    """URL analysis endpoint"""
    
    try:
        start_time = time.time()
        
        result = analyze_url_enhanced(request.url)
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return {
            "url": request.url,
            **result,
            "analysis_time": round(time.time() - start_time, 3),
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/bulk")
async def analyze_bulk_emails(request: BulkAnalysisRequest):
    """Bulk email analysis endpoint"""
    
    start_time = time.time()
    results = []
    
    try:
        for i, email_request in enumerate(request.emails[:10]):  # Limit to 10
            try:
                result = await predict_email(email_request)
                results.append({"index": i, **result})
            except Exception as e:
                results.append({"index": i, "error": str(e)})
        
        return {
            "results": results,
            "total_processed": len(results),
            "processing_time": round(time.time() - start_time, 3),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Model initialization
@app.on_event("startup")
async def startup_event():
    """Initialize optimized models on startup"""
    try:
        logger.info("Starting Optimized Phishing Detection API v4.0.0")
        
        # Train models
        email_accuracy = train_email_models()
        url_accuracy = train_url_model()
        
        models['model_metadata'] = {
            'email_accuracy': email_accuracy,
            'url_accuracy': url_accuracy,
            'startup_time': datetime.now().isoformat(),
            'dataset_info': {
                'email_samples': 45,  # 25 legitimate + 20 phishing
                'url_samples': 'Research dataset loaded',
                'features': {
                    'email_features': len(EnhancedEmailFeatureExtractor().feature_names),
                    'url_features': len(URLFeatureExtractor().feature_names)
                }
            }
        }
        
        logger.info(f"Email model accuracy: {email_accuracy:.3f}")
        logger.info(f"URL model accuracy: {url_accuracy:.3f}")
        logger.info("Optimized API ready for high-accuracy phishing detection!")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8005))
    uvicorn.run(app, host="127.0.0.1", port=port)