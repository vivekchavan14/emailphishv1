from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import re
import numpy as np
from scipy.sparse import hstack
from fastapi.middleware.cors import CORSMiddleware
import os
import logging
from typing import Dict, List, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define email input schema
class EmailInput(BaseModel):
    email: str

# Initialize FastAPI app
app = FastAPI(title="Enhanced Phishing Email Detection API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Well-known legitimate TLDs and domain characteristics
LEGITIMATE_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.co.uk', '.co.in', '.com.au', '.de', '.fr', '.jp', '.cn'
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.pw', '.club', '.online', '.info', '.xyz', '.top',
    '.click', '.download', '.loan', '.work', '.men', '.date', '.racing'
}

# Dynamic legitimacy detection without static lists

# Context-aware legitimate terms that should NOT be flagged
LEGITIMATE_BUSINESS_TERMS = {
    'order', 'delivery', 'payment', 'account', 'subscription', 'service', 'update', 
    'notification', 'receipt', 'invoice', 'statement', 'confirmation', 'booking',
    'reservation', 'membership', 'profile', 'preferences', 'settings', 'support',
    'customer', 'welcome', 'thank you', 'regards', 'sincerely', 'team', 'department'
}

# Enhanced phishing patterns with context awareness
PHISHING_URGENT_PATTERNS = [
    r'\b(?:urgent|immediate|asap|act now|limited time|expires? (?:today|tomorrow|soon))\b',
    r'\b(?:account (?:suspended|blocked|limited|compromised|disabled))\b',
    r'\b(?:verify (?:immediately|now|within|your account|identity))\b',
    r'\b(?:click (?:here )?(?:immediately|now|to (?:verify|confirm|update)))\b',
    r'\b(?:final (?:notice|warning|reminder))\b',
    r'\b(?:security (?:alert|breach|violation))\b'
]

PHISHING_MONEY_PATTERNS = [
    r'\$\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:prize|reward|refund|owed|waiting)',
    r'\b(?:claim your|you (?:have )?won|congratulations.{0,50}winner)\b',
    r'\b(?:inheritance|lottery|jackpot|sweepstakes)\b',
    r'\b(?:transfer.{0,20}million|billion.{0,20}dollars?)\b',
    r'\b(?:bitcoin|cryptocurrency).{0,30}(?:investment|opportunity|profit)\b'
]

PHISHING_CREDENTIAL_PATTERNS = [
    r'\b(?:confirm|verify|update).{0,30}(?:password|credentials|login|account details)\b',
    r'\b(?:social security|ssn|credit card|banking).{0,20}(?:details|information|number)\b',
    r'\b(?:enter your|provide your|submit your).{0,20}(?:password|pin|ssn)\b'
]

# Suspicious URL patterns (not legitimate domains)
SUSPICIOUS_URL_PATTERNS = [
    r'https?://[^/]*\.(?:tk|ml|ga|cf|pw|club|online|info|xyz|top)/',
    r'https?://(?:secure-|verify-|account-|login-)[^/]*\.com/',
    r'https?://[^/]*(?:security|verify|account|login|update)[^/]*\.(?:net|org|info)/',
    r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  # IP addresses
]

def extract_domain_from_email(email_text: str) -> List[str]:
    """Extract domains from email content"""
    # Look for From: headers, email domains, URLs, and plain domain mentions
    domain_patterns = [
        r'from[:\s]+[^@\s]*@([^\s<>\[\]]+)',  # From header
        r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Any email domain
        r'https?://(?:www\.)?([^/\s<>\[\]]+)',  # URL domains
        r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',  # Plain domain mentions (like Claude.ai)
        r'visit\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # "visit domain.com"
        r'go\s+to\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # "go to domain.com"
        r'log\s+in(?:to)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # "log in to domain.com"
    ]
    
    domains = set()
    email_lower = email_text.lower()
    
    for pattern in domain_patterns:
        matches = re.findall(pattern, email_lower, re.IGNORECASE)
        for match in matches:
            domain = match.strip('.,;!?')
            # Filter out obvious non-domains
            if ('.' in domain and 
                len(domain) > 3 and 
                not domain.startswith('.') and 
                not domain.endswith('.') and
                not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)):  # Skip IP addresses for now
                domains.add(domain)
    
    return list(domains)

def calculate_domain_legitimacy_score(domain: str) -> Tuple[float, List[str]]:
    """Calculate a legitimacy score for a domain based on multiple dynamic factors"""
    score = 4.0  # Start with slightly positive bias for legitimate detection
    reasons = []
    
    if not domain or '.' not in domain:
        return 0.0, ["Invalid domain"]
    
    domain_lower = domain.lower()
    
    # 1. TLD analysis (trust indicators)
    domain_parts = domain_lower.split('.')
    if len(domain_parts) >= 2:
        tld = '.' + '.'.join(domain_parts[-2:]) if len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'org'] else '.' + domain_parts[-1]
        
        # Highly suspicious TLDs
        if tld in SUSPICIOUS_TLDS:
            score -= 3.0
            reasons.append(f"Suspicious TLD: {tld}")
        # High-trust TLDs
        elif tld in ['.edu', '.gov', '.mil']:
            score += 3.0
            reasons.append(f"High-trust institutional TLD: {tld}")
        # Standard business TLDs
        elif tld in LEGITIMATE_TLDS:
            score += 1.0
            reasons.append(f"Standard business TLD: {tld}")
    
    # 2. Domain structure analysis
    main_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
    
    # Professional domain length (not too short, not too long)
    if 4 <= len(main_domain) <= 15:
        score += 1.5
        reasons.append("Professional domain length")
    elif len(main_domain) > 25:
        score -= 2.0
        reasons.append("Unusually long domain name")
    elif len(main_domain) <= 3:
        score -= 1.0
        reasons.append("Very short domain name")
    
    # 3. Legitimate business subdomain patterns
    legitimate_subdomain_patterns = [
        r'^(noreply|no-reply)\.',
        r'^(support|help|customer)\.',
        r'^(notifications?|alerts?)\.',
        r'^(mail|email)\.',
        r'^(news|updates?|newsletter)\.',
        r'^(accounts?|login|auth)\.',
        r'^(api|app|mobile)\.',
        r'^(www|web)\.',
        r'^(secure|safe)\.',
        r'^(marketing|promo)\.',
    ]
    
    for pattern in legitimate_subdomain_patterns:
        if re.search(pattern, domain_lower):
            score += 2.0
            reasons.append("Legitimate business communication subdomain")
            break
    
    # 4. Professional domain structure
    if re.search(r'^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$', domain_lower):
        score += 1.0
        reasons.append("Professional domain structure")
    
    # 5. Check for suspicious phishing patterns
    suspicious_patterns = [
        r'\d{3,}',  # Many consecutive digits
        r'^\d+[a-z]+\d+$',  # Alternating numbers and letters pattern
        r'(secure|verify|account|login|update|confirm)-[^.]*$',  # Suspicious prefixes
        r'-?(secure|verify|account|login|update|confirm)$',  # Suspicious suffixes
        r'[0-9]+\.',  # Starts with numbers
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, main_domain):
            score -= 2.0
            reasons.append("Suspicious domain pattern detected")
            break
    
    # 6. Domain age indicators (heuristics)
    # Professional domains tend to have certain characteristics
    if re.search(r'^[a-z]{3,12}\.(com|org|net)$', domain_lower):  # Clean, simple domains
        score += 1.0
        reasons.append("Clean, established domain pattern")
    
    # 7. Check for common business terms and service indicators (positive indicators)
    business_terms = ['corp', 'inc', 'ltd', 'company', 'group', 'team', 'studio', 'tech', 'digital', 'online', 
                     'service', 'services', 'app', 'apps', 'cloud', 'net', 'web', 'media', 'solutions',
                     'platform', 'systems', 'software', 'ai', 'labs', 'hub', 'center', 'store', 'shop']
    for term in business_terms:
        if term in main_domain:
            score += 1.0  # Increased from 0.5
            reasons.append(f"Contains business term: {term}")
            break
    
    # 8. Look for common legitimate service patterns
    service_patterns = [
        r'play\.', r'drive\.', r'docs\.', r'accounts?\.', r'auth\.', r'login\.',  # Service subdomains
        r'cdn\.', r'static\.', r'assets?\.',  # CDN patterns
        r'blog\.', r'news\.', r'help\.', r'support\.',  # Content subdomains
        r'api\.', r'app\.', r'mobile\.',  # API/app subdomains
    ]
    
    for pattern in service_patterns:
        if re.search(pattern, domain_lower):
            score += 1.5
            reasons.append("Common service subdomain pattern")
            break
    
    # 8. Penalize IP addresses
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        score -= 5.0
        reasons.append("IP address instead of domain name")
    
    return min(max(score, 0.0), 10.0), reasons

def is_legitimate_sender(email_text: str) -> Tuple[bool, str]:
    """Dynamic legitimacy check based on multiple factors"""
    domains = extract_domain_from_email(email_text)
    
    if not domains:
        return False, "No domains found"
    
    max_score = 0.0
    best_reasons = []
    best_domain = None
    
    for domain in domains:
        score, reasons = calculate_domain_legitimacy_score(domain)
        if score > max_score:
            max_score = score
            best_reasons = reasons
            best_domain = domain
    
    # Consider legitimate if score is above threshold (lowered for better coverage)
    is_legitimate = max_score >= 4.0
    
    reason = f"Domain: {best_domain}, Score: {max_score:.1f}/10, Reasons: {'; '.join(best_reasons)}"
    
    return is_legitimate, reason

def extract_enhanced_email_features(emails: List[str]) -> np.ndarray:
    """Enhanced feature extraction with legitimate email awareness"""
    num_emails = len(emails)
    
    # Initialize feature arrays
    num_suspicious_links = np.zeros((num_emails, 1))
    phishing_urgency_score = np.zeros((num_emails, 1))
    phishing_money_score = np.zeros((num_emails, 1))
    credential_harvesting_score = np.zeros((num_emails, 1))
    sender_legitimacy_score = np.zeros((num_emails, 1))
    
    for i, email in enumerate(emails):
        email_lower = email.lower()
        
        # 1. Suspicious links (excluding legitimate domains)
        suspicious_link_count = 0
        for pattern in SUSPICIOUS_URL_PATTERNS:
            matches = re.findall(pattern, email, re.IGNORECASE)
            suspicious_link_count += len(matches)
        
        # Don't count links from legitimate domains as suspicious
        domains_in_email = extract_domain_from_email(email)
        for domain in domains_in_email:
            domain_score, _ = calculate_domain_legitimacy_score(domain)
            if domain_score >= 4.0:  # Match new legitimacy threshold
                suspicious_link_count = max(0, suspicious_link_count - 1)  # Reduce penalty for each legitimate domain
        
        num_suspicious_links[i] = min(suspicious_link_count, 10)
        
        # 2. Phishing urgency patterns
        urgency_score = 0
        for pattern in PHISHING_URGENT_PATTERNS:
            matches = re.findall(pattern, email_lower)
            urgency_score += len(matches)
        
        # Reduce urgency score for legitimate business communications
        legitimacy_score = max([calculate_domain_legitimacy_score(d)[0] for d in extract_domain_from_email(email)] + [0.0])
        if legitimacy_score >= 4.0:  # Match new legitimacy threshold
            urgency_score = max(0, urgency_score * (1 - legitimacy_score/15.0))  # Reduce based on legitimacy score
        
        phishing_urgency_score[i] = min(urgency_score, 10)
        
        # 3. Money/prize related phishing
        money_score = 0
        for pattern in PHISHING_MONEY_PATTERNS:
            matches = re.findall(pattern, email_lower)
            money_score += len(matches) * 2  # Weight these heavily
        
        phishing_money_score[i] = min(money_score, 10)
        
        # 4. Credential harvesting attempts
        cred_score = 0
        for pattern in PHISHING_CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, email_lower)
            cred_score += len(matches) * 2
        
        # Don't penalize legitimate password reset emails
        if legitimacy_score >= 4.0 and ('password' in email_lower or 'account' in email_lower):  # Match new legitimacy threshold
            cred_score = max(0, cred_score * (1 - legitimacy_score/12.0))
        
        credential_harvesting_score[i] = min(cred_score, 10)
        
        # 5. Sender legitimacy (higher score = more legitimate)
        domains_in_email = extract_domain_from_email(email)
        if domains_in_email:
            max_domain_score = max([calculate_domain_legitimacy_score(d)[0] for d in domains_in_email])
            sender_legitimacy_score[i] = max_domain_score
        else:
            # Check for business-like characteristics if no domains found
            business_indicators = sum([
                1 for term in LEGITIMATE_BUSINESS_TERMS 
                if re.search(r'\b' + re.escape(term) + r'\b', email_lower)
            ])
            sender_legitimacy_score[i] = min(business_indicators * 0.5, 3.0)  # Lower max score for domain-less emails
    
    # Combine features
    features = np.hstack([
        num_suspicious_links,
        phishing_urgency_score,
        phishing_money_score,
        credential_harvesting_score,
        sender_legitimacy_score
    ])
    
    logger.info(f"Enhanced feature extraction completed. Shape: {features.shape}")
    return features

def calculate_confidence_with_context(features: np.ndarray, prediction_proba: np.ndarray, 
                                     email_text: str) -> Tuple[float, List[str]]:
    """Calculate confidence with contextual adjustments"""
    is_legit, legit_reason = is_legitimate_sender(email_text)
    phishing_prob = float(prediction_proba[1])
    safe_prob = float(prediction_proba[0])
    
    reasons = []
    adjusted_confidence = phishing_prob if phishing_prob > safe_prob else safe_prob
    
    # Contextual adjustments
    if is_legit:
        # Significantly reduce phishing probability for legitimate senders
        phishing_prob *= 0.2
        safe_prob = 1 - phishing_prob
        adjusted_confidence = safe_prob
        reasons.append(legit_reason)
        reasons.append("Sender is from a trusted domain")
    
    # Generate detailed reasoning
    email_features = features[0] if len(features.shape) > 1 else features
    
    if email_features[0] > 2:  # suspicious links
        reasons.append(f"Contains {int(email_features[0])} suspicious links")
    if email_features[1] > 0:  # urgency
        reasons.append(f"Uses urgent/threatening language (score: {email_features[1]:.1f})")
    if email_features[2] > 0:  # money
        reasons.append(f"Contains money/prize claims (score: {email_features[2]:.1f})")
    if email_features[3] > 0:  # credentials
        reasons.append(f"Requests personal/credential information (score: {email_features[3]:.1f})")
    if email_features[4] > 5:  # legitimacy
        reasons.append("Shows characteristics of legitimate business communication")
    
    if not reasons and phishing_prob < 0.3:
        reasons.append("No significant suspicious patterns detected")
    
    return adjusted_confidence, reasons

# Load models (keeping original structure but with enhanced processing)
print("Loading models and preprocessing components...")

try:
    # Try to load advanced model
    try:
        model_path = 'backend/model.pkl' if os.path.exists('backend/model.pkl') else 'model.pkl'
        vectorizer_path = 'backend/vectorizer.pkl' if os.path.exists('backend/vectorizer.pkl') else 'vectorizer.pkl'
        
        with open(model_path, 'rb') as model_file:
            model = pickle.load(model_file)
        
        with open(vectorizer_path, 'rb') as vectorizer_file:
            vectorizer = pickle.load(vectorizer_file)
        
        print(f"Enhanced model loaded successfully from {model_path}")
        use_advanced_model = True
    except FileNotFoundError:
        # Try default model
        default_model_path = 'backend/default_model.pkl' if os.path.exists('backend/default_model.pkl') else 'default_model.pkl'
        
        with open(default_model_path, 'rb') as model_file:
            model = pickle.load(model_file)
        
        with open(vectorizer_path, 'rb') as vectorizer_file:
            vectorizer = pickle.load(vectorizer_file)
        
        print(f"Default model loaded from {default_model_path}")
        use_advanced_model = False

except Exception as e:
    print(f"Error loading models: {e}")
    raise RuntimeError("Failed to load any model. Please train the model first.")

def process_email_enhanced(email_text: str):
    """Enhanced email processing with contextual awareness"""
    try:
        # TF-IDF vectorization
        email_vector = vectorizer.transform([email_text])
        
        # Enhanced feature extraction
        additional_features = extract_enhanced_email_features([email_text])
        
        # Combine features
        combined_features = hstack([email_vector, additional_features])
        
        return combined_features, additional_features
        
    except Exception as e:
        logger.error(f"Error in enhanced email processing: {e}")
        # Fallback to basic processing
        return vectorizer.transform([email_text]), None

@app.post("/predict")
async def predict_enhanced(email: EmailInput):
    """Enhanced prediction endpoint with improved accuracy for legitimate emails"""
    email_text = email.email
    
    try:
        # Process email with enhanced features
        features, additional_features = process_email_enhanced(email_text)
        
        # Make prediction
        prediction = model.predict(features)[0]
        prediction_proba = model.predict_proba(features)[0]
        
        # Enhanced confidence calculation with context
        if additional_features is not None:
            confidence, reasons = calculate_confidence_with_context(
                additional_features, prediction_proba, email_text
            )
        else:
            confidence = float(max(prediction_proba))
            reasons = ["Basic ML model prediction"]
        
        # Determine final prediction label
        phishing_confidence = float(prediction_proba[1])
        safe_confidence = float(prediction_proba[0])
        
        # Check if it's from a legitimate sender
        is_legit, legit_reason = is_legitimate_sender(email_text)
        
        # Override prediction for clearly legitimate emails
        if is_legit:  # Always override for legitimate senders
            prediction = 0  # Mark as safe
            # Force very low phishing confidence for legitimate senders
            domains = extract_domain_from_email(email_text)
            max_domain_score = max([calculate_domain_legitimacy_score(d)[0] for d in domains] + [0.0])
            
            if max_domain_score >= 6.0:  # High legitimacy score
                phishing_confidence = 0.05  # 5% risk
                safe_confidence = 0.95
            elif max_domain_score >= 4.0:  # Medium legitimacy score (matches threshold)
                phishing_confidence = 0.10  # 10% risk
                safe_confidence = 0.90
            else:  # Still legitimate but lower score
                phishing_confidence = 0.12  # 12% risk
                safe_confidence = 0.88
        
        prediction_label = "Phishing Email" if prediction == 1 else "Safe Email"
        # Always return phishing confidence as the main confidence metric for clarity
        final_confidence = phishing_confidence
        
        # Debug logging
        logger.info(f"Email from legitimate sender: {is_legit}")
        logger.info(f"Prediction: {prediction}, Phishing: {phishing_confidence:.3f}, Safe: {safe_confidence:.3f}")
        
        return {
            "prediction": prediction_label,
            "confidence": round(final_confidence, 3),
            "phishing_confidence": round(phishing_confidence, 3),
            "safe_confidence": round(safe_confidence, 3),
            "reasons": reasons,
            "is_legitimate_sender": is_legit,
            "model_type": "Enhanced ML with Legitimate Email Detection"
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Prediction failed: {str(e)}")
        return {
            "error": f"Prediction failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

@app.get("/")
async def root():
    return {
        "status": "online",
        "model_type": "Enhanced Phishing Detection with Legitimate Email Support",
        "version": "2.0",
        "features": [
            "Legitimate domain whitelist",
            "Context-aware pattern matching",
            "Enhanced confidence calculation",
            "Reduced false positives for business emails"
        ]
    }

@app.get("/model_info")
async def model_info():
    return {
        "model_type": type(model).__name__,
        "features": [
            "Suspicious link detection",
            "Phishing urgency patterns", 
            "Money/prize scam detection",
            "Credential harvesting detection",
            "Sender legitimacy scoring"
        ],
        "dynamic_scoring": "Uses purely dynamic domain reputation scoring",
        "scoring_factors": ["TLD analysis", "Domain structure", "Business subdomains", "Professional patterns", "Phishing patterns"]
    }

@app.post("/check_sender")
async def check_sender_legitimacy(email: EmailInput):
    """Endpoint to specifically check if an email sender is legitimate"""
    is_legit, reason = is_legitimate_sender(email.email)
    domains = extract_domain_from_email(email.email)
    
    return {
        "is_legitimate": is_legit,
        "reason": reason,
        "extracted_domains": domains,
        "domain_scores": {d: calculate_domain_legitimacy_score(d)[0] for d in domains},
        "domain_analysis": {d: calculate_domain_legitimacy_score(d)[1] for d in domains}
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1"
    
    print(f"Starting Enhanced Phishing Detection Server on {host}:{port}")
    uvicorn.run("app:app", host=host, port=port, reload=False)
