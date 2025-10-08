#!/usr/bin/env python3
"""
URL/Domain ML-based Phishing Detection System
Replaces static domain whitelisting with dynamic ML-based detection

Based on comprehensive research from:
https://github.com/vaibhavbichave/Phishing-URL-Detection
"""

import pandas as pd
import numpy as np
import requests
import re
import socket
import ipaddress
from urllib.parse import urlparse
import logging
from typing import Dict, List, Tuple, Optional
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import warnings
import os
import shutil

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLFeatureExtractor:
    """Extract comprehensive features from URLs for ML-based classification"""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
    
    def extract_url_features(self, url: str) -> List[float]:
        """Extract 30 comprehensive features from URL"""
        try:
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            features = []
            
            # Feature 1: Using IP address
            features.append(self._using_ip(url))
            
            # Feature 2: URL Length
            features.append(self._long_url(url))
            
            # Feature 3: URL Shortening
            features.append(self._short_url(url))
            
            # Feature 4: Symbol @ in URL
            features.append(self._symbol_at(url))
            
            # Feature 5: Redirecting "//" in URL
            features.append(self._redirecting(url))
            
            # Feature 6: Prefix-Suffix in Domain
            features.append(self._prefix_suffix(domain))
            
            # Feature 7: Number of Sub Domains
            features.append(self._sub_domains(url))
            
            # Feature 8: HTTPS Protocol
            features.append(self._https_protocol(parsed.scheme))
            
            # Feature 9: Domain Registration Length (simplified)
            features.append(self._domain_reg_len(domain))
            
            # Feature 10: Favicon (simplified)
            features.append(self._favicon(domain))
            
            # Feature 11: Non-Standard Port
            features.append(self._non_std_port(parsed.netloc))
            
            # Feature 12: HTTPS in Domain URL
            features.append(self._https_domain_url(domain))
            
            # Features 13-23: Web content based (simplified for URL-only analysis)
            for _ in range(11):  # Simplified web content features
                features.append(0)  # Default neutral value
            
            # Feature 24: Age of Domain (simplified)
            features.append(self._age_of_domain(domain))
            
            # Feature 25: DNS Recording (same as age)
            features.append(features[-1])
            
            # Feature 26: Website Traffic (simplified)
            features.append(self._website_traffic(domain))
            
            # Feature 27: Page Rank (simplified)
            features.append(self._page_rank(domain))
            
            # Feature 28: Google Index (simplified)
            features.append(self._google_index(domain))
            
            # Feature 29: Links Pointing to Page (simplified)
            features.append(self._links_pointing(domain))
            
            # Feature 30: Statistical Reports
            features.append(self._stats_report(url, domain))
            
            return features
            
        except Exception as e:
            logger.warning(f"Error extracting features from {url}: {e}")
            # Return neutral features if extraction fails
            return [0] * 30
    
    def _using_ip(self, url: str) -> int:
        """Check if URL uses IP address"""
        try:
            # Extract domain from URL
            domain = urlparse(url).netloc
            # Try to parse as IP
            ipaddress.ip_address(domain)
            return -1  # Suspicious
        except:
            return 1   # Safe
    
    def _long_url(self, url: str) -> int:
        """Check URL length"""
        if len(url) < 54:
            return 1   # Safe
        elif len(url) <= 75:
            return 0   # Suspicious
        return -1      # Phishing
    
    def _short_url(self, url: str) -> int:
        """Check if URL uses shortening services"""
        shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd',
            'tiny.cc', 'j.mp', 'cutt.us', 'short.link', 'rb.gy'
        ]
        for shortener in shorteners:
            if shortener in url.lower():
                return -1
        return 1
    
    def _symbol_at(self, url: str) -> int:
        """Check for @ symbol"""
        return -1 if '@' in url else 1
    
    def _redirecting(self, url: str) -> int:
        """Check for suspicious redirects"""
        return -1 if url.rfind('//') > 6 else 1
    
    def _prefix_suffix(self, domain: str) -> int:
        """Check for hyphens in domain"""
        return -1 if '-' in domain else 1
    
    def _sub_domains(self, url: str) -> int:
        """Count subdomains"""
        dot_count = url.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1
    
    def _https_protocol(self, scheme: str) -> int:
        """Check HTTPS usage"""
        return 1 if scheme == 'https' else -1
    
    def _domain_reg_len(self, domain: str) -> int:
        """Simplified domain registration check"""
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return -1
        return 1
    
    def _favicon(self, domain: str) -> int:
        """Simplified favicon check"""
        return 1  # Neutral for URL-only analysis
    
    def _non_std_port(self, netloc: str) -> int:
        """Check for non-standard ports"""
        return -1 if ':' in netloc and not netloc.endswith((':80', ':443')) else 1
    
    def _https_domain_url(self, domain: str) -> int:
        """Check if HTTPS is in domain name"""
        return -1 if 'https' in domain else 1
    
    def _age_of_domain(self, domain: str) -> int:
        """Simplified domain age check"""
        # Heuristic: check domain characteristics
        if len(domain) < 5:
            return -1  # Very short domains often suspicious
        
        # Check for common legitimate patterns
        legitimate_patterns = [
            r'^[a-z]+\.(com|org|net|edu|gov)$',
            r'^[a-z]{3,15}\.(com|org|net)$'
        ]
        for pattern in legitimate_patterns:
            if re.match(pattern, domain):
                return 1
        return 0
    
    def _website_traffic(self, domain: str) -> int:
        """Simplified traffic check"""
        # Known high-traffic domains
        popular_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'youtube.com',
            'twitter.com', 'linkedin.com', 'instagram.com', 'github.com',
            'microsoft.com', 'apple.com', 'netflix.com'
        ]
        
        for popular in popular_domains:
            if popular in domain:
                return 1
        
        # Check for common business TLDs
        if any(tld in domain for tld in ['.com', '.org', '.net']):
            return 0
        return -1
    
    def _page_rank(self, domain: str) -> int:
        """Simplified page rank"""
        # Heuristic based on domain structure
        if re.match(r'^[a-z]{3,12}\.(com|org|net|edu)$', domain):
            return 1
        return 0
    
    def _google_index(self, domain: str) -> int:
        """Simplified Google index check"""
        # Assume legitimate-looking domains are indexed
        if '.' in domain and len(domain) > 4:
            return 1
        return -1
    
    def _links_pointing(self, domain: str) -> int:
        """Simplified links pointing check"""
        return 0  # Neutral for URL-only analysis
    
    def _stats_report(self, url: str, domain: str) -> int:
        """Check against known suspicious patterns"""
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]{20,}',  # Very long random strings
            r'\d{4,}',  # Many consecutive digits
        ]
        
        suspicious_domains = [
            '.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top',
            '.click', '.download', '.loan'
        ]
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                return -1
        
        # Check for suspicious TLDs
        for suspicious_tld in suspicious_domains:
            if domain.endswith(suspicious_tld):
                return -1
        
        return 1

class URLPhishingDetector:
    """ML-based URL phishing detector"""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.feature_extractor = URLFeatureExtractor()
        self.model_path = model_path or 'backend/url_phishing_model.pkl'
        
    def load_dataset(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and prepare the phishing URL dataset"""
        try:
            # Copy dataset from the reference repository
            source_path = '/tmp/Phishing-URL-Detection/phishing.csv'
            if os.path.exists(source_path):
                target_path = 'data/phishing_urls.csv'
                os.makedirs('data', exist_ok=True)
                shutil.copy(source_path, target_path)
                logger.info(f"Dataset copied to {target_path}")
            else:
                # Create a sample dataset if reference not available
                target_path = 'data/phishing_urls_sample.csv'
                self._create_sample_dataset(target_path)
            
            # Load dataset
            df = pd.read_csv(target_path)
            
            if 'class' in df.columns:
                # Use existing dataset format
                X = df.drop(['Index', 'class'] if 'Index' in df.columns else ['class'], axis=1)
                y = df['class'].map({-1: 1, 1: 0})  # Convert to binary: 1=phishing, 0=legitimate
            else:
                # Create features from sample dataset
                X, y = self._process_sample_dataset(df)
            
            logger.info(f"Dataset loaded: {len(X)} samples, {X.shape[1] if hasattr(X, 'shape') else len(X.columns)} features")
            logger.info(f"Phishing: {sum(y)}, Legitimate: {len(y) - sum(y)}")
            
            return X, y
            
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            # Create minimal sample dataset
            return self._create_minimal_dataset()
    
    def _create_sample_dataset(self, file_path: str):
        """Create a sample dataset for demonstration"""
        sample_urls = {
            'url': [
                'https://www.google.com',
                'https://www.amazon.com',
                'https://github.com',
                'https://stackoverflow.com',
                'https://www.microsoft.com',
                'https://www.apple.com',
                'http://paypal-verify.tk',
                'https://amazon-security.ml',
                'http://192.168.1.1/bank',
                'https://secure-login.xyz',
                'http://bit.ly/suspicious',
                'https://fake-bank.info',
            ],
            'label': [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]  # 0=legitimate, 1=phishing
        }
        
        df = pd.DataFrame(sample_urls)
        df.to_csv(file_path, index=False)
        logger.info(f"Sample dataset created at {file_path}")
    
    def _process_sample_dataset(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Process sample dataset by extracting features"""
        features_list = []
        labels = []
        
        for _, row in df.iterrows():
            url = row['url']
            label = row['label']
            
            features = self.feature_extractor.extract_url_features(url)
            features_list.append(features)
            labels.append(label)
        
        feature_columns = [f'feature_{i}' for i in range(len(features_list[0]))]
        X = pd.DataFrame(features_list, columns=feature_columns)
        y = pd.Series(labels)
        
        return X, y
    
    def _create_minimal_dataset(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Create minimal dataset as fallback"""
        logger.warning("Creating minimal dataset for demonstration")
        
        urls = [
            'https://www.google.com', 'https://amazon.com', 'https://github.com',
            'http://suspicious.tk', 'https://phishing.ml', 'http://192.168.1.1'
        ]
        labels = [0, 0, 0, 1, 1, 1]
        
        features_list = []
        for url in urls:
            features = self.feature_extractor.extract_url_features(url)
            features_list.append(features)
        
        feature_columns = [f'feature_{i}' for i in range(len(features_list[0]))]
        X = pd.DataFrame(features_list, columns=feature_columns)
        y = pd.Series(labels)
        
        return X, y
    
    def train_model(self, X: pd.DataFrame, y: pd.Series):
        """Train the URL phishing detection model"""
        logger.info("Training URL phishing detection model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model trained successfully!")
        logger.info(f"Accuracy: {accuracy:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=3)
        logger.info(f"Cross-validation: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        return accuracy, cv_scores.mean()
    
    def save_model(self):
        """Save the trained model"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load a pre-trained model"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {self.model_path}")
            return True
        except FileNotFoundError:
            logger.warning(f"Model file not found: {self.model_path}")
            return False
    
    def predict_url(self, url: str) -> Tuple[bool, float, List[str]]:
        """Predict if a URL is phishing"""
        if not self.model:
            raise ValueError("Model not trained or loaded")
        
        # Extract features
        features = self.feature_extractor.extract_url_features(url)
        
        # Make prediction
        X = np.array([features])
        prediction = self.model.predict(X)[0]
        prediction_proba = self.model.predict_proba(X)[0]
        
        is_phishing = prediction == 1
        confidence = float(prediction_proba[1] if is_phishing else prediction_proba[0])
        
        # Generate reasons
        reasons = self._generate_reasons(features, url, is_phishing)
        
        return is_phishing, confidence, reasons
    
    def _generate_reasons(self, features: List[float], url: str, is_phishing: bool) -> List[str]:
        """Generate human-readable reasons for the prediction"""
        reasons = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check specific features that contribute to the decision
            if features[0] == -1:  # Using IP
                reasons.append("Uses IP address instead of domain name")
            if features[1] == -1:  # Long URL
                reasons.append("Unusually long URL")
            if features[2] == -1:  # Short URL
                reasons.append("Uses URL shortening service")
            if features[3] == -1:  # Symbol @
                reasons.append("Contains '@' symbol")
            if features[5] == -1:  # Prefix-suffix
                reasons.append("Domain contains hyphens")
            if features[6] == -1:  # Subdomains
                reasons.append("Multiple suspicious subdomains")
            if features[7] == -1:  # No HTTPS
                reasons.append("Does not use HTTPS protocol")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                reasons.append("Uses suspicious top-level domain")
            
            # Check for suspicious patterns
            if re.search(r'\d{4,}', domain):
                reasons.append("Domain contains many consecutive digits")
            
            if not reasons:
                if is_phishing:
                    reasons.append("Classified as suspicious by ML model")
                else:
                    reasons.append("URL appears legitimate based on comprehensive analysis")
            
        except Exception as e:
            logger.warning(f"Error generating reasons: {e}")
            reasons = ["Analysis completed using ML model"]
        
        return reasons[:5]  # Return top 5 reasons

def main():
    """Main function to train the URL phishing detection model"""
    logger.info("Starting URL Phishing Detection Model Training...")
    
    # Initialize detector
    detector = URLPhishingDetector()
    
    # Load dataset
    X, y = detector.load_dataset()
    
    # Train model
    accuracy, cv_score = detector.train_model(X, y)
    
    # Save model
    detector.save_model()
    
    logger.info("URL phishing detection model training completed!")
    logger.info(f"Final accuracy: {accuracy:.4f}")
    logger.info(f"Cross-validation score: {cv_score:.4f}")
    
    # Test with sample URLs
    test_urls = [
        "https://www.google.com",
        "https://www.amazon.com", 
        "http://paypal-verify.tk",
        "https://suspicious-banking.ml",
        "http://192.168.1.1/login"
    ]
    
    logger.info("\nTesting with sample URLs:")
    for url in test_urls:
        try:
            is_phishing, confidence, reasons = detector.predict_url(url)
            status = "PHISHING" if is_phishing else "LEGITIMATE"
            logger.info(f"{url}: {status} (confidence: {confidence:.3f})")
            if reasons:
                logger.info(f"  Reasons: {reasons[0]}")
        except Exception as e:
            logger.error(f"Error testing {url}: {e}")

if __name__ == "__main__":
    main()