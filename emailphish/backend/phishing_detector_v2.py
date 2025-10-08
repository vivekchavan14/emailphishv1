#!/usr/bin/env python3
"""
Focused Phishing Email Detector - Designed specifically for phishing (not spam) detection.
This should correctly identify obvious phishing attempts like "send me your credit card details".
"""

import pandas as pd
import numpy as np
import re
import logging
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from scipy.sparse import hstack
import pickle

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDetector:
    """Focused phishing detector with rule-based + ML approach"""
    
    def __init__(self):
        # CRITICAL PHISHING KEYWORDS - If any of these appear, it's likely phishing
        self.critical_keywords = [
            # Direct credential requests
            'send me your credit card', 'send your credit card', 'give me your credit card',
            'send me your password', 'send your password', 'give me your password',
            'send me your bank', 'send your bank', 'give me your bank',
            'send me your social security', 'send your social security', 'send your ssn',
            'send me your pin', 'send your pin', 'give me your pin',
            'send me your cvv', 'send your cvv', 'give me your cvv',
            'send me your routing', 'send your routing', 
            'send me your account number', 'send your account number',
            'send me your personal information', 'send your personal information',
            'send me your details', 'send your details', 'give me your details',
            'provide your credit card', 'provide your password', 'provide your bank',
            'provide your social security', 'provide your ssn', 'provide your pin',
            
            # Money requests
            'send me money', 'send money', 'wire money', 'transfer money to me',
            'send me bitcoin', 'send bitcoin', 'send crypto',
            'i need money', 'need money urgently', 'emergency money',
            
            # Suspicious questions
            'what is your credit card', 'what is your password', 'what is your pin',
            'what is your social security', 'what is your ssn', 'what is your bank',
            'what is your mother maiden name', "mother's maiden name",
            
            # Authority impersonation with requests
            'irs send', 'fbi send', 'police send', 'government send',
            'bank send your', 'microsoft send your', 'apple send your',
            'google send your', 'paypal send your',
        ]
        
        # URGENT + CREDENTIAL PATTERNS (very suspicious combination)
        self.urgent_credential_patterns = [
            r'urgent.*credit card', r'urgent.*password', r'urgent.*bank',
            r'emergency.*credit card', r'emergency.*password', r'emergency.*bank',
            r'immediately.*credit card', r'immediately.*password', r'immediately.*bank',
            r'asap.*credit card', r'asap.*password', r'asap.*bank',
            r'right now.*credit card', r'right now.*password', r'right now.*bank',
        ]
        
        # FINANCIAL + ACTION PATTERNS
        self.financial_action_patterns = [
            r'send.*credit card.*details', r'send.*bank.*details', r'send.*personal.*info',
            r'provide.*credit card.*info', r'provide.*bank.*account', r'provide.*ssn',
            r'give.*credit card.*number', r'give.*bank.*details', r'give.*password',
            r'need.*credit card.*info', r'need.*bank.*details', r'need.*personal.*info',
        ]
        
        # Legitimate indicators (lower phishing score)
        self.legitimate_indicators = [
            'unsubscribe', 'customer service', 'support team', 'help desk',
            'thank you for', 'order confirmation', 'receipt', 'invoice',
            'newsletter', 'subscription', 'account statement', 'bill',
            'appointment', 'meeting', 'conference', 'webinar',
            'policy update', 'terms of service', 'privacy policy'
        ]
        
        self.model = None
        self.vectorizer = None
        
    def extract_phishing_features(self, email_text):
        """Extract phishing-specific features"""
        features = []
        email_lower = email_text.lower()
        
        # Critical keyword detection (most important feature)
        critical_count = sum(1 for keyword in self.critical_keywords if keyword in email_lower)
        features.append(critical_count * 10)  # Heavy weight for critical keywords
        
        # Urgent + credential pattern matching
        urgent_cred_count = sum(1 for pattern in self.urgent_credential_patterns 
                               if re.search(pattern, email_lower))
        features.append(urgent_cred_count * 5)
        
        # Financial action pattern matching  
        financial_action_count = sum(1 for pattern in self.financial_action_patterns
                                   if re.search(pattern, email_lower))
        features.append(financial_action_count * 3)
        
        # Basic text features
        words = email_text.split()
        features.extend([
            len(email_text),  # length
            len(words),  # word count
            email_text.count('!'),  # exclamation marks
            email_text.count('?'),  # question marks
            email_text.count('$'),  # dollar signs
        ])
        
        # Character ratios
        if len(email_text) > 0:
            features.extend([
                sum(1 for c in email_text if c.isupper()) / len(email_text),  # uppercase ratio
                sum(1 for c in email_text if c.isdigit()) / len(email_text),   # digit ratio
            ])
        else:
            features.extend([0.0, 0.0])
        
        # Specific phishing indicators
        phishing_words = ['urgent', 'emergency', 'asap', 'immediately', 'critical',
                         'suspend', 'terminate', 'expire', 'deadline', 'final notice',
                         'verify', 'confirm', 'update', 'security', 'fraud', 'hack']
        phishing_count = sum(1 for word in phishing_words if word in email_lower)
        features.append(phishing_count)
        
        # Legitimate indicators (negative weight)
        legit_count = sum(1 for indicator in self.legitimate_indicators if indicator in email_lower)
        features.append(-legit_count)  # Negative because it reduces phishing score
        
        # Financial terms
        financial_terms = ['credit card', 'bank account', 'social security', 'ssn', 'pin',
                          'password', 'login', 'cvv', 'routing', 'account number']
        financial_count = sum(1 for term in financial_terms if term in email_lower)
        features.append(financial_count)
        
        return np.array(features)
    
    def rule_based_detection(self, email_text):
        """Rule-based detection for obvious phishing"""
        email_lower = email_text.lower()
        
        # If any critical keyword is found, it's very likely phishing
        for keyword in self.critical_keywords:
            if keyword in email_lower:
                return True, f"Contains critical phishing keyword: '{keyword}'"
        
        # Check for urgent + credential combination
        for pattern in self.urgent_credential_patterns:
            if re.search(pattern, email_lower):
                return True, f"Urgent credential request pattern detected"
        
        # Check for financial action patterns
        for pattern in self.financial_action_patterns:
            if re.search(pattern, email_lower):
                return True, f"Financial information request pattern detected"
        
        return False, "No obvious phishing patterns detected"
    
    def train(self, dataset_path='phishing_detection_dataset.csv'):
        """Train the phishing detector"""
        logger.info("Training focused phishing detector...")
        
        # Load dataset
        df = pd.read_csv(dataset_path)
        logger.info(f"Loaded dataset with {len(df)} emails")
        
        # Extract custom features
        logger.info("Extracting phishing-specific features...")
        custom_features = np.array([self.extract_phishing_features(email) for email in df['email']])
        
        # TF-IDF features
        logger.info("Creating TF-IDF features...")
        self.vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 2),
            stop_words='english',
            lowercase=True,
            min_df=2,
            max_df=0.9
        )
        tfidf_features = self.vectorizer.fit_transform(df['email'])
        
        # Combine features
        X_combined = hstack([tfidf_features, custom_features])
        y = df['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train models with focus on recall (catching phishing)
        logger.info("Training ensemble models...")
        
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight={0: 1, 1: 3},  # Give more weight to phishing class
            random_state=42
        )
        
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        
        lr_model = LogisticRegression(
            C=1.0,
            penalty='l2',
            class_weight={0: 1, 1: 2},  # Give more weight to phishing class
            random_state=42,
            max_iter=1000
        )
        
        # Create ensemble
        self.model = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('gb', gb_model), 
                ('lr', lr_model)
            ],
            voting='soft'
        )
        
        # Train
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model accuracy: {accuracy:.3f}")
        logger.info("\\nDetailed results:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Test on some obvious examples
        logger.info("\\nTesting on obvious phishing examples:")
        test_emails = [
            "send me your credit card details",
            "I need your bank account information", 
            "provide your social security number",
            "Thank you for your order. It will arrive soon."
        ]
        
        for email in test_emails:
            prediction = self.predict(email)
            logger.info(f"'{email}' -> {prediction}")
        
        return accuracy
    
    def predict(self, email_text):
        """Predict if email is phishing"""
        # First try rule-based detection
        is_phishing_rule, reason = self.rule_based_detection(email_text)
        if is_phishing_rule:
            return {
                'prediction': 'phishing',
                'confidence': 0.95,
                'method': 'rule-based',
                'reason': reason
            }
        
        # If no obvious rules triggered, use ML model
        if self.model is None or self.vectorizer is None:
            return {
                'prediction': 'unknown',
                'confidence': 0.5,
                'method': 'no model',
                'reason': 'Model not trained'
            }
        
        # Extract features
        custom_features = self.extract_phishing_features(email_text).reshape(1, -1)
        tfidf_features = self.vectorizer.transform([email_text])
        X_combined = hstack([tfidf_features, custom_features])
        
        # Predict
        prediction = self.model.predict(X_combined)[0]
        probabilities = self.model.predict_proba(X_combined)[0]
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(max(probabilities)),
            'method': 'ml-model',
            'phishing_probability': float(probabilities[1]),
            'safe_probability': float(probabilities[0])
        }
    
    def save(self, filepath='phishing_detector_v2.pkl'):
        """Save the trained detector"""
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)
        logger.info(f"Detector saved to {filepath}")
    
    @classmethod
    def load(cls, filepath='phishing_detector_v2.pkl'):
        """Load a trained detector"""
        with open(filepath, 'rb') as f:
            detector = pickle.load(f)
        logger.info(f"Detector loaded from {filepath}")
        return detector

def main():
    """Train and test the phishing detector"""
    detector = PhishingDetector()
    
    # Train the detector
    accuracy = detector.train()
    
    # Save the detector
    detector.save()
    
    logger.info(f"\\nPhishing detector trained with {accuracy:.1%} accuracy and saved!")
    
    return detector

if __name__ == "__main__":
    main()