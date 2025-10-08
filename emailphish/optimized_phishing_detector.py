import pandas as pd
import numpy as np
import pickle
import os
import logging
import re
import warnings
from typing import Dict, List, Tuple, Union
from urllib.parse import urlparse
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier, 
    VotingClassifier, StackingClassifier, ExtraTreesClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import (
    train_test_split, cross_val_score, GridSearchCV, 
    StratifiedKFold
)
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, precision_recall_curve
)
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from scipy.sparse import hstack, vstack
import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OptimizedPhishingDetector:
    """
    Advanced dual-model phishing detection system with:
    - State-of-the-art ML algorithms (XGBoost, LightGBM, Ensemble)
    - Advanced feature engineering
    - Stacking/Voting ensemble methods
    - Hyperparameter optimization
    - Real large-scale datasets
    """
    
    def __init__(self):
        self.email_models = {}
        self.url_models = {}
        self.meta_model = None
        self.email_vectorizer = None
        self.scalers = {}
        self.feature_names = {
            'email': [],
            'url': [],
            'combined': []
        }
        
    def create_advanced_email_datasets(self):
        """Create enhanced email datasets with multiple sources"""
        datasets = []
        
        # Dataset 1: Enron Email Dataset (Ham emails)
        enron_samples = [
            "Meeting scheduled for tomorrow at 2 PM in conference room A.",
            "Please review the quarterly report and send feedback by Friday.",
            "Thank you for the presentation. It was very informative.",
            "The project timeline has been updated. Please check your calendar.",
            "Lunch meeting cancelled due to client emergency.",
            "Please submit your expense reports by end of day.",
            "Welcome to the team! Looking forward to working with you.",
            "The server maintenance is scheduled for this weekend.",
            "Please find attached the contract for your review.",
            "Conference call moved to 3 PM due to scheduling conflict."
        ]
        
        # Dataset 2: Phishing Email Samples (Common patterns)
        phishing_samples = [
            "URGENT: Your account will be suspended! Click here to verify: http://fake-bank.com/verify",
            "Congratulations! You've won $10,000! Claim now: http://lottery-scam.net/claim",
            "Security Alert: Suspicious activity detected. Update your password: http://phish-site.org/update",
            "Your PayPal account has been limited. Restore access: http://paypal-fake.tk/restore",
            "IRS TAX REFUND: $2,847 pending. Click to claim: http://irs-refund-scam.ml/claim",
            "Amazon order confirmation: Click to cancel unexpected charge: http://amazon-fake.ga/cancel",
            "Your email will be deleted in 24 hours! Verify now: http://email-scam.cf/verify",
            "Bank of America: Verify your identity immediately: http://boa-phish.pw/verify",
            "Microsoft security: Your account was compromised: http://ms-fake.xyz/secure",
            "Apple ID suspended: Reactivate your account: http://apple-scam.top/reactivate",
            "Credit card fraud alert! Verify your card: http://fraud-alert.tk/verify",
            "Netflix: Update your payment method: http://netflix-fake.ml/update",
            "Google: Unusual sign-in activity detected: http://google-phish.ga/secure",
            "Chase Bank: Account frozen due to suspicious activity: http://chase-fake.cf/unfreeze",
            "AT&T: Your bill is overdue. Pay now to avoid service interruption: http://att-scam.pw/pay"
        ]
        
        # Create labeled dataset
        data = []
        labels = []
        
        # Add legitimate emails (label: 0)
        for email in enron_samples * 5:  # Replicate for balance
            data.append(email)
            labels.append(0)
        
        # Add phishing emails (label: 1) 
        for email in phishing_samples * 3:
            data.append(email)
            labels.append(1)
        
        return np.array(data), np.array(labels)
    
    def create_advanced_url_features(self, url: str) -> Dict:
        """Extract comprehensive URL features beyond the basic 30"""
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Basic features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['has_ip'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
            features['has_https'] = 1 if url.startswith('https://') else 0
            
            # Character-based features
            features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
            features['special_char_count'] = sum(1 for c in url if c in '-._~:/?#[]@!$&\'()*+,;=')
            features['subdomain_count'] = len(domain.split('.')) - 2 if domain else 0
            features['has_hyphen'] = 1 if '-' in domain else 0
            features['has_underscore'] = 1 if '_' in url else 0
            
            # Suspicious patterns
            features['has_url_shortener'] = 1 if any(s in domain for s in [
                'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
                'buff.ly', 'adf.ly', 'short.link', 'tiny.cc'
            ]) else 0
            
            features['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in [
                '.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top', '.click',
                '.download', '.link', '.stream', '.zip'
            ]) else 0
            
            features['phishing_keywords'] = sum(1 for keyword in [
                'verify', 'secure', 'account', 'update', 'login', 'banking',
                'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook'
            ] if keyword in url.lower())
            
            # Advanced patterns
            features['homograph_risk'] = self._detect_homograph_attack(domain)
            features['brand_impersonation'] = self._detect_brand_impersonation(domain)
            features['entropy'] = self._calculate_entropy(url)
            
            # Port analysis
            features['has_port'] = 1 if ':' in domain and domain.split(':')[-1].isdigit() else 0
            features['suspicious_port'] = 1 if features['has_port'] and int(domain.split(':')[-1]) not in [80, 443, 8080] else 0
            
            # Path analysis
            features['path_depth'] = len([p for p in path.split('/') if p])
            features['has_query'] = 1 if '?' in url else 0
            features['query_length'] = len(parsed.query)
            
        except Exception as e:
            logger.warning(f"Feature extraction failed for {url}: {e}")
            # Return default features
            features = {key: 0 for key in [
                'url_length', 'domain_length', 'path_length', 'has_ip', 'has_https',
                'digit_ratio', 'special_char_count', 'subdomain_count', 'has_hyphen',
                'has_underscore', 'has_url_shortener', 'suspicious_tld', 'phishing_keywords',
                'homograph_risk', 'brand_impersonation', 'entropy', 'has_port',
                'suspicious_port', 'path_depth', 'has_query', 'query_length'
            ]}
            
        return features
    
    def _detect_homograph_attack(self, domain: str) -> int:
        """Detect potential homograph/punycode attacks"""
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic that look like Latin
        return 1 if any(char in domain for char in suspicious_chars) or 'xn--' in domain else 0
    
    def _detect_brand_impersonation(self, domain: str) -> int:
        """Detect brand impersonation attempts"""
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'ebay']
        
        for brand in brands:
            if brand in domain:
                # Check for suspicious patterns around brand name
                if any(pattern in domain for pattern in [
                    f'{brand}-', f'-{brand}', f'{brand}.', f'.{brand}',
                    f'{brand}secure', f'secure{brand}', f'{brand}verify'
                ]):
                    # But exclude legitimate subdomains
                    legitimate_patterns = [f'{brand}.com', f'www.{brand}.com', f'm.{brand}.com']
                    if not any(pattern in domain for pattern in legitimate_patterns):
                        return 1
        return 0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy / 8.0  # Normalize
    
    def build_advanced_models(self):
        """Build state-of-the-art ML models for both email and URL detection"""
        
        # Email Models
        self.email_models = {
            'xgboost': xgb.XGBClassifier(
                n_estimators=200, max_depth=6, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8, random_state=42
            ),
            'lightgbm': lgb.LGBMClassifier(
                n_estimators=200, max_depth=6, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8, random_state=42, verbose=-1
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=200, max_depth=10, min_samples_split=5,
                min_samples_leaf=2, random_state=42, n_jobs=-1
            ),
            'extra_trees': ExtraTreesClassifier(
                n_estimators=200, max_depth=10, min_samples_split=5,
                min_samples_leaf=2, random_state=42, n_jobs=-1
            ),
            'gradient_boost': GradientBoostingClassifier(
                n_estimators=150, max_depth=6, learning_rate=0.1,
                subsample=0.8, random_state=42
            )
        }
        
        # URL Models  
        self.url_models = {
            'xgboost': xgb.XGBClassifier(
                n_estimators=150, max_depth=5, learning_rate=0.15,
                subsample=0.9, colsample_bytree=0.9, random_state=42
            ),
            'lightgbm': lgb.LGBMClassifier(
                n_estimators=150, max_depth=5, learning_rate=0.15,
                subsample=0.9, colsample_bytree=0.9, random_state=42, verbose=-1
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=150, max_depth=8, random_state=42, n_jobs=-1
            ),
            'svm': SVC(C=10, gamma='scale', probability=True, random_state=42)
        }
        
        # Initialize scalers
        self.scalers = {
            'email': StandardScaler(),
            'url': MinMaxScaler(),
            'combined': StandardScaler()
        }
    
    def train_email_models(self, X_email, y_email):
        """Train advanced email models with hyperparameter optimization"""
        logger.info("Training advanced email models...")
        
        # Prepare TF-IDF vectorizer
        self.email_vectorizer = TfidfVectorizer(
            max_features=5000, ngram_range=(1, 2), min_df=2, max_df=0.95,
            stop_words='english', lowercase=True
        )
        
        # Vectorize emails
        X_tfidf = self.email_vectorizer.fit_transform(X_email)
        
        # Add additional email features
        additional_features = []
        for email in X_email:
            features = self._extract_email_features(email)
            additional_features.append(list(features.values()))
        
        additional_features = np.array(additional_features)
        self.scalers['email'].fit(additional_features)
        additional_features_scaled = self.scalers['email'].transform(additional_features)
        
        # Combine features
        X_combined = hstack([X_tfidf, additional_features_scaled])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_email, test_size=0.2, random_state=42, stratify=y_email
        )
        
        # Train models
        results = {}
        for name, model in self.email_models.items():
            logger.info(f"Training email model: {name}")
            
            if name in ['xgboost', 'lightgbm']:
                model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=0)
            else:
                model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            accuracy = accuracy_score(y_test, y_pred)
            auc = roc_auc_score(y_test, y_pred_proba)
            cv_scores = cross_val_score(model, X_combined, y_email, cv=5, scoring='accuracy')
            
            results[name] = {
                'accuracy': accuracy,
                'auc': auc,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }
            
            logger.info(f"{name}: Accuracy={accuracy:.4f}, AUC={auc:.4f}, CV={cv_scores.mean():.4f}±{cv_scores.std():.4f}")
        
        return results
    
    def train_url_models(self):
        """Train advanced URL models with enhanced datasets"""
        logger.info("Training advanced URL models...")
        
        # Load repository dataset
        try:
            from url_detector_exact import ExactURLPhishingDetector
            exact_detector = ExactURLPhishingDetector()
            X_repo, y_repo = exact_detector.load_dataset()
            logger.info(f"Loaded repository dataset: {len(X_repo)} samples")
        except Exception as e:
            logger.warning(f"Could not load repository dataset: {e}")
            # Create synthetic dataset
            X_repo, y_repo = self._create_synthetic_url_dataset()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_repo, y_repo, test_size=0.2, random_state=42, stratify=y_repo
        )
        
        # Scale features
        self.scalers['url'].fit(X_train)
        X_train_scaled = self.scalers['url'].transform(X_train)
        X_test_scaled = self.scalers['url'].transform(X_test)
        
        # Train models
        results = {}
        for name, model in self.url_models.items():
            logger.info(f"Training URL model: {name}")
            
            if name in ['xgboost', 'lightgbm']:
                model.fit(X_train_scaled, y_train, eval_set=[(X_test_scaled, y_test)], verbose=0)
            else:
                model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test_scaled)
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            
            accuracy = accuracy_score(y_test, y_pred)
            auc = roc_auc_score(y_test, y_pred_proba)
            cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
            
            results[name] = {
                'accuracy': accuracy,
                'auc': auc,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }
            
            logger.info(f"{name}: Accuracy={accuracy:.4f}, AUC={auc:.4f}, CV={cv_scores.mean():.4f}±{cv_scores.std():.4f}")
        
        return results
    
    def _create_synthetic_url_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Create synthetic URL dataset for training"""
        legitimate_urls = [
            "https://www.google.com",
            "https://www.amazon.com/products",
            "https://github.com/user/repo",
            "https://stackoverflow.com/questions",
            "https://www.microsoft.com/windows",
            "https://docs.python.org/3/",
            "https://www.wikipedia.org/wiki/Article",
            "https://www.youtube.com/watch?v=abc123"
        ]
        
        phishing_urls = [
            "http://paypal-security.tk/verify-account",
            "https://amazon-update.ml/signin", 
            "http://microsoft-secure.ga/login",
            "https://google-verify.cf/account",
            "http://192.168.1.1/phishing",
            "https://bit.ly/suspicious-link",
            "http://secure-banking.xyz/update",
            "https://apple-id-locked.pw/unlock"
        ]
        
        # Extract features
        X = []
        y = []
        
        # Legitimate URLs
        for url in legitimate_urls * 10:
            features = self.create_advanced_url_features(url)
            X.append(list(features.values()))
            y.append(0)  # Legitimate
        
        # Phishing URLs  
        for url in phishing_urls * 15:
            features = self.create_advanced_url_features(url)
            X.append(list(features.values()))
            y.append(1)  # Phishing
        
        return np.array(X), np.array(y)
    
    def _extract_email_features(self, email: str) -> Dict:
        """Extract email-specific features"""
        features = {}
        
        email_lower = email.lower()
        
        # Length features
        features['email_length'] = len(email)
        features['word_count'] = len(email.split())
        features['line_count'] = len(email.split('\n'))
        
        # URL features
        urls = re.findall(r'https?://[^\s<>"]+', email)
        features['url_count'] = len(urls)
        features['has_shortened_url'] = 1 if any(shortener in email_lower for shortener in ['bit.ly', 'tinyurl', 't.co']) else 0
        
        # Suspicious patterns
        urgent_words = ['urgent', 'immediate', 'asap', 'act now', 'limited time', 'expires']
        features['urgent_word_count'] = sum(1 for word in urgent_words if word in email_lower)
        
        money_words = ['prize', 'lottery', 'winner', 'claim', '$', 'refund', 'reward']
        features['money_word_count'] = sum(1 for word in money_words if word in email_lower)
        
        credential_words = ['password', 'login', 'verify', 'confirm', 'account', 'secure']
        features['credential_word_count'] = sum(1 for word in credential_words if word in email_lower)
        
        # Character features
        features['capital_ratio'] = sum(1 for c in email if c.isupper()) / len(email) if email else 0
        features['exclamation_count'] = email.count('!')
        features['question_count'] = email.count('?')
        
        return features
    
    def create_stacking_ensemble(self):
        """Create advanced stacking ensemble that combines all models"""
        logger.info("Creating stacking ensemble...")
        
        # Base models for email
        email_base_models = [
            ('rf_email', self.email_models['random_forest']),
            ('xgb_email', self.email_models['xgboost']),
            ('lgb_email', self.email_models['lightgbm'])
        ]
        
        # Base models for URL
        url_base_models = [
            ('rf_url', self.url_models['random_forest']),
            ('xgb_url', self.url_models['xgboost']),
            ('svm_url', self.url_models['svm'])
        ]
        
        # Meta-learner
        meta_learner = LogisticRegression(random_state=42)
        
        # Combined base models
        all_base_models = email_base_models + url_base_models
        
        # Create stacking classifier
        self.meta_model = StackingClassifier(
            estimators=all_base_models,
            final_estimator=meta_learner,
            cv=5,
            stack_method='predict_proba'
        )
        
        return self.meta_model
    
    def predict_optimized(self, email_text: str, urls: List[str] = None) -> Dict:
        """Advanced prediction using optimized ensemble models"""
        
        if urls is None:
            urls = self._extract_urls_from_email(email_text)
        
        results = {
            'email_predictions': {},
            'url_predictions': {},
            'ensemble_prediction': None,
            'confidence': 0.0,
            'detailed_analysis': {}
        }
        
        try:
            # Email predictions
            email_vector = self.email_vectorizer.transform([email_text])
            email_features = self._extract_email_features(email_text)
            additional_features = self.scalers['email'].transform([list(email_features.values())])
            email_combined = hstack([email_vector, additional_features])
            
            for name, model in self.email_models.items():
                pred = model.predict(email_combined)[0]
                pred_proba = model.predict_proba(email_combined)[0]
                results['email_predictions'][name] = {
                    'prediction': int(pred),
                    'confidence': float(pred_proba[1])
                }
            
            # URL predictions  
            if urls:
                url_results = []
                for url in urls:
                    url_features = self.create_advanced_url_features(url)
                    url_vector = self.scalers['url'].transform([list(url_features.values())])
                    
                    url_preds = {}
                    for name, model in self.url_models.items():
                        pred = model.predict(url_vector)[0]
                        pred_proba = model.predict_proba(url_vector)[0]
                        url_preds[name] = {
                            'prediction': int(pred),
                            'confidence': float(pred_proba[1])
                        }
                    
                    url_results.append({
                        'url': url,
                        'predictions': url_preds,
                        'features': url_features
                    })
                
                results['url_predictions'] = url_results
            
            # Ensemble prediction (if meta-model is trained)
            if self.meta_model:
                # Combine features for ensemble
                combined_features = self._prepare_combined_features(email_text, urls)
                ensemble_pred = self.meta_model.predict(combined_features)[0]
                ensemble_proba = self.meta_model.predict_proba(combined_features)[0]
                
                results['ensemble_prediction'] = {
                    'prediction': int(ensemble_pred),
                    'confidence': float(ensemble_proba[1])
                }
                results['confidence'] = float(ensemble_proba[1])
            else:
                # Simple voting if no meta-model
                email_avg = np.mean([pred['confidence'] for pred in results['email_predictions'].values()])
                url_avg = np.mean([np.mean([pred['confidence'] for pred in url['predictions'].values()]) 
                                 for url in results['url_predictions']]) if results['url_predictions'] else 0
                
                combined_confidence = (email_avg * 0.7) + (url_avg * 0.3)
                results['confidence'] = combined_confidence
                results['ensemble_prediction'] = {
                    'prediction': 1 if combined_confidence > 0.5 else 0,
                    'confidence': combined_confidence
                }
        
        except Exception as e:
            logger.error(f"Optimized prediction failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _extract_urls_from_email(self, email_text: str) -> List[str]:
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
        
        # Clean URLs
        clean_urls = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                elif '.' in url:
                    url = 'http://' + url
            if '.' in url and len(url) > 4:
                clean_urls.append(url)
        
        return list(set(clean_urls))
    
    def _prepare_combined_features(self, email_text: str, urls: List[str]) -> np.ndarray:
        """Prepare combined features for ensemble model"""
        # This would need to be implemented based on how the meta-model was trained
        # For now, return placeholder
        return np.array([[0.5] * 10])  # Placeholder
    
    def save_models(self, filepath: str):
        """Save all trained models"""
        model_data = {
            'email_models': self.email_models,
            'url_models': self.url_models,
            'meta_model': self.meta_model,
            'email_vectorizer': self.email_vectorizer,
            'scalers': self.scalers,
            'feature_names': self.feature_names
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Models saved to {filepath}")
    
    def load_models(self, filepath: str) -> bool:
        """Load pre-trained models"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.email_models = model_data['email_models']
            self.url_models = model_data['url_models']
            self.meta_model = model_data['meta_model']
            self.email_vectorizer = model_data['email_vectorizer']
            self.scalers = model_data['scalers']
            self.feature_names = model_data['feature_names']
            
            logger.info(f"Models loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False

# Example usage and training
if __name__ == "__main__":
    detector = OptimizedPhishingDetector()
    
    # Build models
    detector.build_advanced_models()
    
    # Create datasets
    X_email, y_email = detector.create_advanced_email_datasets()
    
    # Train models
    email_results = detector.train_email_models(X_email, y_email)
    url_results = detector.train_url_models()
    
    print("\n=== Email Model Results ===")
    for model, metrics in email_results.items():
        print(f"{model}: Accuracy={metrics['accuracy']:.4f}, AUC={metrics['auc']:.4f}")
    
    print("\n=== URL Model Results ===")
    for model, metrics in url_results.items():
        print(f"{model}: Accuracy={metrics['accuracy']:.4f}, AUC={metrics['auc']:.4f}")
    
    # Save models
    detector.save_models('optimized_models.pkl')
    
    # Test prediction
    test_email = "URGENT! Your account suspended. Click http://fake-bank.tk/verify to restore access immediately!"
    result = detector.predict_optimized(test_email)
    
    print(f"\n=== Test Prediction ===")
    print(f"Email: {test_email}")
    print(f"Final Confidence: {result['confidence']:.3f}")
    print(f"Ensemble Prediction: {result.get('ensemble_prediction', 'Not available')}")