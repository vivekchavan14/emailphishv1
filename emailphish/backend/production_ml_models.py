"""
Production-Ready ML Models for Phishing Detection

This module implements state-of-the-art machine learning models with proper
feature engineering, validation, and production optimizations.
"""

import pandas as pd
import numpy as np
import pickle
import logging
import re
import string
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import warnings
from urllib.parse import urlparse
import hashlib
from collections import Counter

# ML libraries
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)
import joblib

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductionFeatureExtractor:
    """
    Advanced feature extraction for email and URL content analysis.
    Designed to minimize false positives on legitimate marketing emails.
    """
    
    def __init__(self):
        # Legitimate brand indicators (to avoid false positives)
        self.legitimate_domains = {
            'nykaa.com', 'amazon.com', 'flipkart.com', 'myntra.com',
            'ajio.com', 'tatacliq.com', 'bigbasket.com', 'zomato.com',
            'swiggy.com', 'uber.com', 'ola.com', 'paytm.com',
            'phonepe.com', 'gpay.com', 'netflix.com', 'hotstar.com',
            'spotify.com', 'linkedin.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'youtube.com', 'google.com', 'microsoft.com',
            'apple.com', 'github.com', 'stackoverflow.com'
        }
        
        # Sophisticated threat indicators (high precision)
        self.threat_indicators = {
            'urgent_threats': [
                'account.*suspended', 'account.*locked', 'account.*restricted',
                'immediate.*action', 'urgent.*verification', 'expires.*hours',
                'final.*notice', 'last.*warning', 'act.*immediately'
            ],
            'financial_scams': [
                'won.*million', 'lottery.*winner', 'inheritance.*claim',
                'tax.*refund', 'unclaimed.*money', 'prize.*claim'
            ],
            'credential_harvesting': [
                'verify.*password.*immediately', 'confirm.*identity.*now',
                'update.*security.*urgent', 'login.*credentials.*expire'
            ]
        }
        
        # URL suspicious patterns
        self.suspicious_url_patterns = {
            'ip_addresses': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top', '.click'],
            'url_shorteners': ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd'],
            'phishing_keywords': ['verify', 'secure', 'update', 'confirm', 'validate', 'urgent']
        }
    
    def extract_email_features(self, email_text: str) -> np.ndarray:
        """
        Extract sophisticated email features with low false positive rate.
        """
        features = []
        email_lower = email_text.lower()
        
        # Basic text features
        features.extend(self._extract_text_features(email_text))
        
        # URL analysis features
        features.extend(self._extract_url_features(email_text))
        
        # Content analysis features
        features.extend(self._extract_content_features(email_lower))
        
        # Brand legitimacy features
        features.extend(self._extract_legitimacy_features(email_lower))
        
        # Advanced linguistic features
        features.extend(self._extract_linguistic_features(email_text))
        
        return np.array(features)
    
    def _extract_text_features(self, text: str) -> List[float]:
        """Extract basic text statistics"""
        features = []
        
        features.append(len(text))  # Text length
        features.append(len(text.split()))  # Word count
        features.append(len(text.split('\n')))  # Line count
        features.append(len(set(text.split())))  # Unique word count
        
        # Character ratio features
        if len(text) > 0:
            features.append(sum(1 for c in text if c.isupper()) / len(text))  # Capital ratio
            features.append(sum(1 for c in text if c.isdigit()) / len(text))  # Digit ratio
            features.append(sum(1 for c in text if c in string.punctuation) / len(text))  # Punctuation ratio
        else:
            features.extend([0.0, 0.0, 0.0])
        
        return features
    
    def _extract_url_features(self, text: str) -> List[float]:
        """Extract URL-related features"""
        features = []
        
        # Find URLs
        urls = re.findall(r'https?://[^\s<>"\[\]]+', text)
        features.append(len(urls))  # URL count
        
        # Analyze URL characteristics
        suspicious_url_count = 0
        legitimate_url_count = 0
        
        for url in urls:
            parsed = urlparse(url.lower())
            domain = parsed.netloc
            
            # Check if domain is legitimate
            if any(legit_domain in domain for legit_domain in self.legitimate_domains):
                legitimate_url_count += 1
            
            # Check for suspicious patterns
            if (re.match(self.suspicious_url_patterns['ip_addresses'], domain) or
                any(tld in domain for tld in self.suspicious_url_patterns['suspicious_tlds']) or
                any(shortener in domain for shortener in self.suspicious_url_patterns['url_shorteners'])):
                suspicious_url_count += 1
        
        features.append(suspicious_url_count)  # Suspicious URL count
        features.append(legitimate_url_count)  # Legitimate URL count
        
        # URL to text ratio
        url_char_count = sum(len(url) for url in urls)
        features.append(url_char_count / len(text) if len(text) > 0 else 0)
        
        return features
    
    def _extract_content_features(self, text_lower: str) -> List[float]:
        """Extract content-based features with high precision"""
        features = []
        
        # Threat indicators (high precision patterns)
        for category, patterns in self.threat_indicators.items():
            threat_count = sum(1 for pattern in patterns 
                             if re.search(pattern, text_lower, re.IGNORECASE))
            features.append(threat_count)
        
        # Money-related terms (refined to reduce false positives)
        money_patterns = [
            r'\$[\d,]+(?:\.\d{2})?\s*(?:million|thousand|prize|reward)',
            r'\b(?:inheritance|lottery|jackpot|sweepstakes)\b.*\$',
            r'(?:claim|won|winner).*\$[\d,]+',
            r'tax.*refund.*\$[\d,]+'
        ]
        money_count = sum(1 for pattern in money_patterns 
                         if re.search(pattern, text_lower, re.IGNORECASE))
        features.append(money_count)
        
        # Suspicious character patterns
        features.append(text_lower.count('!'))  # Exclamation marks
        features.append(text_lower.count('?'))  # Question marks
        features.append(len(re.findall(r'[A-Z]{3,}', text_lower)))  # All caps words
        
        return features
    
    def _extract_legitimacy_features(self, text_lower: str) -> List[float]:
        """Extract legitimacy indicators to reduce false positives"""
        features = []
        
        # Legitimate business indicators
        business_terms = [
            'order', 'purchase', 'invoice', 'receipt', 'subscription',
            'newsletter', 'unsubscribe', 'customer', 'support'
        ]
        business_count = sum(1 for term in business_terms if term in text_lower)
        features.append(business_count)
        
        # Professional language indicators
        professional_terms = [
            'thank you', 'please', 'regarding', 'sincerely', 'best regards',
            'team', 'company', 'organization', 'service'
        ]
        professional_count = sum(1 for term in professional_terms if term in text_lower)
        features.append(professional_count)
        
        # Known legitimate brand mentions
        brand_count = sum(1 for domain in self.legitimate_domains 
                         if domain.split('.')[0] in text_lower)
        features.append(brand_count)
        
        return features
    
    def _extract_linguistic_features(self, text: str) -> List[float]:
        """Extract advanced linguistic features"""
        features = []
        words = text.lower().split()
        
        if len(words) > 0:
            # Average word length
            avg_word_length = sum(len(word.strip(string.punctuation)) for word in words) / len(words)
            features.append(avg_word_length)
            
            # Vocabulary diversity (unique words / total words)
            unique_words = len(set(words))
            vocabulary_diversity = unique_words / len(words)
            features.append(vocabulary_diversity)
            
            # Readability approximation (sentences vs words)
            sentence_count = len(re.findall(r'[.!?]+', text))
            avg_sentence_length = len(words) / max(sentence_count, 1)
            features.append(avg_sentence_length)
        else:
            features.extend([0.0, 0.0, 0.0])
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Get feature names for interpretability"""
        return [
            # Text features
            'text_length', 'word_count', 'line_count', 'unique_word_count',
            'capital_ratio', 'digit_ratio', 'punctuation_ratio',
            
            # URL features
            'url_count', 'suspicious_url_count', 'legitimate_url_count', 'url_to_text_ratio',
            
            # Content features
            'urgent_threats', 'financial_scams', 'credential_harvesting',
            'money_patterns', 'exclamation_count', 'question_count', 'caps_words',
            
            # Legitimacy features
            'business_terms', 'professional_terms', 'brand_mentions',
            
            # Linguistic features
            'avg_word_length', 'vocabulary_diversity', 'avg_sentence_length'
        ]

class ProductionMLModels:
    """
    Production-ready ML models with proper validation and error handling.
    Optimized for high precision to minimize false positives.
    """
    
    def __init__(self, model_dir: str = "trained_models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        
        self.feature_extractor = ProductionFeatureExtractor()
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.model_metadata = {}
    
    def build_email_models(self) -> Dict[str, Any]:
        """Build optimized email classification models"""
        
        models = {
            'random_forest': {
                'model': RandomForestClassifier(
                    n_estimators=200,
                    max_depth=12,
                    min_samples_split=8,
                    min_samples_leaf=4,
                    class_weight='balanced',  # Handle class imbalance
                    random_state=42,
                    n_jobs=-1
                ),
                'description': 'Random Forest with balanced weights'
            },
            
            'gradient_boosting': {
                'model': GradientBoostingClassifier(
                    n_estimators=150,
                    max_depth=8,
                    learning_rate=0.1,
                    subsample=0.85,
                    random_state=42
                ),
                'description': 'Gradient Boosting with regularization'
            },
            
            'logistic_regression': {
                'model': LogisticRegression(
                    C=10,
                    class_weight='balanced',
                    max_iter=2000,
                    random_state=42
                ),
                'description': 'Logistic Regression with balanced weights'
            },
            
            'svm': {
                'model': SVC(
                    C=1.0,
                    kernel='rbf',
                    gamma='scale',
                    class_weight='balanced',
                    probability=True,
                    random_state=42
                ),
                'description': 'Support Vector Machine with RBF kernel'
            }
        }
        
        return models
    
    def build_url_models(self) -> Dict[str, Any]:
        """Build URL classification models"""
        
        models = {
            'random_forest': {
                'model': RandomForestClassifier(
                    n_estimators=150,
                    max_depth=10,
                    min_samples_split=5,
                    class_weight='balanced',
                    random_state=42,
                    n_jobs=-1
                ),
                'description': 'Random Forest for URL classification'
            },
            
            'gradient_boosting': {
                'model': GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.15,
                    random_state=42
                ),
                'description': 'Gradient Boosting for URL classification'
            }
        }
        
        return models
    
    def train_email_model(self, X_train: pd.DataFrame, y_train: np.ndarray, 
                         X_test: pd.DataFrame, y_test: np.ndarray) -> Dict[str, Any]:
        """Train email classification models with proper validation"""
        
        logger.info("Training email classification models...")
        
        # Text preprocessing
        self.vectorizers['email'] = TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 3),  # Unigrams to trigrams
            min_df=3,
            max_df=0.9,
            stop_words='english',
            lowercase=True,
            strip_accents='unicode'
        )
        
        # Extract text features
        X_train_tfidf = self.vectorizers['email'].fit_transform(X_train['email'])
        X_test_tfidf = self.vectorizers['email'].transform(X_test['email'])
        
        # Extract custom features
        train_custom_features = np.array([
            self.feature_extractor.extract_email_features(email) 
            for email in X_train['email']
        ])
        
        test_custom_features = np.array([
            self.feature_extractor.extract_email_features(email) 
            for email in X_test['email']
        ])
        
        # Scale custom features
        self.scalers['email'] = StandardScaler()
        train_custom_features = self.scalers['email'].fit_transform(train_custom_features)
        test_custom_features = self.scalers['email'].transform(test_custom_features)
        
        # Combine features
        from scipy.sparse import hstack, csr_matrix
        X_train_combined = hstack([X_train_tfidf, csr_matrix(train_custom_features)])
        X_test_combined = hstack([X_test_tfidf, csr_matrix(test_custom_features)])
        
        # Build and train models
        email_models = self.build_email_models()
        results = {}
        
        for name, model_config in email_models.items():
            logger.info(f"Training email model: {name}")
            
            model = model_config['model']
            
            # Train model
            model.fit(X_train_combined, y_train)
            
            # Evaluate model
            y_pred = model.predict(X_test_combined)
            y_pred_proba = model.predict_proba(X_test_combined)[:, 1]
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred),
                'roc_auc': roc_auc_score(y_test, y_pred_proba)
            }
            
            # Cross-validation
            cv_scores = cross_val_score(
                model, X_train_combined, y_train, 
                cv=5, scoring='f1', n_jobs=-1
            )
            
            metrics['cv_f1_mean'] = cv_scores.mean()
            metrics['cv_f1_std'] = cv_scores.std()
            
            # Store model and results
            self.models[f'email_{name}'] = model
            results[name] = metrics
            
            logger.info(f"{name}: F1={metrics['f1_score']:.3f}, "
                       f"Precision={metrics['precision']:.3f}, "
                       f"Recall={metrics['recall']:.3f}")
        
        return results
    
    def train_url_model(self, X_train: np.ndarray, y_train: np.ndarray,
                       X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Train URL classification models"""
        
        logger.info("Training URL classification models...")
        
        # Scale features
        self.scalers['url'] = MinMaxScaler()
        X_train_scaled = self.scalers['url'].fit_transform(X_train)
        X_test_scaled = self.scalers['url'].transform(X_test)
        
        # Build and train models
        url_models = self.build_url_models()
        results = {}
        
        for name, model_config in url_models.items():
            logger.info(f"Training URL model: {name}")
            
            model = model_config['model']
            
            # Train model
            model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = model.predict(X_test_scaled)
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred),
                'roc_auc': roc_auc_score(y_test, y_pred_proba)
            }
            
            # Cross-validation
            cv_scores = cross_val_score(
                model, X_train_scaled, y_train,
                cv=5, scoring='f1', n_jobs=-1
            )
            
            metrics['cv_f1_mean'] = cv_scores.mean()
            metrics['cv_f1_std'] = cv_scores.std()
            
            # Store model and results
            self.models[f'url_{name}'] = model
            results[name] = metrics
            
            logger.info(f"{name}: F1={metrics['f1_score']:.3f}, "
                       f"Precision={metrics['precision']:.3f}, "
                       f"Recall={metrics['recall']:.3f}")
        
        return results
    
    def create_ensemble_model(self, email_results: Dict, url_results: Dict) -> str:
        """Create ensemble model based on best performing models"""
        
        # Select best email model based on F1 score
        best_email_model = max(email_results.items(), key=lambda x: x[1]['f1_score'])
        
        # Select best URL model based on F1 score
        best_url_model = max(url_results.items(), key=lambda x: x[1]['f1_score'])
        
        ensemble_config = {
            'email_model': best_email_model[0],
            'url_model': best_url_model[0],
            'email_performance': best_email_model[1],
            'url_performance': best_url_model[1],
            'weights': {
                'email': 0.7,  # Higher weight for email model
                'url': 0.3
            }
        }
        
        self.model_metadata['ensemble'] = ensemble_config
        
        logger.info(f"Ensemble model created: Email={best_email_model[0]} (F1={best_email_model[1]['f1_score']:.3f}), "
                   f"URL={best_url_model[0]} (F1={best_url_model[1]['f1_score']:.3f})")
        
        return f"email_{best_email_model[0]}"  # Return primary model name
    
    def predict_email(self, email_text: str) -> Dict[str, Any]:
        """Predict email with ensemble approach and detailed reasoning"""
        
        if 'ensemble' not in self.model_metadata:
            return {'error': 'Ensemble model not trained'}
        
        try:
            # Get ensemble configuration
            ensemble = self.model_metadata['ensemble']
            email_model_name = f"email_{ensemble['email_model']}"
            
            # Extract features
            email_tfidf = self.vectorizers['email'].transform([email_text])
            custom_features = self.feature_extractor.extract_email_features(email_text).reshape(1, -1)
            custom_features = self.scalers['email'].transform(custom_features)
            
            # Combine features
            from scipy.sparse import hstack, csr_matrix
            combined_features = hstack([email_tfidf, csr_matrix(custom_features)])
            
            # Get prediction from email model
            email_model = self.models[email_model_name]
            prediction = email_model.predict(combined_features)[0]
            prediction_proba = email_model.predict_proba(combined_features)[0]
            
            # Generate detailed reasoning
            feature_values = custom_features[0]
            feature_names = self.feature_extractor.get_feature_names()
            
            reasons = self._generate_reasoning(email_text, feature_values, feature_names, prediction)
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'safe',
                'confidence': float(prediction_proba[1]),
                'safe_confidence': float(prediction_proba[0]),
                'model_used': email_model_name,
                'reasons': reasons,
                'feature_analysis': dict(zip(feature_names, feature_values.tolist()))
            }
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {'error': str(e)}
    
    def _generate_reasoning(self, email_text: str, feature_values: np.ndarray, 
                          feature_names: List[str], prediction: int) -> List[str]:
        """Generate human-readable reasoning for the prediction"""
        
        reasons = []
        email_lower = email_text.lower()
        
        # Create feature dict
        features = dict(zip(feature_names, feature_values))
        
        # URL-based reasons
        if features['url_count'] > 0:
            if features['suspicious_url_count'] > 0:
                reasons.append(f"Contains {int(features['suspicious_url_count'])} suspicious URLs")
            if features['legitimate_url_count'] > 0:
                reasons.append(f"Contains {int(features['legitimate_url_count'])} legitimate URLs")
        
        # Threat indicators
        if features['urgent_threats'] > 0:
            reasons.append(f"Uses {int(features['urgent_threats'])} urgent threat language patterns")
        
        if features['financial_scams'] > 0:
            reasons.append(f"Contains {int(features['financial_scams'])} financial scam indicators")
        
        if features['credential_harvesting'] > 0:
            reasons.append(f"Shows {int(features['credential_harvesting'])} credential harvesting attempts")
        
        # Legitimacy indicators
        if features['business_terms'] > 2:
            reasons.append(f"Contains {int(features['business_terms'])} legitimate business terms")
        
        if features['professional_terms'] > 2:
            reasons.append(f"Uses {int(features['professional_terms'])} professional language patterns")
        
        if features['brand_mentions'] > 0:
            reasons.append(f"Mentions {int(features['brand_mentions'])} known legitimate brands")
        
        # Character analysis
        if features['capital_ratio'] > 0.3:
            reasons.append("Excessive use of capital letters (suspicious)")
        
        if features['exclamation_count'] > 5:
            reasons.append("Excessive use of exclamation marks")
        
        # Default reasoning
        if not reasons:
            if prediction == 1:
                reasons.append("Classified as phishing by ML model based on text patterns")
            else:
                reasons.append("No suspicious patterns detected - appears legitimate")
        
        return reasons[:5]  # Return top 5 reasons
    
    def save_models(self):
        """Save all trained models and components"""
        
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        
        # Save models
        for name, model in self.models.items():
            model_path = self.model_dir / f"{name}_{timestamp}.pkl"
            joblib.dump(model, model_path)
        
        # Save vectorizers
        for name, vectorizer in self.vectorizers.items():
            vec_path = self.model_dir / f"vectorizer_{name}_{timestamp}.pkl"
            joblib.dump(vectorizer, vec_path)
        
        # Save scalers
        for name, scaler in self.scalers.items():
            scaler_path = self.model_dir / f"scaler_{name}_{timestamp}.pkl"
            joblib.dump(scaler, scaler_path)
        
        # Save metadata
        metadata_path = self.model_dir / f"model_metadata_{timestamp}.json"
        with open(metadata_path, 'w') as f:
            import json
            json.dump(self.model_metadata, f, indent=2, default=str)
        
        logger.info(f"Models saved with timestamp {timestamp}")
        return timestamp
    
    def load_models(self, timestamp: str) -> bool:
        """Load previously saved models"""
        
        try:
            # Load models
            for model_file in self.model_dir.glob(f"*_{timestamp}.pkl"):
                if "vectorizer" not in model_file.name and "scaler" not in model_file.name:
                    model_name = model_file.name.replace(f"_{timestamp}.pkl", "")
                    self.models[model_name] = joblib.load(model_file)
            
            # Load vectorizers
            for vec_file in self.model_dir.glob(f"vectorizer_*_{timestamp}.pkl"):
                vec_name = vec_file.name.replace(f"vectorizer_", "").replace(f"_{timestamp}.pkl", "")
                self.vectorizers[vec_name] = joblib.load(vec_file)
            
            # Load scalers
            for scaler_file in self.model_dir.glob(f"scaler_*_{timestamp}.pkl"):
                scaler_name = scaler_file.name.replace(f"scaler_", "").replace(f"_{timestamp}.pkl", "")
                self.scalers[scaler_name] = joblib.load(scaler_file)
            
            # Load metadata
            metadata_file = self.model_dir / f"model_metadata_{timestamp}.json"
            if metadata_file.exists():
                import json
                with open(metadata_file, 'r') as f:
                    self.model_metadata = json.load(f)
            
            logger.info(f"Models loaded with timestamp {timestamp}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False

# Example usage
if __name__ == "__main__":
    from dataset_manager import ProductionDatasetManager
    
    # Initialize components
    data_manager = ProductionDatasetManager()
    ml_models = ProductionMLModels()
    
    # Prepare datasets
    datasets = data_manager.prepare_production_datasets()
    splits = data_manager.get_train_test_split(datasets)
    
    # Train email models
    email_results = ml_models.train_email_model(
        splits['email']['X_train'], splits['email']['y_train'],
        splits['email']['X_test'], splits['email']['y_test']
    )
    
    # Train URL models
    url_results = ml_models.train_url_model(
        splits['url']['X_train'], splits['url']['y_train'],
        splits['url']['X_test'], splits['url']['y_test']
    )
    
    # Create ensemble
    best_model = ml_models.create_ensemble_model(email_results, url_results)
    
    # Save models
    timestamp = ml_models.save_models()
    
    # Test prediction
    test_email = "Thank you for shopping with Nykaa! Your order has been confirmed."
    result = ml_models.predict_email(test_email)
    
    print(f"\nTest prediction:")
    print(f"Email: {test_email}")
    print(f"Prediction: {result.get('prediction', 'error')}")
    print(f"Confidence: {result.get('confidence', 0):.3f}")
    print(f"Reasons: {result.get('reasons', [])}")