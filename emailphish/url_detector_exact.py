import pandas as pd
import numpy as np
import pickle
import os
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from typing import Tuple, List
import warnings
warnings.filterwarnings('ignore')

# Import the exact feature extraction class from the repository
import sys
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExactURLPhishingDetector:
    """
    URL Phishing Detector using the exact algorithms and dataset from:
    https://github.com/vaibhavbichave/Phishing-URL-Detection
    """
    
    def __init__(self, model_path='exact_url_phishing_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.feature_names = [
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
            'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]

    def copy_dataset_from_repository(self):
        """Copy the exact dataset from the cloned repository"""
        repo_dataset_path = '/home/vivek/vadapav/email-phish-project/Phishing-URL-Detection/phishing.csv'
        local_dataset_path = 'data/phishing_exact.csv'
        
        os.makedirs('data', exist_ok=True)
        
        if os.path.exists(repo_dataset_path):
            shutil.copy2(repo_dataset_path, local_dataset_path)
            logger.info(f"Exact dataset copied from repository to {local_dataset_path}")
            return local_dataset_path
        else:
            logger.error(f"Repository dataset not found at {repo_dataset_path}")
            return None

    def copy_feature_extraction_from_repository(self):
        """Copy the exact feature extraction module from the repository"""
        repo_feature_path = '/home/vivek/vadapav/email-phish-project/Phishing-URL-Detection/feature.py'
        local_feature_path = 'feature_exact.py'
        
        if os.path.exists(repo_feature_path):
            shutil.copy2(repo_feature_path, local_feature_path)
            logger.info(f"Exact feature extraction module copied to {local_feature_path}")
            return local_feature_path
        else:
            logger.error(f"Repository feature module not found at {repo_feature_path}")
            return None

    def load_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load the exact dataset from the repository"""
        dataset_path = self.copy_dataset_from_repository()
        
        if dataset_path and os.path.exists(dataset_path):
            df = pd.read_csv(dataset_path)
            logger.info(f"Exact dataset loaded: {len(df)} samples, {len(df.columns)-2} features")
            
            # The dataset has features from column 1 to 30, and 'class' as the target (column 31)
            X = df.iloc[:, 1:31].values  # Features: columns 1-30
            y = df.iloc[:, 31].values    # Target: column 31 ('class')
            
            # Count distribution
            phishing_count = np.sum(y == -1)  # -1 is phishing
            legitimate_count = np.sum(y == 1)  # 1 is legitimate
            
            logger.info(f"Phishing: {phishing_count}, Legitimate: {legitimate_count}")
            
            return X, y
        else:
            raise FileNotFoundError("Could not load the exact dataset from repository")

    def train_model(self, X: np.ndarray, y: np.ndarray) -> Tuple[float, float]:
        """Train the model using Random Forest (as used in the original repository)"""
        logger.info("Training URL phishing detection model using exact dataset...")
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Use Random Forest as in the original repository
        # Based on the performance metrics shown, Random Forest was one of the top performers
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        cv_mean = cv_scores.mean()
        cv_std = cv_scores.std()
        
        logger.info("Model trained successfully!")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Cross-validation: {cv_mean:.4f} (+/- {cv_std * 2:.4f})")
        
        # Print classification report
        logger.info("Classification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        return accuracy, cv_mean

    def save_model(self):
        """Save the trained model"""
        if self.model:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logger.info(f"Model saved to {self.model_path}")
        else:
            logger.warning("No model to save")

    def load_model(self) -> bool:
        """Load a pre-trained model"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"Model loaded from {self.model_path}")
                return True
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
                return False
        else:
            logger.warning(f"Model file not found: {self.model_path}")
            return False

    def extract_features_simple(self, url: str) -> np.ndarray:
        """
        Simplified feature extraction when the full feature extraction fails
        This implements basic versions of the most important features from the repository
        """
        import re
        import ipaddress
        from urllib.parse import urlparse
        
        features = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else ''
            
            # 1. UsingIP - Check if URL uses IP address instead of domain
            try:
                ipaddress.ip_address(domain)
                features.append(-1)  # Using IP is suspicious
            except:
                features.append(1)   # Using domain is normal
            
            # 2. LongURL - Check URL length
            if len(url) < 54:
                features.append(1)
            elif len(url) <= 75:
                features.append(0)
            else:
                features.append(-1)
            
            # 3. ShortURL - Check for URL shorteners
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd', 'wp.me']
            if any(shortener in url.lower() for shortener in shorteners):
                features.append(-1)
            else:
                features.append(1)
            
            # 4. Symbol@ - Check for @ symbol
            features.append(-1 if '@' in url else 1)
            
            # 5. Redirecting// - Check for // after protocol
            features.append(-1 if url.rfind('//') > 6 else 1)
            
            # 6. PrefixSuffix- - Check for - in domain
            features.append(-1 if '-' in domain else 1)
            
            # 7. SubDomains - Count dots to estimate subdomains
            dot_count = url.count('.')
            if dot_count == 1:
                features.append(1)
            elif dot_count == 2:
                features.append(0)
            else:
                features.append(-1)
            
            # 8. HTTPS - Check for HTTPS
            features.append(1 if url.startswith('https') else -1)
            
            # 9-30: For remaining features, use defaults based on common patterns
            # These would normally require domain analysis, web scraping, etc.
            remaining_features = [
                -1,  # DomainRegLen (assume suspicious)
                1,   # Favicon (assume normal)
                1,   # NonStdPort (assume normal)
                -1 if 'https' in domain else 1,  # HTTPSDomainURL
                0,   # RequestURL (neutral)
                0,   # AnchorURL (neutral)
                0,   # LinksInScriptTags (neutral)
                1,   # ServerFormHandler (assume normal)
                1,   # InfoEmail (assume normal)
                -1,  # AbnormalURL (assume suspicious)
                1,   # WebsiteForwarding (assume normal)
                -1,  # StatusBarCust (assume suspicious)
                -1,  # DisableRightClick (assume suspicious)
                -1,  # UsingPopupWindow (assume suspicious)
                -1,  # IframeRedirection (assume suspicious)
                -1,  # AgeofDomain (assume suspicious)
                -1,  # DNSRecording (assume suspicious)
                -1,  # WebsiteTraffic (assume suspicious)
                -1,  # PageRank (assume suspicious)
                1,   # GoogleIndex (assume normal)
                0,   # LinksPointingToPage (neutral)
                1    # StatsReport (assume normal)
            ]
            
            features.extend(remaining_features)
            
        except Exception as e:
            logger.warning(f"Feature extraction failed for {url}: {e}")
            # Return all neutral features if extraction fails
            features = [0] * 30
        
        return np.array(features).reshape(1, -1)

    def predict_url(self, url: str) -> Tuple[bool, float, List[str]]:
        """Predict if a URL is malicious using the exact trained model"""
        if not self.model:
            logger.error("Model not loaded. Please train or load a model first.")
            return False, 0.0, ["Model not available"]
        
        try:
            # Try to use the exact feature extraction from the repository
            feature_module_path = self.copy_feature_extraction_from_repository()
            
            if feature_module_path and os.path.exists(feature_module_path):
                try:
                    # Import the exact FeatureExtraction class
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("feature_exact", feature_module_path)
                    feature_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(feature_module)
                    
                    # Extract features using the exact algorithm
                    obj = feature_module.FeatureExtraction(url)
                    features = np.array(obj.getFeaturesList()).reshape(1, 30)
                    
                    logger.info("Using exact feature extraction from repository")
                    
                except Exception as e:
                    logger.warning(f"Exact feature extraction failed: {e}, using simplified version")
                    features = self.extract_features_simple(url)
            else:
                logger.warning("Using simplified feature extraction")
                features = self.extract_features_simple(url)
            
            # Predict using the model
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # In the dataset: -1 = phishing, 1 = legitimate
            is_malicious = (prediction == -1)
            confidence = probabilities[0] if is_malicious else probabilities[1]  # Probability of predicted class
            
            # Generate reasons based on feature values
            reasons = self.generate_reasons(features[0], url)
            
            return is_malicious, confidence, reasons
            
        except Exception as e:
            logger.error(f"Prediction failed for {url}: {e}")
            return False, 0.0, [f"Prediction failed: {str(e)}"]

    def generate_reasons(self, features: np.ndarray, url: str) -> List[str]:
        """Generate human-readable reasons based on feature values"""
        reasons = []
        
        feature_explanations = [
            ("Uses IP address instead of domain", features[0] == -1),
            ("URL is suspiciously long", features[1] == -1),
            ("Uses URL shortening service", features[2] == -1),
            ("Contains @ symbol in URL", features[3] == -1),
            ("Contains suspicious redirects", features[4] == -1),
            ("Domain contains hyphens", features[5] == -1),
            ("Has too many subdomains", features[6] == -1),
            ("Does not use HTTPS", features[7] == -1),
            ("Domain registration length suspicious", features[8] == -1),
            ("Favicon issues detected", features[9] == -1),
        ]
        
        for explanation, condition in feature_explanations:
            if condition:
                reasons.append(explanation)
        
        if not reasons:
            reasons.append("URL appears to have legitimate characteristics")
        
        return reasons[:3]  # Return top 3 reasons

    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """Get feature importance from the trained model"""
        if not self.model or not hasattr(self.model, 'feature_importances_'):
            return []
        
        importance_pairs = list(zip(self.feature_names, self.model.feature_importances_))
        importance_pairs.sort(key=lambda x: x[1], reverse=True)
        
        return importance_pairs

# Example usage and testing
if __name__ == "__main__":
    detector = ExactURLPhishingDetector()
    
    try:
        # Load dataset and train model
        X, y = detector.load_dataset()
        accuracy, cv_score = detector.train_model(X, y)
        detector.save_model()
        
        # Test some URLs
        test_urls = [
            "https://www.google.com",
            "http://bit.ly/suspicious",
            "https://secure-banking-update.com",
            "https://github.com",
            "http://192.168.1.1/phishing"
        ]
        
        print("\n=== Testing URL Detection ===")
        for url in test_urls:
            is_malicious, confidence, reasons = detector.predict_url(url)
            print(f"\nURL: {url}")
            print(f"Malicious: {is_malicious}")
            print(f"Confidence: {confidence:.3f}")
            print(f"Reasons: {', '.join(reasons)}")
        
        # Show feature importance
        print("\n=== Top 10 Most Important Features ===")
        importance = detector.get_feature_importance()
        for i, (feature, score) in enumerate(importance[:10], 1):
            print(f"{i}. {feature}: {score:.4f}")
            
    except Exception as e:
        print(f"Error: {e}")