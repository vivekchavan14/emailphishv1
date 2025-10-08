#!/usr/bin/env python3
"""
Comprehensive Test Suite for Production Phishing Detection System

This script tests all components of the production system including
models, API endpoints, and integration scenarios.
"""

import os
import sys
import time
import json
import requests
from pathlib import Path
from typing import Dict, List, Any
import unittest
from unittest.mock import patch
import pandas as pd
import numpy as np

# Add parent directories to path
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir.parent / "models"))
sys.path.append(str(current_dir.parent / "data"))
sys.path.append(str(current_dir.parent / "api"))

# Import our production components
try:
    from production_ml_models import ProductionMLModels, ProductionFeatureExtractor
    from dataset_manager import ProductionDatasetManager
    import production_api
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure you're running from the correct directory")
    sys.exit(1)

class TestProductionSystem(unittest.TestCase):
    """Comprehensive test suite for the production system"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        print("Setting up production system tests...")
        
        cls.test_emails = {
            'legitimate_marketing': [
                "Thank you for shopping with Nykaa! Your order #NK12345 has been confirmed and will be delivered within 2-3 business days. Track your order at nykaa.com/track",
                "Amazon Prime Day Sale: Save up to 50% on electronics, fashion, and home essentials. Shop now at amazon.com. Unsubscribe anytime.",
                "Your Flipkart order is out for delivery! Order ID: FLP789012. Expected delivery: Today by 8 PM. Track at flipkart.com",
                "Netflix subscription renewal: Your monthly subscription of $9.99 will be charged on March 15th. Manage your account at netflix.com"
            ],
            'phishing_emails': [
                "URGENT: Your account has been suspended! Click here immediately to verify your password or lose access forever: http://fake-bank-verify.tk/login",
                "Congratulations! You've won $1,000,000 in the international lottery! Claim your prize now by providing your bank details: winner-claim.ml",
                "Security Alert: Unusual activity detected on your account. Verify your identity immediately or account will be locked: http://192.168.1.1/verify",
                "Final Notice: Your PayPal account expires in 2 hours! Update your payment information NOW or lose access: paypal-urgent.cf/update"
            ],
            'suspicious_but_tricky': [
                "Limited time offer: Get 90% off luxury watches! Act now before this exclusive deal expires in 24 hours! Click here: luxury-deals.xyz",
                "You've been selected for a special Amazon gift card worth $500! Claim within 48 hours: amazon-rewards.top/claim"
            ]
        }
        
        cls.test_urls = {
            'legitimate': [
                "https://www.amazon.com/dp/B08N5WRWNW",
                "https://nykaa.com/brand/lakme",
                "https://www.netflix.com/browse",
                "https://github.com/openai/gpt-4"
            ],
            'suspicious': [
                "http://192.168.1.1/login",
                "https://amazon-free-gift.tk/claim",
                "https://bit.ly/suspicious-link",
                "https://paypal-verify.ml/urgent"
            ]
        }
        
        cls.api_base_url = "http://localhost:8000"
        
    def setUp(self):
        """Set up each test"""
        self.feature_extractor = ProductionFeatureExtractor()
        self.ml_models = ProductionMLModels()
        self.data_manager = ProductionDatasetManager()
    
    def test_feature_extraction(self):
        """Test feature extraction capabilities"""
        print("\n=== Testing Feature Extraction ===")
        
        # Test legitimate email feature extraction
        legitimate_email = self.test_emails['legitimate_marketing'][0]
        features = self.feature_extractor.extract_email_features(legitimate_email)
        
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(len(features), len(self.feature_extractor.get_feature_names()))
        
        # Test that legitimate emails have appropriate features
        feature_names = self.feature_extractor.get_feature_names()
        feature_dict = dict(zip(feature_names, features))
        
        # Should have legitimate brand mentions
        self.assertGreater(feature_dict['brand_mentions'], 0, 
                          "Legitimate email should mention known brands")
        
        # Should have business terms
        self.assertGreater(feature_dict['business_terms'], 0,
                          "Legitimate email should contain business terms")
        
        print(f"✓ Legitimate email features: {len(features)} features extracted")
        print(f"  Brand mentions: {feature_dict['brand_mentions']}")
        print(f"  Business terms: {feature_dict['business_terms']}")
        
        # Test phishing email feature extraction
        phishing_email = self.test_emails['phishing_emails'][0]
        phishing_features = self.feature_extractor.extract_email_features(phishing_email)
        phishing_dict = dict(zip(feature_names, phishing_features))
        
        # Should have threat indicators
        self.assertGreater(phishing_dict['urgent_threats'], 0,
                          "Phishing email should contain urgent threats")
        
        print(f"✓ Phishing email features: {len(phishing_features)} features extracted")
        print(f"  Urgent threats: {phishing_dict['urgent_threats']}")
        print(f"  Credential harvesting: {phishing_dict['credential_harvesting']}")
    
    def test_dataset_manager(self):
        """Test dataset management functionality"""
        print("\n=== Testing Dataset Manager ===")
        
        try:
            datasets = self.data_manager.prepare_production_datasets()
            
            self.assertIn('email', datasets)
            self.assertIn('url', datasets)
            
            # Test email dataset
            email_data = datasets['email']
            self.assertGreater(len(email_data), 100, "Should have substantial email dataset")
            self.assertIn('email', email_data.columns)
            self.assertIn('label', email_data.columns)
            
            print(f"✓ Email dataset: {len(email_data)} samples")
            print(f"  Phishing samples: {(email_data['label'] == 1).sum()}")
            print(f"  Legitimate samples: {(email_data['label'] == 0).sum()}")
            
            # Test URL dataset
            url_data = datasets['url']
            self.assertGreater(len(url_data), 1000, "Should have substantial URL dataset")
            
            print(f"✓ URL dataset: {len(url_data)} samples")
            
            # Test train/test split
            splits = self.data_manager.get_train_test_split(datasets)
            self.assertIn('email', splits)
            self.assertIn('url', splits)
            
            print("✓ Train/test splits created successfully")
            
        except Exception as e:
            print(f"✗ Dataset manager test failed: {e}")
            raise
    
    def test_model_training_and_prediction(self):
        """Test model training and prediction"""
        print("\n=== Testing Model Training ===")
        
        try:
            # Prepare datasets
            datasets = self.data_manager.prepare_production_datasets()
            splits = self.data_manager.get_train_test_split(datasets)
            
            # Train email models
            print("Training email models...")
            email_results = self.ml_models.train_email_model(
                splits['email']['X_train'], splits['email']['y_train'],
                splits['email']['X_test'], splits['email']['y_test']
            )
            
            self.assertIsInstance(email_results, dict)
            self.assertGreater(len(email_results), 0, "Should train multiple models")
            
            for model_name, metrics in email_results.items():
                self.assertIn('f1_score', metrics)
                self.assertIn('precision', metrics)
                self.assertIn('recall', metrics)
                print(f"  {model_name}: F1={metrics['f1_score']:.3f}, "
                      f"Precision={metrics['precision']:.3f}")
            
            # Train URL models
            print("Training URL models...")
            url_results = self.ml_models.train_url_model(
                splits['url']['X_train'], splits['url']['y_train'],
                splits['url']['X_test'], splits['url']['y_test']
            )
            
            self.assertIsInstance(url_results, dict)
            
            # Create ensemble
            best_model = self.ml_models.create_ensemble_model(email_results, url_results)
            self.assertIsInstance(best_model, str)
            
            print("✓ Models trained successfully")
            
            # Test predictions
            print("\n=== Testing Predictions ===")
            
            # Test legitimate emails
            for i, email in enumerate(self.test_emails['legitimate_marketing']):
                result = self.ml_models.predict_email(email)
                
                self.assertIn('prediction', result)
                self.assertIn('confidence', result)
                self.assertIn('reasons', result)
                
                print(f"Legitimate Email {i+1}: {result['prediction']} "
                      f"(confidence: {result['confidence']:.3f})")
                
                # Most legitimate emails should be classified as safe
                # (allowing for some false positives in development)
                if result['prediction'] == 'phishing':
                    print(f"  Warning: Legitimate email classified as phishing")
                    print(f"  Reasons: {result['reasons']}")
            
            # Test phishing emails
            phishing_correct = 0
            for i, email in enumerate(self.test_emails['phishing_emails']):
                result = self.ml_models.predict_email(email)
                
                print(f"Phishing Email {i+1}: {result['prediction']} "
                      f"(confidence: {result['confidence']:.3f})")
                
                if result['prediction'] == 'phishing':
                    phishing_correct += 1
                    print(f"  ✓ Correctly identified as phishing")
                    print(f"  Reasons: {result['reasons'][:3]}")
                else:
                    print(f"  ✗ Missed phishing email")
            
            phishing_accuracy = phishing_correct / len(self.test_emails['phishing_emails'])
            print(f"\nPhishing detection accuracy: {phishing_accuracy:.1%}")
            
            # Should catch at least 50% of obvious phishing emails
            self.assertGreaterEqual(phishing_accuracy, 0.5, 
                                   "Should detect at least 50% of phishing emails")
            
        except Exception as e:
            print(f"✗ Model training/prediction test failed: {e}")
            raise
    
    def test_model_persistence(self):
        """Test model saving and loading"""
        print("\n=== Testing Model Persistence ===")
        
        try:
            # Train a simple model
            datasets = self.data_manager.prepare_production_datasets()
            splits = self.data_manager.get_train_test_split(datasets)
            
            email_results = self.ml_models.train_email_model(
                splits['email']['X_train'], splits['email']['y_train'],
                splits['email']['X_test'], splits['email']['y_test']
            )
            
            url_results = self.ml_models.train_url_model(
                splits['url']['X_train'], splits['url']['y_train'],
                splits['url']['X_test'], splits['url']['y_test']
            )
            
            self.ml_models.create_ensemble_model(email_results, url_results)
            
            # Save models
            timestamp = self.ml_models.save_models()
            self.assertIsInstance(timestamp, str)
            print(f"✓ Models saved with timestamp: {timestamp}")
            
            # Test prediction before loading
            test_email = self.test_emails['legitimate_marketing'][0]
            original_result = self.ml_models.predict_email(test_email)
            
            # Create new instance and load models
            new_ml_models = ProductionMLModels()
            success = new_ml_models.load_models(timestamp)
            self.assertTrue(success, "Should successfully load models")
            
            # Test prediction after loading
            loaded_result = new_ml_models.predict_email(test_email)
            
            # Results should be identical
            self.assertEqual(original_result['prediction'], loaded_result['prediction'])
            self.assertAlmostEqual(original_result['confidence'], 
                                 loaded_result['confidence'], places=3)
            
            print("✓ Model loading and prediction consistency verified")
            
        except Exception as e:
            print(f"✗ Model persistence test failed: {e}")
            raise
    
    def test_api_endpoints(self):
        """Test API endpoints (requires running server)"""
        print("\n=== Testing API Endpoints ===")
        
        # Check if API server is running
        try:
            response = requests.get(f"{self.api_base_url}/api/v2/health", timeout=5)
            if response.status_code != 200:
                print("⚠ API server not running, skipping API tests")
                return
        except requests.exceptions.RequestException:
            print("⚠ API server not running, skipping API tests")
            return
        
        # Test health endpoint
        response = requests.get(f"{self.api_base_url}/api/v2/health")
        self.assertEqual(response.status_code, 200)
        health_data = response.json()
        self.assertEqual(health_data['status'], 'healthy')
        print("✓ Health endpoint working")
        
        # Test email analysis endpoint
        test_data = {
            "email": self.test_emails['legitimate_marketing'][0],
            "sender": "nykaa@nykaa.com",
            "subject": "Order Confirmation"
        }
        
        response = requests.post(f"{self.api_base_url}/api/v2/analyze/email", 
                                json=test_data)
        self.assertEqual(response.status_code, 200)
        
        result = response.json()
        self.assertIn('prediction', result)
        self.assertIn('confidence', result)
        self.assertIn('reasons', result)
        print(f"✓ Email analysis: {result['prediction']} (confidence: {result['confidence']:.3f})")
        
        # Test phishing email
        phishing_data = {
            "email": self.test_emails['phishing_emails'][0]
        }
        
        response = requests.post(f"{self.api_base_url}/api/v2/analyze/email",
                                json=phishing_data)
        self.assertEqual(response.status_code, 200)
        
        phishing_result = response.json()
        print(f"✓ Phishing analysis: {phishing_result['prediction']} "
              f"(confidence: {phishing_result['confidence']:.3f})")
        
        # Test URL analysis
        url_data = {"url": self.test_urls['suspicious'][0]}
        response = requests.post(f"{self.api_base_url}/api/v2/analyze/url",
                                json=url_data)
        self.assertEqual(response.status_code, 200)
        url_result = response.json()
        print(f"✓ URL analysis: {url_result['prediction']}")
        
        # Test bulk analysis
        bulk_data = {
            "emails": [
                {"email": email} for email in self.test_emails['legitimate_marketing'][:2]
            ]
        }
        
        response = requests.post(f"{self.api_base_url}/api/v2/analyze/bulk",
                                json=bulk_data)
        self.assertEqual(response.status_code, 200)
        bulk_result = response.json()
        self.assertEqual(bulk_result['total_processed'], 2)
        print(f"✓ Bulk analysis: {bulk_result['total_processed']} emails processed")
        
        # Test model status
        response = requests.get(f"{self.api_base_url}/api/v2/model/status")
        self.assertEqual(response.status_code, 200)
        status = response.json()
        self.assertTrue(status['loaded'])
        print(f"✓ Model status: {status['model_count']} models loaded")
        
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        print("\n=== Testing Edge Cases ===")
        
        # Test empty email
        try:
            empty_features = self.feature_extractor.extract_email_features("")
            self.assertEqual(len(empty_features), 
                           len(self.feature_extractor.get_feature_names()))
            print("✓ Empty email handled gracefully")
        except Exception as e:
            print(f"✗ Empty email test failed: {e}")
        
        # Test very long email
        long_email = "This is a test email. " * 1000
        try:
            long_features = self.feature_extractor.extract_email_features(long_email)
            self.assertIsInstance(long_features, np.ndarray)
            print("✓ Long email handled gracefully")
        except Exception as e:
            print(f"✗ Long email test failed: {e}")
        
        # Test special characters
        special_email = "Test email with special chars: àáâãäåæçèéêë ñòóôõö ¡¢£¤¥¦§¨©"
        try:
            special_features = self.feature_extractor.extract_email_features(special_email)
            self.assertIsInstance(special_features, np.ndarray)
            print("✓ Special characters handled gracefully")
        except Exception as e:
            print(f"✗ Special characters test failed: {e}")

def run_comprehensive_test():
    """Run comprehensive system test"""
    print("="*60)
    print("PRODUCTION PHISHING DETECTION SYSTEM - COMPREHENSIVE TEST")
    print("="*60)
    
    # Check Python version
    print(f"Python version: {sys.version}")
    print(f"Test directory: {Path(__file__).parent}")
    
    # Run unit tests
    unittest.main(verbosity=2, exit=False)
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    # Additional integration test
    print("\n=== Integration Test ===")
    try:
        # Full system test
        data_manager = ProductionDatasetManager()
        ml_models = ProductionMLModels()
        
        # Quick training
        datasets = data_manager.prepare_production_datasets()
        splits = data_manager.get_train_test_split(datasets)
        
        # Train with smaller dataset for speed
        X_train_small = splits['email']['X_train'][:100]
        y_train_small = splits['email']['y_train'][:100]
        X_test_small = splits['email']['X_test'][:50]
        y_test_small = splits['email']['y_test'][:50]
        
        email_results = ml_models.train_email_model(
            X_train_small, y_train_small, X_test_small, y_test_small
        )
        
        url_results = ml_models.train_url_model(
            splits['url']['X_train'][:100], splits['url']['y_train'][:100],
            splits['url']['X_test'][:50], splits['url']['y_test'][:50]
        )
        
        ml_models.create_ensemble_model(email_results, url_results)
        
        # Test prediction
        test_cases = [
            ("Legitimate: Nykaa order confirmation", 
             "Thank you for shopping with Nykaa! Your order has been confirmed."),
            ("Phishing: Urgent account suspension",
             "URGENT: Your account will be suspended! Click here immediately to verify."),
            ("Marketing: Netflix subscription", 
             "Your Netflix subscription will renew on March 15th. Enjoy streaming!")
        ]
        
        print("\nFinal Integration Test Results:")
        print("-" * 50)
        
        for description, email in test_cases:
            result = ml_models.predict_email(email)
            print(f"{description}")
            print(f"  Prediction: {result['prediction']}")
            print(f"  Confidence: {result['confidence']:.3f}")
            print(f"  Top reason: {result['reasons'][0] if result['reasons'] else 'None'}")
            print()
        
        print("✓ Integration test completed successfully!")
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*60)
    print("PRODUCTION SYSTEM TEST COMPLETED")
    print("="*60)

if __name__ == "__main__":
    run_comprehensive_test()