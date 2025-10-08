#!/usr/bin/env python3
"""
Simple test script for production phishing detection system
"""

import sys
from pathlib import Path

# Add parent directories to path
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir / "models"))
sys.path.append(str(current_dir / "data"))

def test_imports():
    """Test that all components can be imported"""
    print("Testing imports...")
    
    try:
        from production_ml_models import ProductionMLModels, ProductionFeatureExtractor
        print("✓ ML models imported successfully")
        
        from dataset_manager import ProductionDatasetManager
        print("✓ Dataset manager imported successfully")
        
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_feature_extraction():
    """Test feature extraction"""
    print("\nTesting feature extraction...")
    
    try:
        from production_ml_models import ProductionFeatureExtractor
        
        extractor = ProductionFeatureExtractor()
        
        # Test with legitimate email
        legitimate_email = "Thank you for shopping with Nykaa! Your order has been confirmed. Track at nykaa.com"
        features = extractor.extract_email_features(legitimate_email)
        
        print(f"✓ Extracted {len(features)} features from legitimate email")
        
        # Test with phishing email
        phishing_email = "URGENT: Your account will be suspended! Click here immediately to verify your password: http://fake-site.tk"
        phishing_features = extractor.extract_email_features(phishing_email)
        
        print(f"✓ Extracted {len(phishing_features)} features from phishing email")
        
        # Show feature names
        feature_names = extractor.get_feature_names()
        print(f"✓ Feature names: {len(feature_names)} total features")
        
        return True
        
    except Exception as e:
        print(f"✗ Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_dataset_manager():
    """Test dataset management"""
    print("\nTesting dataset manager...")
    
    try:
        from dataset_manager import ProductionDatasetManager
        
        manager = ProductionDatasetManager()
        
        # Test dataset preparation (this might take a moment)
        print("Preparing datasets...")
        datasets = manager.prepare_production_datasets()
        
        print(f"✓ Email dataset: {len(datasets['email'])} samples")
        print(f"✓ URL dataset: {len(datasets['url'])} samples")
        
        # Test train/test split
        splits = manager.get_train_test_split(datasets)
        print(f"✓ Train/test splits created")
        print(f"  Email train: {len(splits['email']['X_train'])}, test: {len(splits['email']['X_test'])}")
        print(f"  URL train: {len(splits['url']['X_train'])}, test: {len(splits['url']['X_test'])}")
        
        return True
        
    except Exception as e:
        print(f"✗ Dataset manager failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_model_training():
    """Test model training with small dataset"""
    print("\nTesting model training (small dataset)...")
    
    try:
        from production_ml_models import ProductionMLModels
        from dataset_manager import ProductionDatasetManager
        
        # Prepare small datasets
        manager = ProductionDatasetManager()
        datasets = manager.prepare_production_datasets()
        splits = manager.get_train_test_split(datasets)
        
        # Use smaller datasets for testing
        email_train_small = splits['email']['X_train'].head(50)
        email_test_small = splits['email']['X_test'].head(20)
        email_y_train_small = splits['email']['y_train'][:50]
        email_y_test_small = splits['email']['y_test'][:20]
        
        url_train_small = splits['url']['X_train'][:50]
        url_test_small = splits['url']['X_test'][:20]
        url_y_train_small = splits['url']['y_train'][:50]
        url_y_test_small = splits['url']['y_test'][:20]
        
        # Train models
        ml_models = ProductionMLModels()
        
        print("Training email models...")
        email_results = ml_models.train_email_model(
            email_train_small, email_y_train_small,
            email_test_small, email_y_test_small
        )
        
        print("Training URL models...")
        url_results = ml_models.train_url_model(
            url_train_small, url_y_train_small,
            url_test_small, url_y_test_small
        )
        
        # Create ensemble
        best_model = ml_models.create_ensemble_model(email_results, url_results)
        print(f"✓ Ensemble created with best model: {best_model}")
        
        # Test predictions
        test_emails = [
            "Thank you for shopping with Nykaa! Your order has been confirmed.",
            "URGENT: Your account has been suspended! Click here immediately to verify.",
            "Your Netflix subscription will renew next month. Enjoy streaming!"
        ]
        
        print("\nTesting predictions:")
        for i, email in enumerate(test_emails):
            result = ml_models.predict_email(email)
            print(f"  Email {i+1}: {result['prediction']} (confidence: {result['confidence']:.3f})")
            print(f"    Reason: {result['reasons'][0] if result['reasons'] else 'None'}")
        
        return True
        
    except Exception as e:
        print(f"✗ Model training failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("PRODUCTION PHISHING DETECTION SYSTEM - SIMPLE TEST")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_feature_extraction,
        test_dataset_manager,
        test_model_training
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except KeyboardInterrupt:
            print("\n\nTest interrupted by user")
            break
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("🎉 All tests passed! Production system is ready.")
    else:
        print("⚠ Some tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)