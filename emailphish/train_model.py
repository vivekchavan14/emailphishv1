import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
from scipy.sparse import hstack
import os

print("Starting model training process...")

# Function to extract additional features from emails
def extract_email_features(emails):
    # Create empty arrays for features
    num_links = np.zeros((len(emails), 1))
    contains_urgent = np.zeros((len(emails), 1))
    contains_money = np.zeros((len(emails), 1))
    contains_suspicious_domains = np.zeros((len(emails), 1))
    email_length = np.zeros((len(emails), 1))
    
    # Define patterns
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    urgent_pattern = re.compile(r'urgent|immediate|alert|attention|important|verify', re.IGNORECASE)
    money_pattern = re.compile(r'money|cash|dollar|payment|bank|account|transfer|credit', re.IGNORECASE)
    suspicious_domains = re.compile(r'\.xyz|\.info|\.top|\.club|\.online', re.IGNORECASE)
    
    # Extract features
    for i, email in enumerate(emails):
        # Count URLs
        urls = url_pattern.findall(email)
        num_links[i] = len(urls)
        
        # Check for urgent language
        contains_urgent[i] = 1 if urgent_pattern.search(email) else 0
        
        # Check for money-related terms
        contains_money[i] = 1 if money_pattern.search(email) else 0
        
        # Check for suspicious domains
        contains_suspicious_domains[i] = 1 if suspicious_domains.search(email) else 0
        
        # Email length
        email_length[i] = len(email)
    
    # Return all features as a single array
    return np.hstack([num_links, contains_urgent, contains_money, 
                     contains_suspicious_domains, email_length])

# Load dataset
print("Loading dataset...")
df = pd.read_csv('data/emails.csv')  # Ensure your CSV has 'Email Text' and 'Email Type' columns

# Handle missing or invalid data
df['Email Text'] = df['Email Text'].fillna('')  # Replace NaN with an empty string
df['Email Type'] = df['Email Type'].fillna('')  # Ensure no missing labels

# Prepare features and labels
X = df['Email Text']
y = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})  # Convert labels to binary

# Save raw text for additional feature extraction
X_raw = X.copy()

# Text preprocessing and vectorization
print("Performing text vectorization...")
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_vectorized = vectorizer.fit_transform(X)

# Extract additional features
print("Extracting additional features...")
X_additional = extract_email_features(X_raw)

# Combine TF-IDF features with additional features
print("Combining features...")
X_combined = hstack([X_vectorized, X_additional])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.3, random_state=42)

# Create output directories if they don't exist
os.makedirs('backend', exist_ok=True)

# Default model without hyperparameter tuning (in case grid search takes too long)
print("Training baseline model...")
default_model = GradientBoostingClassifier(random_state=42)
default_model.fit(X_train, y_train)

# Evaluate the default model
y_pred_default = default_model.predict(X_test)
print("\nBaseline Model:")
print("Accuracy:", accuracy_score(y_test, y_pred_default))
print("Classification Report:\n", classification_report(y_test, y_pred_default))

# Save the default model and vectorizer (as a backup)
with open('backend/default_model.pkl', 'wb') as model_file:
    pickle.dump(default_model, model_file)

# Hyperparameter tuning with GridSearchCV
print("\nStarting hyperparameter tuning (this may take a while)...")
# Define a smaller parameter grid for initial testing
param_grid = {
    'n_estimators': [100, 200],
    'learning_rate': [0.05, 0.1],
    'max_depth': [3, 5],
    'subsample': [0.8, 1.0]
}

# Create the GridSearchCV object
grid_search = GridSearchCV(
    GradientBoostingClassifier(random_state=42),
    param_grid=param_grid,
    cv=3,  # Use 3-fold cross-validation to speed up the process
    scoring='f1_weighted',
    n_jobs=-1,  # Use all available cores
    verbose=1
)

# Train with grid search
grid_search.fit(X_train, y_train)

# Get the best parameters and model
best_params = grid_search.best_params_
best_model = grid_search.best_estimator_

# Print results
print("\nBest parameters:", best_params)
print("Best F1 score:", grid_search.best_score_)

# Use the best model for predictions
y_pred = best_model.predict(X_test)
print("\nImproved Model:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save the best model and vectorizer
print("\nSaving model and preprocessing components...")
with open('backend/model.pkl', 'wb') as model_file:
    pickle.dump(best_model, model_file)

with open('backend/vectorizer.pkl', 'wb') as vectorizer_file:
    pickle.dump(vectorizer, vectorizer_file)

# Save feature extraction function
with open('backend/feature_extractor.pkl', 'wb') as extractor_file:
    pickle.dump(extract_email_features, extractor_file)

print("Model and preprocessing components saved!")
print("\nNow you can run the FastAPI application with 'uvicorn app:app --reload'")