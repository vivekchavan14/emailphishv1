#!/usr/bin/env python3
"""
Process SpamAssassin email corpus into a clean dataset for phishing detection.
"""

import os
import pandas as pd
import re
from pathlib import Path
import logging
from typing import List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_email_content(file_path: str) -> str:
    """Extract the main content from an email file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split headers and body
        if '\n\n' in content:
            headers, body = content.split('\n\n', 1)
        else:
            headers = content
            body = ""
        
        # Extract subject from headers
        subject_match = re.search(r'^Subject:\s*(.+)$', headers, re.MULTILINE | re.IGNORECASE)
        subject = subject_match.group(1).strip() if subject_match else ""
        
        # Clean the body
        body = re.sub(r'^[>|]+.*$', '', body, flags=re.MULTILINE)  # Remove quoted text
        body = re.sub(r'http[s]?://[^\s]+', '[URL]', body)  # Replace URLs
        body = re.sub(r'\n+', ' ', body)  # Replace multiple newlines
        body = re.sub(r'\s+', ' ', body).strip()  # Normalize whitespace
        
        # Combine subject and body
        full_content = f"{subject} {body}".strip()
        
        # Filter out very short emails or ones that are mostly HTML
        if len(full_content) < 50:
            return None
        
        # Remove emails that are mostly HTML tags
        html_ratio = len(re.findall(r'<[^>]+>', full_content)) / max(len(full_content.split()), 1)
        if html_ratio > 0.3:  # More than 30% HTML tags
            return None
            
        return full_content
        
    except Exception as e:
        logger.warning(f"Failed to process {file_path}: {e}")
        return None

def process_email_directory(directory: str, label: int, max_emails: int = None) -> List[Tuple[str, int]]:
    """Process all emails in a directory."""
    emails = []
    directory_path = Path(directory)
    
    if not directory_path.exists():
        logger.error(f"Directory {directory} does not exist")
        return emails
    
    email_files = list(directory_path.glob('*'))
    if max_emails:
        email_files = email_files[:max_emails]
    
    logger.info(f"Processing {len(email_files)} emails from {directory}")
    
    for file_path in email_files:
        if file_path.is_file():
            content = extract_email_content(str(file_path))
            if content:
                emails.append((content, label))
    
    logger.info(f"Successfully processed {len(emails)} emails from {directory}")
    return emails

def create_balanced_dataset():
    """Create a balanced email dataset from SpamAssassin corpus."""
    
    # Paths to the datasets
    ham_dir = "datasets/easy_ham"
    spam_dir = "datasets/spam"
    
    # Process legitimate emails (ham)
    ham_emails = process_email_directory(ham_dir, 0, max_emails=1000)  # Limit to 1000
    
    # Process spam emails
    spam_emails = process_email_directory(spam_dir, 1, max_emails=500)   # Limit to 500
    
    # Combine datasets
    all_emails = ham_emails + spam_emails
    
    if not all_emails:
        logger.error("No emails processed successfully")
        return None
    
    # Create DataFrame
    df = pd.DataFrame(all_emails, columns=['email', 'label'])
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"Created dataset with {len(df)} emails:")
    logger.info(f"  - Legitimate emails: {len(df[df['label'] == 0])}")
    logger.info(f"  - Spam emails: {len(df[df['label'] == 1])}")
    
    return df

def save_processed_dataset():
    """Process and save the email dataset."""
    df = create_balanced_dataset()
    
    if df is not None:
        # Save to CSV
        output_path = "processed_email_dataset.csv"
        df.to_csv(output_path, index=False)
        logger.info(f"Dataset saved to {output_path}")
        
        # Show some samples
        print("\n--- Sample Legitimate Emails ---")
        for i, email in enumerate(df[df['label'] == 0]['email'].head(3)):
            print(f"{i+1}. {email[:200]}...")
        
        print("\n--- Sample Spam Emails ---")
        for i, email in enumerate(df[df['label'] == 1]['email'].head(3)):
            print(f"{i+1}. {email[:200]}...")
            
        return output_path
    else:
        logger.error("Failed to create dataset")
        return None

if __name__ == "__main__":
    save_processed_dataset()