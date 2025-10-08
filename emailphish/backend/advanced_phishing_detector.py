#!/usr/bin/env python3
"""
Advanced Phishing Email Detection System
- Comprehensive dataset creation from multiple sources
- Advanced feature engineering
- State-of-the-art ML algorithms
- Deep learning integration
"""

import pandas as pd
import numpy as np
import re
import logging
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import pickle
from datetime import datetime

# Advanced ML imports
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import (
    RandomForestClassifier, 
    GradientBoostingClassifier, 
    ExtraTreesClassifier,
    AdaBoostClassifier,
    VotingClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB, GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
from scipy.sparse import hstack, vstack
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedPhishingDatasetBuilder:
    """Build comprehensive phishing email dataset from multiple sources"""
    
    def __init__(self):
        self.modern_phishing_emails = [
            # Cryptocurrency scams
            "🚨 URGENT: Your Bitcoin wallet has been compromised! Unauthorized transactions detected totaling $15,000. Secure your funds immediately by verifying your identity here: cryptosecure-wallet.com. Act within 2 hours or lose access forever!",
            
            # AI/Tech themed phishing
            "ChatGPT Pro Account Suspended! Your premium subscription has been terminated due to suspicious activity. Restore access now by confirming your OpenAI credentials. Limited time: 24 hours only!",
            
            # Modern financial phishing
            "Venmo Security Alert: Multiple failed login attempts detected from Russia and China. Your account will be locked in 1 hour unless you verify your identity immediately. Click here to secure your account.",
            
            # COVID/Health related (still common)
            "NHS Vaccination Certificate: Download your official COVID-19 vaccination passport. Required for international travel. Verify your NHS number and personal details here.",
            
            # Streaming service phishing
            "Disney+ Account Expired: Your subscription has ended. Continue watching your favorite shows with our special 50% discount. Update payment info within 48 hours or lose access permanently.",
            
            # E-commerce sophisticated phishing
            "Amazon Prime Day Exclusive: You've been selected for early access to deals up to 90% off. Limited to first 1000 customers. Confirm your Prime membership details to unlock deals.",
            
            # Social media account compromise
            "Instagram Security Team: We detected unusual activity on your account from multiple countries. Your account will be permanently deleted in 24 hours unless you verify ownership immediately.",
            
            # Tax/Government phishing (modern)
            "IRS Digital Tax Portal: You have unclaimed tax refund of $2,847.53 waiting. File your digital claim now before the deadline expires. Secure portal expires in 72 hours.",
            
            # Sophisticated bank phishing
            "Chase Mobile Banking: Your account shows 3 unauthorized transactions totaling $1,250. Freeze your account now to prevent further fraud. Immediate action required to protect your funds.",
            
            # Job/Career phishing
            "LinkedIn Job Opportunity: Senior Software Engineer position at Google. Salary: $180,000. Interview scheduled for tomorrow. Confirm your attendance and provide credentials for security clearance.",
            
            # Investment/Trading scams
            "Tesla Stock Alert: Elon Musk announces new AI project. Stock price expected to surge 400%. Invest now before public announcement. Minimum $500 investment for guaranteed returns.",
            
            # Package delivery scams
            "FedEx Delivery Failure: Your package worth $899 couldn't be delivered. Pay $3.95 customs fee to reschedule delivery. Package will be returned to sender in 24 hours if not claimed.",
            
            # Utility/Service provider phishing
            "Xfinity Internet: Your service will be disconnected tomorrow due to unpaid bills. Avoid disconnection by paying $127.50 immediately. Log into your account to prevent service interruption.",
            
            # Dating/Romance scams
            "Match.com Premium: Someone special has been trying to message you! You have 5 premium messages waiting. Upgrade now to read them before they expire in 48 hours.",
            
            # Tech support scams
            "Microsoft Windows Defender: 18 viruses detected on your computer. Your personal files are at risk. Download our advanced security software immediately to prevent data loss and identity theft.",
            
            # Travel/Booking phishing
            "Booking.com Confirmation: Your hotel reservation in Paris has been cancelled due to payment failure. Re-book within 2 hours to secure the same rate or face 300% price increase.",
            
            # Insurance/Legal phishing
            "Auto Insurance Refund: You're entitled to $480 refund due to COVID-19 relief program. Claim must be filed within 5 days. Provide your policy details to process the refund.",
            
            # Subscription service phishing
            "Spotify Premium Alert: Your music will stop playing tomorrow. Renew your subscription with our exclusive 70% discount. Offer valid for next 6 hours only for select users.",
            
            # Cloud storage phishing
            "Google Drive Storage Full: Your account storage is 100% full. All new emails and files will be lost unless you upgrade immediately. Free upgrade available for next 24 hours only.",
            
            # Energy/Utility modern phishing
            "Electric Company Alert: Smart meter data shows irregular usage patterns. Avoid overcharge penalties by updating your account information. Failure to respond will result in service disconnection."
        ]
        
        self.legitimate_emails = [
            # Modern legitimate business emails
            "Google Workspace: Your team's monthly summary is ready. This month you collaborated on 45 documents, attended 23 meetings, and shared 156 files. View your productivity dashboard here.",
            
            "Microsoft Teams: Meeting recording for 'Project Alpha Review' is now available. The recording will be kept for 90 days. Access it through your Teams account or the meeting chat.",
            
            "Slack: Your workspace 'TechCorp' has reached 85% of its monthly message limit. Consider upgrading to our Pro plan for unlimited messaging and additional features.",
            
            "GitHub: Pull request #147 in repository 'web-app' has been approved and merged by senior-developer. The CI/CD pipeline completed successfully with all tests passing.",
            
            "AWS Billing: Your monthly AWS usage for account ending in 4567 is $89.23. This includes EC2, S3, and Lambda usage. Download your detailed billing report from the AWS console.",
            
            "Zoom: Your Pro account expires in 7 days. Renew now to continue hosting meetings with up to 100 participants and cloud recording features. Your meeting history will be preserved.",
            
            "Stripe: Payment of $299.00 from Customer #cus_1234 has been successfully processed. Transaction ID: pi_1AbC2D3EfG4Hi5Jk. Funds will appear in your account within 2-7 business days.",
            
            "Adobe Creative Cloud: New updates are available for Photoshop, Illustrator, and InDesign. These updates include performance improvements and new AI-powered features. Update now.",
            
            "Salesforce: Your monthly CRM report shows 127 new leads, 43 deals closed, and $234,567 in revenue generated. Your team exceeded targets by 12% this month. Great work!",
            
            "LinkedIn Learning: You've completed 'Advanced Python Programming' course. Your certificate is ready for download. Add this skill to your LinkedIn profile to boost your visibility.",
            
            "Dropbox Business: Your team used 1.2TB of storage this month. Files were accessed from 15 different devices across 8 countries. Security scan shows no suspicious activity.",
            
            "Shopify: Your online store 'TechGadgets' processed 89 orders this week totaling $4,567. Your best-selling product was 'Wireless Headphones' with 23 sales. View detailed analytics.",
            
            "QuickBooks: Your monthly bookkeeping summary is ready. Total income: $15,678, Total expenses: $8,923, Net profit: $6,755. Tax filing deadline is approaching in 30 days.",
            
            "HubSpot: Your email campaign 'Summer Sale 2024' achieved a 24% open rate and 8.3% click-through rate, above industry average. 156 new subscribers joined your list.",
            
            "Atlassian Jira: Sprint 23 has been completed. 18 out of 20 story points delivered. 2 bugs fixed, 5 features implemented. Next sprint planning meeting scheduled for Monday.",
            
            "Zendesk: Your customer satisfaction score improved to 94% this month. Average response time: 2.3 hours. Your team resolved 234 tickets with only 3 escalations.",
            
            "DocuSign: Document 'Employment Contract - John Smith' has been signed by all parties. The signed document is now legally binding and stored in your account securely.",
            
            "Mailchimp: Your newsletter 'Tech Weekly' was sent to 2,456 subscribers. Open rate: 31.2%, Click rate: 7.8%. Most clicked link was 'New AI Tools Review' with 89 clicks.",
            
            "Asana: Project 'Website Redesign' is 78% complete. 15 tasks remaining before the deadline. Team velocity is on track. Next milestone: 'User Testing' due Friday.",
            
            "Twilio: Your SMS campaign sent 1,234 messages successfully. Delivery rate: 98.7%. Cost: $24.68. No failed deliveries or compliance issues detected.",
            
            "Square: Daily sales report for March 15th: 67 transactions totaling $2,346. Most popular item: Coffee Latte (23 sales). Peak hour: 10-11 AM with $456 in sales.",
            
            "PayPal Business: Monthly account statement is ready. Total payments received: $12,345. Total fees: $458. Net amount: $11,887. Automatic transfer to bank account completed.",
            
            "Calendly: You have 12 upcoming appointments this week. Reminder emails have been sent to all attendees. One reschedule request pending for Thursday 3 PM meeting.",
            
            "Buffer: Your social media posts performed well this month. Total reach: 45,678 users. Engagement rate: 6.7%. Most popular post: 'Industry Trends 2024' with 234 likes.",
            
            "Intercom: Customer support metrics for February: Average first response time: 1.2 hours. Customer satisfaction: 91%. 89% of conversations resolved without escalation.",
            
            "Notion: Your workspace 'Product Team' has been updated with 15 new pages this week. Most active collaborator: sarah@company.com. Database 'Tasks' has 23 new entries.",
            
            "Figma: Design file 'Mobile App UI v2.3' has been shared with your team. 4 comments added this week. Next design review meeting scheduled for Wednesday at 2 PM.",
            
            "Canva: Your brand kit 'TechStart Logo' has been accessed 45 times this month. 12 new designs created using your brand colors and fonts. Team collaboration is active.",
            
            "Loom: Video 'Product Demo V1' has been viewed 78 times with average watch time of 4 minutes 32 seconds. 5 comments received. Engagement rate: 12.8%.",
            
            "1Password: Security report for your business account: 234 passwords stored, 89% strong passwords, 12 passwords need updating. No compromised passwords detected."
        ]

    def create_comprehensive_dataset(self) -> pd.DataFrame:
        """Create a comprehensive dataset combining multiple sources"""
        logger.info("Creating comprehensive phishing email dataset...")
        
        datasets = []
        
        # Add SpamAssassin data (if available)
        try:
            spam_df = pd.read_csv('processed_email_dataset.csv')
            datasets.append(spam_df)
            logger.info(f"Added SpamAssassin dataset: {len(spam_df)} emails")
        except FileNotFoundError:
            logger.warning("SpamAssassin dataset not found")
        
        # Add modern phishing emails
        modern_phishing_df = pd.DataFrame({
            'email': self.modern_phishing_emails,
            'label': [1] * len(self.modern_phishing_emails)
        })
        datasets.append(modern_phishing_df)
        logger.info(f"Added modern phishing emails: {len(modern_phishing_df)} emails")
        
        # Add modern legitimate emails
        modern_legit_df = pd.DataFrame({
            'email': self.legitimate_emails,
            'label': [0] * len(self.legitimate_emails)
        })
        datasets.append(modern_legit_df)
        logger.info(f"Added modern legitimate emails: {len(modern_legit_df)} emails")
        
        # Combine all datasets
        if datasets:
            combined_df = pd.concat(datasets, ignore_index=True)
            combined_df = combined_df.dropna().drop_duplicates(subset=['email'])
            combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
            
            logger.info(f"Total dataset size: {len(combined_df)} emails")
            logger.info(f"Legitimate emails: {len(combined_df[combined_df['label'] == 0])}")
            logger.info(f"Phishing emails: {len(combined_df[combined_df['label'] == 1])}")
            
            return combined_df
        else:
            raise ValueError("No datasets could be loaded")

class AdvancedFeatureExtractor:
    """Extract advanced features for phishing detection"""
    
    def __init__(self):
        self.feature_names = [
            # Basic text features
            'length', 'word_count', 'char_count', 'avg_word_length', 'sentence_count',
            'unique_words_ratio', 'type_token_ratio',
            
            # Character-level features
            'uppercase_ratio', 'lowercase_ratio', 'digit_ratio', 'punctuation_ratio',
            'whitespace_ratio', 'special_char_ratio',
            
            # Punctuation analysis
            'exclamation_count', 'question_count', 'period_count', 'comma_count',
            'exclamation_density', 'question_density',
            
            # URL and link analysis
            'url_count', 'short_url_count', 'suspicious_url_count', 'legitimate_url_count',
            'url_to_text_ratio', 'redirect_count',
            
            # Email-specific features
            'email_address_count', 'phone_number_count', 'ip_address_count',
            
            # Phishing indicators
            'urgent_words', 'threat_words', 'financial_words', 'credential_words',
            'scarcity_words', 'authority_words', 'social_proof_words',
            
            # Legitimate indicators
            'business_terms', 'professional_language', 'legitimate_domains',
            'subscription_terms', 'service_terms',
            
            # Advanced linguistic features
            'readability_score', 'sentiment_polarity', 'emotion_intensity',
            'formality_score', 'urgency_score', 'trust_score',
            
            # Structural features
            'html_tag_count', 'link_text_ratio', 'image_count',
            'attachment_indicators', 'form_count',
            
            # Time and currency features
            'time_references', 'currency_mentions', 'number_sequences',
            'percentage_mentions', 'date_references',
            
            # Security-related features
            'security_terms', 'account_terms', 'verification_terms',
            'password_terms', 'login_terms',
            
            # Brand impersonation features
            'bank_brands', 'tech_brands', 'social_brands', 'ecommerce_brands',
            'government_brands', 'financial_brands'
        ]
        
        # Define feature dictionaries
        self.urgent_keywords = [
            'urgent', 'immediate', 'asap', 'emergency', 'critical', 'important',
            'expires', 'deadline', 'limited time', 'act now', 'hurry', 'quick',
            'final notice', 'last chance', 'don\'t miss', 'time sensitive'
        ]
        
        self.threat_keywords = [
            'suspend', 'terminate', 'close', 'lock', 'freeze', 'restrict',
            'penalty', 'fine', 'legal action', 'court', 'lawsuit', 'arrest',
            'criminal', 'fraud', 'investigation', 'consequences', 'jail'
        ]
        
        self.financial_keywords = [
            'refund', 'tax', 'money', 'payment', 'credit card', 'bank account',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'investment', 'profit',
            'winner', 'prize', 'lottery', 'jackpot', 'million', 'inheritance'
        ]
        
        self.credential_keywords = [
            'password', 'username', 'login', 'signin', 'verify', 'confirm',
            'update', 'validate', 'authenticate', 'security code', 'pin',
            'ssn', 'social security', 'driver license', 'passport'
        ]
        
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
            'netflix.com', 'spotify.com', 'linkedin.com', 'twitter.com', 'instagram.com',
            'paypal.com', 'ebay.com', 'uber.com', 'airbnb.com', 'dropbox.com',
            'github.com', 'slack.com', 'zoom.com', 'adobe.com', 'salesforce.com'
        }
        
        self.business_terms = [
            'invoice', 'receipt', 'order', 'shipment', 'delivery', 'subscription',
            'newsletter', 'unsubscribe', 'customer', 'support', 'service',
            'account', 'billing', 'statement', 'report', 'analytics', 'dashboard'
        ]

    def extract_features(self, email_text: str) -> np.ndarray:
        """Extract all features from email text"""
        features = []
        email_lower = email_text.lower()
        
        # Basic text features
        words = email_text.split()
        sentences = re.split(r'[.!?]+', email_text)
        
        features.extend([
            len(email_text),  # length
            len(words),  # word_count
            len(email_text),  # char_count
            np.mean([len(word) for word in words]) if words else 0,  # avg_word_length
            len([s for s in sentences if s.strip()]),  # sentence_count
            len(set(words)) / max(len(words), 1),  # unique_words_ratio
            len(set(words)) / max(len(words), 1)  # type_token_ratio
        ])
        
        # Character-level features
        if len(email_text) > 0:
            features.extend([
                sum(1 for c in email_text if c.isupper()) / len(email_text),
                sum(1 for c in email_text if c.islower()) / len(email_text),
                sum(1 for c in email_text if c.isdigit()) / len(email_text),
                sum(1 for c in email_text if c in '.,!?;:()[]{}') / len(email_text),
                sum(1 for c in email_text if c.isspace()) / len(email_text),
                sum(1 for c in email_text if not c.isalnum() and not c.isspace()) / len(email_text)
            ])
        else:
            features.extend([0.0] * 6)
        
        # Punctuation analysis
        exclamation_count = email_text.count('!')
        question_count = email_text.count('?')
        period_count = email_text.count('.')
        comma_count = email_text.count(',')
        
        features.extend([
            exclamation_count,
            question_count,
            period_count,
            comma_count,
            exclamation_count / max(len(words), 1),  # exclamation_density
            question_count / max(len(words), 1)  # question_density
        ])
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', email_text)
        short_urls = len([url for url in urls if any(short in url for short in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'])])
        suspicious_urls = len([url for url in urls if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf'])])
        legitimate_urls = len([url for url in urls if any(domain in url for domain in self.legitimate_domains)])
        
        features.extend([
            len(urls),
            short_urls,
            suspicious_urls,
            legitimate_urls,
            len(' '.join(urls)) / max(len(email_text), 1),  # url_to_text_ratio
            email_text.count('redirect')
        ])
        
        # Contact information
        email_addresses = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_text))
        phone_numbers = len(re.findall(r'(\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})', email_text))
        ip_addresses = len(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', email_text))
        
        features.extend([email_addresses, phone_numbers, ip_addresses])
        
        # Keyword analysis
        for keywords in [self.urgent_keywords, self.threat_keywords, self.financial_keywords, 
                        self.credential_keywords, [], [], []]:  # Add more keyword lists
            count = sum(1 for keyword in keywords if keyword in email_lower)
            features.append(count)
        
        # Business and legitimate terms
        business_count = sum(1 for term in self.business_terms if term in email_lower)
        legitimate_domain_count = sum(1 for domain in self.legitimate_domains if domain.split('.')[0] in email_lower)
        
        features.extend([business_count, 0, legitimate_domain_count, 0, 0])  # Placeholder for professional_language, subscription_terms, service_terms
        
        # Advanced features (simplified implementations)
        features.extend([
            0.5,  # readability_score (placeholder)
            0.0,  # sentiment_polarity (placeholder)
            0.0,  # emotion_intensity (placeholder)
            0.5,  # formality_score (placeholder)
            min(sum(1 for word in self.urgent_keywords if word in email_lower) / max(len(words), 1), 1.0),  # urgency_score
            max(0, business_count + legitimate_domain_count) / max(len(words), 1)  # trust_score
        ])
        
        # Structural features
        html_tags = len(re.findall(r'<[^>]+>', email_text))
        features.extend([
            html_tags,
            0.0,  # link_text_ratio (placeholder)
            email_text.count('<img'),
            1 if 'attachment' in email_lower else 0,
            email_text.count('<form')
        ])
        
        # Additional features
        features.extend([
            len(re.findall(r'\b\d{1,2}:\d{2}\b', email_text)),  # time_references
            len(re.findall(r'[\$£€¥₹]', email_text)),  # currency_mentions
            len(re.findall(r'\b\d{3,}\b', email_text)),  # number_sequences
            len(re.findall(r'\d+%', email_text)),  # percentage_mentions
            len(re.findall(r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', email_text))  # date_references
        ])
        
        # Security and brand features (simplified)
        security_terms = sum(1 for term in ['security', 'secure', 'protected', 'encrypted'] if term in email_lower)
        features.extend([security_terms, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        
        # Ensure we have exactly the right number of features
        while len(features) < len(self.feature_names):
            features.append(0.0)
        
        return np.array(features[:len(self.feature_names)])

class AdvancedPhishingDetector:
    """Advanced machine learning system for phishing detection"""
    
    def __init__(self):
        self.models = {}
        self.feature_extractor = AdvancedFeatureExtractor()
        self.vectorizers = {}
        self.scalers = {}
        self.feature_selector = None
        
    def build_advanced_models(self) -> Dict:
        """Build ensemble of advanced models"""
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=500,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=300,
                learning_rate=0.1,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            ),
            'extra_trees': ExtraTreesClassifier(
                n_estimators=300,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            ),
            'svm_rbf': SVC(
                C=10,
                gamma='scale',
                kernel='rbf',
                probability=True,
                class_weight='balanced',
                random_state=42
            ),
            'logistic_regression': LogisticRegression(
                C=1.0,
                penalty='l2',
                solver='liblinear',
                class_weight='balanced',
                random_state=42,
                max_iter=1000
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(200, 100, 50),
                activation='relu',
                solver='adam',
                alpha=0.001,
                batch_size=200,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            )
        }
        return models
        
    def train_advanced_system(self, df: pd.DataFrame) -> Dict:
        """Train the advanced phishing detection system"""
        logger.info("Training advanced phishing detection system...")
        
        # Feature extraction
        logger.info("Extracting advanced features...")
        custom_features = np.array([
            self.feature_extractor.extract_features(email) 
            for email in df['email']
        ])
        
        # TF-IDF vectorization with advanced parameters
        logger.info("Creating TF-IDF features...")
        tfidf_word = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english',
            lowercase=True,
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )
        
        tfidf_char = TfidfVectorizer(
            max_features=3000,
            analyzer='char',
            ngram_range=(3, 5),
            lowercase=True,
            min_df=2,
            max_df=0.95
        )
        
        X_tfidf_word = tfidf_word.fit_transform(df['email'])
        X_tfidf_char = tfidf_char.fit_transform(df['email'])
        
        # Combine all features
        X_combined = hstack([X_tfidf_word, X_tfidf_char, custom_features])
        y = df['label'].values
        
        # Feature selection
        logger.info("Performing feature selection...")
        selector = SelectKBest(mutual_info_classif, k=8000)
        X_selected = selector.fit_transform(X_combined, y)
        
        # Scale features
        scaler = StandardScaler(with_mean=False)
        X_scaled = scaler.fit_transform(X_selected)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train individual models
        logger.info("Training individual models...")
        models = self.build_advanced_models()
        trained_models = {}
        model_scores = {}
        
        for name, model in models.items():
            logger.info(f"Training {name}...")
            try:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred)
                recall = recall_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred)
                auc = roc_auc_score(y_test, y_pred_proba)
                
                trained_models[name] = model
                model_scores[name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'auc': auc
                }
                
                logger.info(f"{name} - Accuracy: {accuracy:.3f}, F1: {f1:.3f}, AUC: {auc:.3f}")
                
            except Exception as e:
                logger.error(f"Failed to train {name}: {e}")
        
        # Create ensemble
        logger.info("Creating advanced ensemble...")
        if len(trained_models) >= 3:
            # Select top 3 models based on F1 score
            top_models = sorted(model_scores.items(), key=lambda x: x[1]['f1'], reverse=True)[:3]
            ensemble_estimators = [(name, trained_models[name]) for name, _ in top_models]
            
            ensemble = VotingClassifier(
                estimators=ensemble_estimators,
                voting='soft',
                n_jobs=-1
            )
            
            logger.info("Training ensemble...")
            ensemble.fit(X_train, y_train)
            
            # Evaluate ensemble
            y_pred_ensemble = ensemble.predict(X_test)
            y_pred_proba_ensemble = ensemble.predict_proba(X_test)[:, 1]
            
            ensemble_accuracy = accuracy_score(y_test, y_pred_ensemble)
            ensemble_f1 = f1_score(y_test, y_pred_ensemble)
            ensemble_auc = roc_auc_score(y_test, y_pred_proba_ensemble)
            
            logger.info(f"Ensemble - Accuracy: {ensemble_accuracy:.3f}, F1: {ensemble_f1:.3f}, AUC: {ensemble_auc:.3f}")
            
            # Store components
            self.models['ensemble'] = ensemble
            self.vectorizers['tfidf_word'] = tfidf_word
            self.vectorizers['tfidf_char'] = tfidf_char
            self.scalers['feature_scaler'] = scaler
            self.feature_selector = selector
            
            return {
                'ensemble_accuracy': ensemble_accuracy,
                'ensemble_f1': ensemble_f1,
                'ensemble_auc': ensemble_auc,
                'individual_scores': model_scores,
                'top_models': [name for name, _ in top_models]
            }
        
        else:
            raise ValueError("Not enough models trained successfully")
    
    def predict_advanced(self, email_text: str) -> Dict:
        """Make prediction using the advanced system"""
        if 'ensemble' not in self.models:
            return {'error': 'Advanced model not trained'}
        
        try:
            # Extract features
            custom_features = self.feature_extractor.extract_features(email_text).reshape(1, -1)
            
            # Vectorize
            tfidf_word = self.vectorizers['tfidf_word'].transform([email_text])
            tfidf_char = self.vectorizers['tfidf_char'].transform([email_text])
            
            # Combine features
            X_combined = hstack([tfidf_word, tfidf_char, custom_features])
            
            # Select and scale features
            X_selected = self.feature_selector.transform(X_combined)
            X_scaled = self.scalers['feature_scaler'].transform(X_selected)
            
            # Predict
            prediction = self.models['ensemble'].predict(X_scaled)[0]
            probabilities = self.models['ensemble'].predict_proba(X_scaled)[0]
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'safe',
                'confidence': float(max(probabilities)),
                'phishing_probability': float(probabilities[1]),
                'safe_probability': float(probabilities[0])
            }
            
        except Exception as e:
            logger.error(f"Advanced prediction error: {e}")
            return {'error': str(e)}

def main():
    """Main function to build and train advanced system"""
    try:
        # Build dataset
        logger.info("Building comprehensive dataset...")
        dataset_builder = AdvancedPhishingDatasetBuilder()
        df = dataset_builder.create_comprehensive_dataset()
        
        # Save dataset
        df.to_csv('advanced_phishing_dataset.csv', index=False)
        logger.info("Dataset saved to advanced_phishing_dataset.csv")
        
        # Train advanced system
        detector = AdvancedPhishingDetector()
        results = detector.train_advanced_system(df)
        
        # Save models
        with open('advanced_phishing_detector.pkl', 'wb') as f:
            pickle.dump(detector, f)
        
        logger.info("Advanced phishing detection system trained successfully!")
        logger.info(f"Results: {results}")
        
        return detector, results
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return None, None

if __name__ == "__main__":
    main()