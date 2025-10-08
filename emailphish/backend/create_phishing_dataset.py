#!/usr/bin/env python3
"""
Create a comprehensive phishing detection dataset with clear phishing vs legitimate examples.
This focuses on PHISHING detection, not spam detection.
"""

import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_comprehensive_phishing_dataset():
    """Create a dataset specifically for phishing detection"""
    
    # CLEAR PHISHING EMAILS - These should ALWAYS be detected as phishing
    clear_phishing = [
        "Send me your credit card details",
        "Please provide your social security number",
        "I need your bank account information",
        "Send your password for verification",
        "Give me your PIN number",
        "What is your mother's maiden name?",
        "Send me your full name, address and credit card number",
        "Please send your banking details immediately",
        "I need your personal information for verification",
        "Send me your credit card number and CVV code",
        "Please provide your online banking username and password",
        "Send me your social security number and date of birth",
        "I need your debit card details right now",
        "Give me your full credit card information",
        "Send your bank routing number and account number",
        "What is your credit card security code?",
        "Please send me your personal identification number",
        "I need your financial information for processing",
        "Send me your complete banking credentials",
        "Provide your credit card details to continue",
        
        # Urgent credential theft
        "URGENT: Your account has been hacked! Send me your login details to secure it",
        "Security Alert: Verify your identity by sending your full credit card info",
        "Your bank account is compromised! Send your details for protection",
        "EMERGENCY: We need your social security number to prevent fraud",
        "Account suspended! Send credit card info to reactivate immediately",
        "CRITICAL: Your password has been stolen! Send me your new one",
        "WARNING: Send your bank details now or lose your money",
        "Your credit card is being used illegally! Send me the details to stop it",
        "FRAUD ALERT: Send me your personal info to prevent identity theft",
        "Your account will be closed! Send banking details to keep it open",
        
        # Prize/money scams requesting info
        "You won $1 million! Send your bank details to claim your prize",
        "Lottery winner! Provide your credit card info to receive $50,000",
        "Congratulations! Send your personal information to get your inheritance",
        "You've won! Send me your social security number for tax purposes",
        "Prize notification: Send credit card details for processing fee",
        "Winner! Send banking information for money transfer",
        "You inherited money! Send your personal details to claim it",
        "Jackpot winner! Provide your financial information immediately",
        "Cash prize awarded! Send your bank account details now",
        "Money waiting for you! Send credit card info for transfer costs",
        
        # Fake authority/government
        "IRS: Send your social security number for tax refund processing",
        "FBI: Provide your personal information for investigation clearance",
        "Government: Send bank details for stimulus check processing",
        "Police: Send your information to avoid arrest warrant",
        "Court: Provide your details to dismiss charges against you",
        "Tax office: Send credit card info for immediate refund",
        "Social Security Administration: Send your SSN for benefit update",
        "Homeland Security: Provide your information to clear your name",
        "Immigration: Send personal details to update your status",
        "Legal notice: Send your financial info to avoid prosecution",
        
        # Romance/relationship scams
        "I love you! Send me money for my emergency",
        "My dear, I need your bank details to send you money",
        "Honey, send me your credit card info for our future together",
        "Sweetheart, I need your personal information to visit you",
        "My love, send your details so I can transfer money to you",
        "Baby, I need your bank account for our wedding expenses",
        "Darling, send your credit card details for my visa application",
        "My heart, I need your financial info for our life together",
        "Love, send me your personal details for our future",
        "My dear friend, send your banking information to help me",
        
        # Technical support scams
        "Microsoft support: Send your computer password for virus removal",
        "Apple support: Provide your Apple ID password for security update",
        "Google support: Send your Gmail password to fix security issues",
        "Windows support: Send your login details for system repair",
        "Tech support: Provide your passwords for computer maintenance",
        "Security team: Send your credentials for virus scan",
        "IT support: Send your personal info for account recovery",
        "Software support: Provide your passwords for license update",
        "System administrator: Send your login details for urgent fix",
        "Computer repair: Send your passwords to remove malware",
        
        # Investment/crypto scams
        "Send me $500 and your bank details for guaranteed Bitcoin profits",
        "Investment opportunity! Send your credit card info for returns",
        "Crypto mining: Send your personal details for free Bitcoin",
        "Trading platform: Provide your bank details for account funding",
        "Investment club: Send your financial info for membership",
        "Bitcoin generator: Send your wallet details for free coins",
        "Trading bot: Provide your exchange passwords for profits",
        "Cryptocurrency offer: Send your bank details for instant gains",
        "Mining pool: Send your personal info for mining rewards",
        "Forex trading: Provide your credit card for guaranteed profits"
    ]
    
    # LEGITIMATE EMAILS - These should be detected as safe
    legitimate_emails = [
        # Normal business communications
        "Thank you for your recent purchase. Your order #12345 will arrive soon.",
        "Your monthly statement is now available for download in your account.",
        "Meeting reminder: Our project review is scheduled for tomorrow at 2 PM.",
        "Welcome to our newsletter! You can unsubscribe at any time.",
        "Your subscription to our service has been renewed successfully.",
        "Invoice attached for services rendered this month.",
        "Thank you for attending our webinar. Here are the recorded materials.",
        "Your support ticket has been resolved. Please let us know if you need further help.",
        "Quarterly report is now available in the company portal.",
        "Your registration for the conference has been confirmed.",
        
        # Legitimate service notifications
        "Your Netflix subscription will renew on March 15th.",
        "Spotify: Your Discover Weekly playlist is ready.",
        "Amazon: Your package has been delivered to your address.",
        "Google: Your account storage is 80% full. Consider upgrading.",
        "Microsoft: New security features are now available in your account.",
        "Apple: Your iCloud backup was successful.",
        "PayPal: You sent $25.00 to John Smith. Transaction completed.",
        "Uber: Your trip receipt for $12.50 is ready.",
        "Airbnb: Your reservation is confirmed for next week.",
        "LinkedIn: You have 3 new connection requests.",
        
        # Professional emails
        "I hope this email finds you well. I wanted to follow up on our conversation.",
        "Please find attached the documents you requested for review.",
        "I'm writing to inform you about the upcoming changes to our policy.",
        "Thank you for your time during the interview. We'll be in touch soon.",
        "The project deadline has been extended to accommodate the new requirements.",
        "Please join us for the team lunch this Friday at the usual place.",
        "Your performance review has been scheduled for next Thursday.",
        "The client presentation went well. Thank you for your preparation.",
        "New employee handbook is now available on the company intranet.",
        "Budget approval for the marketing campaign has been granted.",
        
        # Customer service
        "We received your inquiry and will respond within 24 hours.",
        "Your warranty claim has been approved. Replacement parts are being shipped.",
        "Thank you for your feedback. We've forwarded it to the relevant team.",
        "Your account settings have been updated as requested.",
        "The issue you reported has been fixed in our latest update.",
        "Your refund has been processed and will appear in 3-5 business days.",
        "New features have been added to your account. Check them out!",
        "Your subscription gives you access to premium content and features.",
        "Technical maintenance is scheduled for this weekend. Minimal disruption expected.",
        "Your loyalty points balance is 2,500 points. Redeem them for rewards!",
        
        # Educational/informational
        "This month's industry insights and trends report is now available.",
        "Join our free webinar on digital marketing strategies next week.",
        "New course materials have been uploaded to the learning platform.",
        "Your certificate of completion is ready for download.",
        "Upcoming training session: Advanced Excel techniques for professionals.",
        "Monthly newsletter: Product updates and company news.",
        "Workshop reminder: Leadership skills development tomorrow at 10 AM.",
        "New research paper published in our journal. Access it online.",
        "Conference proceedings are now available for all attendees.",
        "Free resource: Best practices guide for project management.",
        
        # Healthcare/appointments
        "Appointment reminder: Your checkup is scheduled for Monday at 9 AM.",
        "Test results are available in your patient portal.",
        "Annual screening reminder: Please schedule your appointment.",
        "Your prescription refill is ready for pickup at the pharmacy.",
        "Health insurance: Your claim has been processed successfully.",
        "Vaccination reminder: Flu shots are now available.",
        "Wellness tip of the week: Stay hydrated during summer months.",
        "Your medical records have been updated in our system.",
        "New patient portal features make it easier to manage your health.",
        "Appointment confirmation: Dr. Smith will see you next Tuesday.",
        
        # Banking/financial (legitimate)
        "Your monthly bank statement is now available online.",
        "Direct deposit has been set up successfully for your account.",
        "Your loan application is being processed. We'll contact you soon.",
        "Credit card payment received. Thank you for your prompt payment.",
        "Your savings account has earned $15.67 in interest this month.",
        "New mobile banking features are now available in our app.",
        "Your automatic bill pay has been set up for your utilities.",
        "Investment portfolio summary for Q3 is now available.",
        "Your credit score has increased by 12 points this month.",
        "Mortgage payment reminder: Payment due on the 1st of each month."
    ]
    
    # Create the dataset
    all_emails = clear_phishing + legitimate_emails
    all_labels = [1] * len(clear_phishing) + [0] * len(legitimate_emails)
    
    df = pd.DataFrame({
        'email': all_emails,
        'label': all_labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"Created phishing dataset with {len(df)} emails:")
    logger.info(f"  - Phishing emails: {len(clear_phishing)}")
    logger.info(f"  - Legitimate emails: {len(legitimate_emails)}")
    
    return df

def main():
    """Create and save the phishing dataset"""
    df = create_comprehensive_phishing_dataset()
    
    # Save the dataset
    df.to_csv('phishing_detection_dataset.csv', index=False)
    logger.info("Phishing dataset saved to 'phishing_detection_dataset.csv'")
    
    # Show some examples
    print("\n=== PHISHING EXAMPLES ===")
    phishing_examples = df[df['label'] == 1]['email'].head(10)
    for i, email in enumerate(phishing_examples, 1):
        print(f"{i}. {email}")
    
    print("\n=== LEGITIMATE EXAMPLES ===")
    legitimate_examples = df[df['label'] == 0]['email'].head(10)
    for i, email in enumerate(legitimate_examples, 1):
        print(f"{i}. {email}")
    
    return df

if __name__ == "__main__":
    main()