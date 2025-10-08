#!/usr/bin/env python3
"""
Test script to demonstrate improvements in the refactored phishing detection system
"""

import sys
import os
sys.path.append('backend')

# Test emails that should NOT be flagged as phishing
LEGITIMATE_TEST_EMAILS = [
    # Zomato order confirmation
    """
    From: orders@zomato.com
    Subject: Your Zomato order #12345 is confirmed
    
    Hi John,
    
    Thank you for your order from Pizza Palace. Your order for 2x Margherita Pizza has been confirmed.
    
    Order Details:
    - Order ID: 12345
    - Total: ₹599
    - Delivery Address: Your saved address
    - Expected delivery time: 45 minutes
    
    You can track your order in the Zomato app.
    
    Best regards,
    Zomato Team
    """,
    
    # Zepto delivery update
    """
    From: support@zepto.com
    Subject: Your Zepto order is out for delivery
    
    Dear Customer,
    
    Your order #ZPT67890 is now out for delivery and will reach you shortly.
    
    Items ordered:
    - Milk (1L) - ₹60
    - Bread (Brown) - ₹45
    - Total: ₹105
    
    Our delivery partner will contact you shortly.
    
    Thanks for shopping with Zepto!
    Zepto Team
    """,
    
    # PayTM payment receipt
    """
    From: noreply@paytm.com
    Subject: Payment successful - Transaction ID: TXN123456789
    
    Hi,
    
    Your payment of ₹1,500 to Amazon India has been successful.
    
    Transaction Details:
    - Amount: ₹1,500
    - Date: Today
    - Transaction ID: TXN123456789
    - Payment Method: Paytm Wallet
    
    Thank you for using Paytm.
    
    Team Paytm
    """,
    
    # HDFC Bank statement
    """
    From: alerts@hdfcbank.com
    Subject: Account Statement - Savings Account ****1234
    
    Dear Customer,
    
    Your monthly account statement for Savings Account ending with 1234 is now available.
    
    Account Summary:
    - Opening Balance: ₹50,000
    - Closing Balance: ₹48,500
    - Total Credits: ₹15,000
    - Total Debits: ₹16,500
    
    You can download your statement from HDFC NetBanking.
    
    Regards,
    HDFC Bank
    """
]

# Test emails that SHOULD be flagged as phishing
PHISHING_TEST_EMAILS = [
    # Fake urgent account suspension
    """
    From: security@amaz0n-verify.com
    Subject: URGENT: Your Amazon account will be suspended
    
    Dear Customer,
    
    We detected suspicious activity on your Amazon account. Your account will be suspended within 24 hours unless you verify your identity immediately.
    
    Click here to verify: http://secure-amazon-verify.tk/login
    
    This is an automated message, please do not reply.
    
    Amazon Security Team
    """,
    
    # Fake prize notification
    """
    From: winner@lottery-notification.info
    Subject: Congratulations! You've won $50,000
    
    Dear Winner,
    
    You have been selected as the lucky winner of our monthly lottery draw. You have won $50,000!
    
    To claim your prize immediately, click here: http://claim-prize.xyz/winner
    
    Reference Number: WIN123456
    Expires in 48 hours.
    
    Lottery Commission
    """,
    
    # Fake banking alert
    """
    From: alerts@hdfc-security.net
    Subject: Security Alert: Unusual login detected
    
    Dear Customer,
    
    We detected a login from an unusual location. If this wasn't you, your account may be compromised.
    
    Secure your account immediately: http://hdfc-secure-login.club/verify
    
    Enter your login details to confirm your identity.
    
    HDFC Bank Security
    """
]

def test_email_classification(email_content: str, expected_result: str, description: str):
    """Test a single email and print results"""
    print(f"\n{'='*60}")
    print(f"Test: {description}")
    print(f"Expected: {expected_result}")
    print(f"{'='*60}")
    print(f"Email content (first 200 chars):")
    print(email_content[:200].strip() + "...")
    
    # Here you would call your API or model
    # For demonstration, we'll just extract key info
    
    # Check if it's from a legitimate domain
    from app_refactored import is_legitimate_sender, extract_domain_from_email
    
    is_legit, reason = is_legitimate_sender(email_content)
    domains = extract_domain_from_email(email_content)
    
    print(f"\nExtracted domains: {domains}")
    print(f"Legitimate sender: {is_legit}")
    print(f"Reason: {reason}")
    
    return is_legit

def main():
    print("🔍 Testing Enhanced Phishing Detection System")
    print("Demonstrating improvements in handling legitimate emails")
    
    print("\n" + "🟢 TESTING LEGITIMATE EMAILS (Should NOT be flagged)" + "\n")
    
    legitimate_correct = 0
    for i, email in enumerate(LEGITIMATE_TEST_EMAILS, 1):
        is_legit = test_email_classification(
            email, 
            "Safe Email", 
            f"Legitimate Email {i}"
        )
        if is_legit:
            legitimate_correct += 1
            print("✅ CORRECT: Identified as legitimate")
        else:
            print("❌ WRONG: Falsely flagged as suspicious")
    
    print("\n" + "🔴 TESTING PHISHING EMAILS (Should BE flagged)" + "\n")
    
    phishing_correct = 0
    for i, email in enumerate(PHISHING_TEST_EMAILS, 1):
        is_legit = test_email_classification(
            email, 
            "Phishing Email", 
            f"Phishing Email {i}"
        )
        if not is_legit:
            phishing_correct += 1
            print("✅ CORRECT: Identified as suspicious")
        else:
            print("❌ WRONG: Missed phishing attempt")
    
    print(f"\n{'='*60}")
    print("📊 RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Legitimate emails correctly identified: {legitimate_correct}/{len(LEGITIMATE_TEST_EMAILS)}")
    print(f"Phishing emails correctly identified: {phishing_correct}/{len(PHISHING_TEST_EMAILS)}")
    
    total_correct = legitimate_correct + phishing_correct
    total_emails = len(LEGITIMATE_TEST_EMAILS) + len(PHISHING_TEST_EMAILS)
    accuracy = (total_correct / total_emails) * 100
    
    print(f"Overall accuracy: {accuracy:.1f}%")
    
    print(f"\n🎯 KEY IMPROVEMENTS:")
    print("1. ✅ Whitelist of 50+ legitimate domains (Zomato, Zepto, PayTM, etc.)")
    print("2. ✅ Context-aware pattern matching")
    print("3. ✅ Reduced false positives for business communications")
    print("4. ✅ Enhanced confidence scoring")
    print("5. ✅ Separate legitimacy check endpoint")

if __name__ == "__main__":
    main()