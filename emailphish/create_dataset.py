import pandas as pd
import os
import random
from datetime import datetime, timedelta

def generate_comprehensive_dataset(num_samples=200):
    """
    Generates a comprehensive phishing and safe email dataset with realistic patterns.
    
    Args:
        num_samples: Number of email samples to generate (default: 200)
    
    Returns:
        DataFrame containing the generated dataset
    """
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    # Common email components
    companies = ['Amazon', 'PayPal', 'Netflix', 'Microsoft', 'Google', 'Apple', 'Facebook', 
                'Bank of America', 'Chase', 'LinkedIn', 'Twitter', 'Dropbox', 'Zoom', 'DocuSign']
    
    business_names = ['Acme Corp', 'Globex Industries', 'Initech', 'Stark Enterprises', 
                     'Wayne Enterprises', 'Dunder Mifflin', 'Pied Piper', 'Umbrella Corporation']
    
    email_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'aol.com', 
                    'protonmail.com', 'icloud.com', 'company.com']
    
    names = ['John Smith', 'Emily Johnson', 'Michael Williams', 'Jessica Brown', 'Christopher Jones',
            'Ashley Davis', 'Matthew Miller', 'Amanda Wilson', 'David Moore', 'Sarah Taylor',
            'James Anderson', 'Jennifer Thomas', 'Robert Jackson', 'Lisa White', 'Daniel Harris']
    
    # Phishing patterns
    phishing_subjects = [
        "URGENT: Your account has been compromised",
        "Your {company} account will be suspended",
        "Payment declined - immediate action required",
        "Verify your identity now",
        "You've received a secure document",
        "Your package could not be delivered",
        "Unusual sign-in activity detected",
        "Important security alert for your account",
        "{company} refund notification",
        "Your invoice #INV-{invoice_num}",
        "Your password will expire today",
        "🔴 ATTENTION: Account suspension notice",
        "Claim your reward now",
        "You have won the {company} monthly lottery",
        "Unclaimed funds in your name",
        "FINAL NOTICE: Action required within 24 hours",
        "Congratulations! You've been selected for our survey",
        "Security breach - password reset required immediately",
        "Your tax refund is ready (reference #{ref_num})",
        "Verify your banking details"
    ]
    
    phishing_bodies = [
        """Dear Valued Customer,
        
We have detected unusual activity on your {company} account. To secure your account, please verify your information immediately by clicking the link below:
        
{phishing_link}
        
If you do not verify your account within 24 hours, your account will be permanently suspended.
        
Thank you,
{company} Security Team""",
        
        """ATTENTION {company} USER:
        
Your account has been temporarily limited due to suspicious login attempts. To restore full access to your account, please confirm your identity by providing your login details here:
        
{phishing_link}
        
This is an automated message, please do not reply.
        
{company} Security Department""",
        
        """Dear Customer,
        
We were unable to process your recent payment of ${amount}.00 for your {company} subscription due to insufficient information.
        
To update your payment information and avoid service interruption:
{phishing_link}
        
Kind regards,
{company} Billing Team""",
        
        """NOTIFICATION: We've detected a new device sign-in to your account from {location}.
        
If this wasn't you, your account may be compromised.
        
Secure your account now: {phishing_link}
        
Regards,
{company} Security""",
        
        """Your {company} package #{tracking_num} could not be delivered due to an address error.
        
Update delivery preferences here: {phishing_link}
        
The delivery will be returned to our warehouse if no action is taken within 3 business days.""",
        
        """Dear {name},
        
You have (1) unclaimed reward from {company} valued at ${amount}.00!
        
Your reward will expire on: {expiry_date}
        
CLAIM NOW: {phishing_link}
        
This message was sent to you because you are registered on our rewards program.""",
        
        """URGENT TAX REFUND NOTIFICATION
        
Due to an error in calculation, you are eligible for a tax refund of ${amount}.00.
        
To claim your refund, please verify your details within the next 48 hours:
        
{phishing_link}
        
Internal Revenue Reference: TAX-{ref_num}""",
        
        """Dear {company} customer,
        
We have updated our security systems and require all users to reset their passwords.
        
Please click the link below to create a new password:
        
{phishing_link}
        
Your account access will be limited until this process is completed.
        
{company} IT Department""",
        
        """FINAL NOTICE: Your {company} account will be deactivated today.
        
Our systems show you haven't verified your account information as requested in our previous emails.
        
Last chance to keep your account active:
{phishing_link}
        
This process takes only 2 minutes to complete.""",
        
        """Congratulations {name}!
        
You've been randomly selected to participate in our monthly customer survey.
        
Complete the 5-minute survey and receive a ${amount} gift card!
        
START SURVEY: {phishing_link}
        
Thank you for being a valued {company} customer."""
    ]
    
    # Safe email patterns
    safe_subjects = [
        "Your {company} receipt",
        "Meeting agenda for tomorrow",
        "Project update: {project_name}",
        "Thanks for your purchase",
        "Your monthly newsletter",
        "Invitation: Team lunch next Friday",
        "Document shared with you: {doc_name}",
        "Your flight confirmation #{confirmation_code}",
        "Reminder: Appointment on {date}",
        "Welcome to {company}!",
        "Your subscription has been renewed",
        "Feedback request for recent service",
        "Important: System maintenance scheduled",
        "Your {company} statement is available",
        "{company} - New features announcement",
        "Your order #{order_num} has shipped",
        "Password changed successfully",
        "Weekly team update",
        "Holiday schedule announcement",
        "Action required: Complete your profile"
    ]
    
    safe_bodies = [
        """Hi {name},
        
Just confirming our meeting tomorrow at {time}. Here's the agenda:

1. Project status updates (15 min)
2. Budget review (10 min)
3. Timeline adjustments (15 min)
4. Open discussion (20 min)

The meeting room has been booked and I've attached the latest project report for your review.

Let me know if you need anything else before tomorrow.

Best regards,
{sender_name}""",
        
        """Dear {name},
        
Thank you for your recent purchase from {company}. We've processed your order #{order_num} and it will be shipped within 2 business days.

Order Summary:
- Order Date: {date}
- Order Total: ${amount}.00
- Shipping Address: Your registered address
- Estimated Delivery: {delivery_date}

You can track your package using our website or mobile app once it ships.

If you have any questions about your order, please contact our customer service team at support@{company_domain}.com.

Thank you for shopping with us!

{company} Customer Service Team""",
        
        """Hello {name},
        
This is a friendly reminder about your appointment scheduled for:

Date: {date}
Time: {time}
Location: {location}

Please arrive 10 minutes early to complete any necessary paperwork. If you need to reschedule, please call us at (555) 123-4567 at least 24 hours in advance.

We look forward to seeing you!

Best regards,
{business_name} Team""",
        
        """Dear {company} Customer,
        
Your monthly statement for account ending in {account_last_digits} is now available online.

Statement Period: {statement_start} - {statement_end}
Available Balance: ${balance}

To view your complete statement, please log in to your account at www.{company_domain}.com.

Thank you for choosing {company}.

This is an automated message, please do not reply.""",
        
        """Hi Team,
        
Here's our weekly update for {project_name}:

Completed:
- Finalized design mockups
- Completed user testing for phase 1
- Updated documentation

In Progress:
- Backend integration (80% complete)
- Security audit
- Performance optimization

Blockers:
- None currently

Upcoming deadlines:
- Phase 2 launch: {deadline_date}

Please review and let me know if you have any questions during our standup tomorrow.

Best,
{sender_name}""",
        
        """Dear {name},
        
We're excited to announce some new features that have been added to your {company} account:

1. Enhanced dashboard with customizable widgets
2. Improved reporting tools with export options
3. New mobile app features for on-the-go access
4. Increased storage capacity at no additional cost

These updates are now available when you log in to your account.

For a detailed overview of these new features, visit our blog at www.{company_domain}.com/blog.

We hope you enjoy these improvements!

The {company} Team""",
        
        """Hello {name},
        
Good news! Your order #{order_num} has shipped and is on its way to you.

Tracking Number: {tracking_num}
Estimated Delivery: {delivery_date}

You can track your package's progress here: www.{company_domain}.com/track

If you have any questions, our customer support team is available 24/7.

Thank you for shopping with {company}!

Best regards,
{company} Shipping Team""",
        
        """Dear {name},
        
Welcome to {company}! We're thrilled to have you join our community.

Your account has been successfully created and is ready to use. Here's how to get started:

1. Complete your profile
2. Explore our features
3. Download our mobile app for on-the-go access

If you have any questions, check out our FAQ section or contact our support team at help@{company_domain}.com.

We're looking forward to helping you achieve great things with {company}!

Best regards,
The {company} Team""",
        
        """Hi {name},
        
We wanted to inform you about scheduled maintenance on our systems.

Date: {date}
Time: {time} - {end_time} (approximately 2 hours)
Impact: The {company} platform will be temporarily unavailable during this period

This maintenance is necessary to implement important security updates and performance improvements.

We apologize for any inconvenience this may cause and appreciate your understanding.

Thank you,
{company} IT Department""",
        
        """Dear {company} Customer,
        
Thank you for contacting our support team regarding your recent inquiry (Case #{case_num}).

As discussed, we've resolved the issue with your account settings. The changes have been applied and should take effect immediately.

If you encounter any further issues or have additional questions, please don't hesitate to reach out to us by replying to this email or calling our customer service line.

We appreciate your patience and are happy to have resolved this matter for you.

Best regards,
{sender_name}
Customer Support Representative
{company}"""
    ]
    
    # Generate random components for templating
    def random_amount():
        return random.randint(50, 5000)
    
    def random_date():
        days = random.randint(1, 30)
        future_date = datetime.now() + timedelta(days=days)
        return future_date.strftime("%B %d, %Y")
    
    def random_time():
        hour = random.randint(9, 17)
        minute = random.choice([0, 15, 30, 45])
        return f"{hour}:{minute:02d} {'AM' if hour < 12 else 'PM'}"
    
    def random_end_time(start_time):
        start_hour = int(start_time.split(':')[0])
        end_hour = min(start_hour + 2, 18)
        minute = random.choice([0, 15, 30, 45])
        return f"{end_hour}:{minute:02d} {'AM' if end_hour < 12 else 'PM'}"
    
    def random_phishing_link():
        company = random.choice(companies).lower()
        domains = [
            f"secure-{company}.com",
            f"{company}-verify.net",
            f"account-{company}.org",
            f"{company}-security.info",
            f"login-{company}.co",
            f"{company}-support.net",
            f"verify-{company}-account.com"
        ]
        return f"http://{random.choice(domains)}/verify?id={random.randint(100000, 999999)}"
    
    def random_project_name():
        adjectives = ["Global", "Digital", "Smart", "Agile", "Strategic", "Advanced", "Innovative"]
        nouns = ["Transformation", "Initiative", "Platform", "Solution", "Framework", "System", "Deployment"]
        return f"{random.choice(adjectives)} {random.choice(nouns)}"
    
    def random_doc_name():
        prefixes = ["Project", "Report", "Analysis", "Proposal", "Plan", "Budget", "Strategy"]
        suffixes = ["Overview", "Details", "Summary", "Update", "Review", "2025", "Final"]
        return f"{random.choice(prefixes)} {random.choice(suffixes)}"
    
    def random_confirmation_code():
        letters = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ', k=2))
        numbers = ''.join(random.choices('0123456789', k=4))
        return f"{letters}{numbers}"
    
    def random_order_num():
        return ''.join(random.choices('0123456789', k=7))
    
    def random_tracking_num():
        prefix = random.choice(['TRK', 'SHP', 'PKG'])
        numbers = ''.join(random.choices('0123456789', k=10))
        return f"{prefix}{numbers}"
    
    def random_location():
        cities = ["New York, NY", "Los Angeles, CA", "Chicago, IL", "Houston, TX", "Phoenix, AZ", 
                 "Philadelphia, PA", "San Antonio, TX", "San Diego, CA", "Dallas, TX", "Mumbai, India", 
                 "London, UK", "Tokyo, Japan", "Berlin, Germany", "Sydney, Australia"]
        devices = ["iPhone", "Android Device", "Windows PC", "MacBook", "Unknown Device", "iPad", "New Browser"]
        return f"{random.choice(devices)} in {random.choice(cities)}"
    
    def random_account_digits():
        return ''.join(random.choices('0123456789', k=4))
    
    def random_balance():
        return round(random.uniform(1000, 10000), 2)
    
    def random_statement_period():
        end_date = datetime.now() - timedelta(days=random.randint(1, 10))
        start_date = end_date - timedelta(days=30)
        return (start_date.strftime("%B %d"), end_date.strftime("%B %d, %Y"))
    
    def random_case_num():
        return ''.join(random.choices('0123456789', k=8))
    
    def random_ref_num():
        return ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
    
    def random_invoice_num():
        return ''.join(random.choices('0123456789', k=6))
    
    # Generate the dataset
    emails = []
    for _ in range(num_samples // 2):
        # Generate a phishing email
        company = random.choice(companies)
        name = random.choice(names)
        
        subject_template = random.choice(phishing_subjects)
        body_template = random.choice(phishing_bodies)
        
        # Fill in templates with random data
        subject = subject_template.format(
            company=company,
            invoice_num=random_invoice_num(),
            ref_num=random_ref_num()
        )
        
        body = body_template.format(
            company=company,
            name=name,
            phishing_link=random_phishing_link(),
            amount=random_amount(),
            expiry_date=random_date(),
            location=random_location(),
            tracking_num=random_tracking_num(),
            ref_num=random_ref_num()
        )
        
        emails.append({
            'Email Text': f"Subject: {subject}\n\n{body}",
            'Email Type': 'Phishing Email'
        })
        
        # Generate a safe email
        company = random.choice(companies)
        name = random.choice(names)
        sender_name = random.choice(names)
        business_name = random.choice(business_names)
        company_domain = f"{company.lower().replace(' ', '')}.com"
        
        subject_template = random.choice(safe_subjects)
        body_template = random.choice(safe_bodies)
        
        date = random_date()
        time = random_time()
        end_time = random_end_time(time)
        statement_start, statement_end = random_statement_period()
        
        subject = subject_template.format(
            company=company,
            project_name=random_project_name(),
            doc_name=random_doc_name(),
            confirmation_code=random_confirmation_code(),
            date=date,
            order_num=random_order_num()
        )
        
        body = body_template.format(
            name=name,
            company=company,
            company_domain=company_domain,
            sender_name=sender_name,
            business_name=business_name,
            date=date,
            time=time,
            end_time=end_time,
            location=random_location(),
            project_name=random_project_name(),
            deadline_date=random_date(),
            order_num=random_order_num(),
            tracking_num=random_tracking_num(),
            delivery_date=random_date(),
            amount=random_amount(),
            account_last_digits=random_account_digits(),
            balance=random_balance(),
            statement_start=statement_start,
            statement_end=statement_end,
            case_num=random_case_num()
        )
        
        emails.append({
            'Email Text': f"Subject: {subject}\n\n{body}",
            'Email Type': 'Safe Email'
        })
    
    # Create DataFrame and shuffle the rows
    df = pd.DataFrame(emails)
    df = df.sample(frac=1).reset_index(drop=True)  # Shuffle the dataset
    
    # Save to CSV
    output_path = 'data/emails.csv'
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} email samples ({len(df)//2} phishing, {len(df)//2} safe)")
    print(f"Dataset saved to {output_path}")
    
    # Print a few examples
    print("\nSample phishing email:")
    phish_sample = df[df['Email Type'] == 'Phishing Email'].iloc[0]
    print(phish_sample['Email Text'])
    
    print("\nSample safe email:")
    safe_sample = df[df['Email Type'] == 'Safe Email'].iloc[0]
    print(safe_sample['Email Text'])
    
    return df

if __name__ == "__main__":
    # Generate a dataset with 200 samples (100 phishing, 100 safe)
    generate_comprehensive_dataset(200)