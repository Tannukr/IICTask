import random
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

# Email Configuration
SENDER_EMAIL = "krishn20114@gmail.com"
SENDER_PASSWORD = "wtmtzalvsjqqhyxh"

# Store OTPs temporarily (in production, use Redis or similar)
otp_store = {}

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    """Store OTP with expiry time"""
    otp_store[email] = {
        'otp': otp,
        'expiry': datetime.utcnow() + timedelta(minutes=10)
    }

def verify_otp(email, otp):
    """Verify OTP and check if it's expired"""
    if email in otp_store:
        stored_data = otp_store[email]
        if datetime.utcnow() <= stored_data['expiry']:
            if stored_data['otp'] == otp:
                del otp_store[email]  # Clear used OTP
                return True
    return False

def send_otp_email(recipient_email, otp, sender_email=None):
    """Send OTP via email"""
    # Use provided sender email or default
    from_email = sender_email if sender_email else SENDER_EMAIL
    
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = recipient_email
    msg['Subject'] = "Your TaskMaster OTP"

    # Create the email body
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #1e3c72; text-align: center;">TaskMaster OTP Verification</h2>
                <p>Hello,</p>
                <p>Your OTP for TaskMaster registration is:</p>
                <div style="background-color: #f4f4f4; padding: 20px; margin: 20px 0; border-radius: 5px; text-align: center;">
                    <h1 style="color: #1e3c72; margin: 0; font-size: 32px; letter-spacing: 5px;">{otp}</h1>
                </div>
                <p>This OTP will expire in 10 minutes.</p>
                <p>If you didn't request this OTP, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="text-align: center; color: #666; font-size: 12px;">
                    This is an automated message, please do not reply.
                </p>
            </div>
        </body>
    </html>
    """

    msg.attach(MIMEText(body, 'html'))

    try:
        print(f"Attempting to send OTP email to {recipient_email} from {from_email}")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.set_debuglevel(1)  # Enable debug output
        server.starttls()
        print("TLS connection established")
        server.login(from_email, SENDER_PASSWORD)
        print("Login successful")
        server.send_message(msg)
        print("Message sent successfully")
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication failed: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False 