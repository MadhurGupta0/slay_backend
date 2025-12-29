"""
Mobile App Backend API - Email Verification & Authentication
Flask-based backend API for iOS/Android mobile applications
- Email verification with Resend API
- Passwordless authentication (OTP + Passkeys/WebAuthn)
- User registration and management
- Passkey support for iOS (ASAuthorizationController) and Android (Fido2ApiClient)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import os
import random
import string
import re
from datetime import datetime, timedelta
from typing import Optional
import threading
import requests
import base64
import json
import secrets
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://drepvbrhkxzwtwqncnyd.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRyZXB2YnJoa3h6d3R3cW5jbnlkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjkzOTczMjQsImV4cCI6MjA0NDk3MzMyNH0.OJCaAJBAxZfrydgUfm1A_ECFL3uCOmYX33rjCETcNQw")

# Validate Supabase configuration
if not SUPABASE_URL or not SUPABASE_KEY:
    print("⚠️  WARNING: SUPABASE_URL or SUPABASE_KEY not set in environment variables")
    print("Please set them in your .env file")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Resend Configuration
RESEND_API_KEY ="re_VgndXmD1_GVpJezaQpNZU4M3B3uAnJ6XV"
FROM_EMAIL =  "onboarding@slay.money"  # Default Resend test email

# WebAuthn/Passkey Configuration for Mobile Apps
# RP_ID: Relying Party ID - domain or app identifier (for mobile: bundle ID/package name)
RP_ID = os.getenv("RP_ID", "slay.money")  # Relying Party ID (domain or app identifier)
RP_NAME = os.getenv("RP_NAME", "Slay Money")  # Relying Party Name
# ORIGIN: Origin for WebAuthn verification (mobile apps use bundle ID/package name)
ORIGIN = os.getenv("ORIGIN", "https://slay.money")  # Origin for WebAuthn (mobile app origin)

# Helper Functions
def generate_verification_code(length: int = 6) -> str:
    """Generate a random numeric verification code"""
    return ''.join(random.choices(string.digits, k=length))

def remove_ellipsis(obj):
    """Recursively remove Ellipsis objects and convert non-JSON-serializable types to JSON-serializable formats"""
    if isinstance(obj, dict):
        return {k: remove_ellipsis(v) for k, v in obj.items() if v is not ...}
    elif isinstance(obj, (list, tuple)):
        # Convert lists and tuples, filtering out Ellipsis objects
        return [remove_ellipsis(item) for item in obj if item is not ...]
    elif isinstance(obj, set):
        # Convert sets to lists for JSON serialization
        return [remove_ellipsis(item) for item in obj if item is not ...]
    elif isinstance(obj, bytes):
        # Convert bytes to base64 URL-safe string for JSON serialization (WebAuthn uses URL-safe base64)
        return base64.urlsafe_b64encode(obj).decode('utf-8').rstrip('=')
    elif obj is ...:
        return None
    elif hasattr(obj, 'model_dump'):
        # Handle Pydantic v2 models
        try:
            return remove_ellipsis(obj.model_dump(mode='json'))
        except (TypeError, AttributeError):
            try:
                return remove_ellipsis(obj.model_dump())
            except (TypeError, AttributeError):
                # Fallback: try to get dict representation
                return remove_ellipsis(obj.__dict__ if hasattr(obj, '__dict__') else str(obj))
    elif hasattr(obj, 'dict'):
        # Handle Pydantic v1 models
        try:
            return remove_ellipsis(obj.dict())
        except (TypeError, AttributeError):
            return remove_ellipsis(obj.__dict__ if hasattr(obj, '__dict__') else str(obj))
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        # Handle other objects with __dict__ attribute (but not basic types)
        try:
            # Try to convert to dict
            obj_dict = {k: remove_ellipsis(v) for k, v in obj.__dict__.items()}
            return obj_dict
        except (TypeError, AttributeError):
            # If that fails, convert to string representation
            return str(obj)
    else:
        return obj

def send_verification_email_resend(email: str, code: str, full_name: Optional[str] = None):
    """
    Send verification email using Resend API
    """
    try:
        if not RESEND_API_KEY:
            raise ValueError("RESEND_API_KEY not configured. Please add it to your .env file")
        
        # Email HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .email-container {{
                    max-width: 600px;
                    margin: 40px auto;
                    background-color: #ffffff;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    font-size: 16px;
                    opacity: 0.9;
                }}
                .content {{
                    padding: 40px 30px;
                }}
                .greeting {{
                    font-size: 20px;
                    font-weight: 600;
                    color: #1a1a1a;
                    margin: 0 0 20px 0;
                }}
                .message {{
                    font-size: 16px;
                    color: #4a5568;
                    margin: 0 0 30px 0;
                    line-height: 1.8;
                }}
                .code-container {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 12px;
                    padding: 30px;
                    text-align: center;
                    margin: 30px 0;
                }}
                .code-label {{
                    color: white;
                    font-size: 14px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin: 0 0 15px 0;
                }}
                .code-box {{
                    background-color: white;
                    border-radius: 8px;
                    padding: 20px;
                    font-size: 42px;
                    font-weight: bold;
                    letter-spacing: 12px;
                    color: #667eea;
                    font-family: 'Courier New', monospace;
                }}
                .expiry-notice {{
                    background-color: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 15px 20px;
                    margin: 30px 0;
                    border-radius: 4px;
                }}
                .expiry-notice p {{
                    margin: 0;
                    color: #92400e;
                    font-size: 14px;
                }}
                .expiry-notice strong {{
                    color: #78350f;
                }}
                .security-note {{
                    background-color: #f3f4f6;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 30px 0;
                }}
                .security-note p {{
                    margin: 0;
                    font-size: 14px;
                    color: #6b7280;
                }}
                .footer {{
                    text-align: center;
                    padding: 30px;
                    background-color: #f9fafb;
                    border-top: 1px solid #e5e7eb;
                }}
                .footer p {{
                    margin: 5px 0;
                    color: #6b7280;
                    font-size: 13px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background-color: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: 600;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <h1>🔐 Email Verification</h1>
                    <p>Secure your account in seconds</p>
                </div>
                
                <div class="content">
                    <p class="greeting">Hello {full_name or 'there'}! 👋</p>
                    
                    <p class="message">
                        Thank you for registering! To complete your registration and secure your account, 
                        please verify your email address using the code below.
                    </p>
                    
                    <div class="code-container">
                        <p class="code-label">Your Verification Code</p>
                        <div class="code-box">{code}</div>
                    </div>
                    
                    <div class="expiry-notice">
                        <p>
                            ⏰ <strong>Important:</strong> This code will expire in <strong>15 minutes</strong>. 
                            If it expires, you can request a new one.
                        </p>
                    </div>
                    
                    <p class="message">
                        Enter this code in the verification page to activate your account and get started.
                    </p>
                    
                    <div class="security-note">
                        <p>
                            🔒 <strong>Security Tip:</strong> If you didn't request this verification code, 
                            please ignore this email. Your account is safe and no action is required.
                        </p>
                    </div>
                </div>
                
                <div class="footer">
                    <p><strong>Need Help?</strong></p>
                    <p>If you have any questions, feel free to contact our support team.</p>
                    <p style="margin-top: 20px;">&copy; 2024 Your Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version for email clients that don't support HTML
        text_content = f"""
        Hello {full_name or 'there'}!
        
        Thank you for registering! Please verify your email address using the code below:
        
        Verification Code: {code}
        
        This code will expire in 15 minutes.
        
        If you didn't request this verification, please ignore this email.
        
        © 2024 Your Company. All rights reserved.
        """
        
        # Send email via Resend API
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {RESEND_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'from': FROM_EMAIL,
                'to': [email],
                'subject': f'Your Verification Code: {code}',
                'html': html_content,
                'text': text_content
            },
            timeout=10
        )
        
        if response.status_code == 200:
            response_data = response.json()
            email_id = response_data.get('id', 'unknown')
            print(f"✅ Email sent successfully via Resend to {email} (ID: {email_id})")
            return True
        else:
            error_message = response.text
            print(f"❌ Resend API Error: {response.status_code} - {error_message}")
            raise Exception(f"Resend API Error: {response.status_code} - {error_message}")
            
    except requests.exceptions.Timeout:
        print(f"❌ Resend API Timeout while sending to {email}")
        raise Exception("Email service timeout. Please try again.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Resend API Request Error: {str(e)}")
        raise Exception(f"Failed to connect to email service: {str(e)}")
    except Exception as e:
        print(f"❌ Resend Error: {str(e)}")
        raise Exception(f"Email sending failed: {str(e)}")

def send_login_otp_email_resend(email: str, code: str, full_name: Optional[str] = None):
    """
    Send login OTP email using Resend API
    """
    try:
        if not RESEND_API_KEY:
            raise ValueError("RESEND_API_KEY not configured. Please add it to your .env file")
        
        # Email HTML template for login
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .email-container {{
                    max-width: 600px;
                    margin: 40px auto;
                    background-color: #ffffff;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    font-size: 16px;
                    opacity: 0.9;
                }}
                .content {{
                    padding: 40px 30px;
                }}
                .greeting {{
                    font-size: 20px;
                    font-weight: 600;
                    color: #1a1a1a;
                    margin: 0 0 20px 0;
                }}
                .message {{
                    font-size: 16px;
                    color: #4a5568;
                    margin: 0 0 30px 0;
                    line-height: 1.8;
                }}
                .code-container {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 12px;
                    padding: 30px;
                    text-align: center;
                    margin: 30px 0;
                }}
                .code-label {{
                    color: white;
                    font-size: 14px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin: 0 0 15px 0;
                }}
                .code-box {{
                    background-color: white;
                    border-radius: 8px;
                    padding: 20px;
                    font-size: 42px;
                    font-weight: bold;
                    letter-spacing: 12px;
                    color: #667eea;
                    font-family: 'Courier New', monospace;
                }}
                .expiry-notice {{
                    background-color: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 15px 20px;
                    margin: 30px 0;
                    border-radius: 4px;
                }}
                .expiry-notice p {{
                    margin: 0;
                    color: #92400e;
                    font-size: 14px;
                }}
                .expiry-notice strong {{
                    color: #78350f;
                }}
                .security-note {{
                    background-color: #f3f4f6;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 30px 0;
                }}
                .security-note p {{
                    margin: 0;
                    font-size: 14px;
                    color: #6b7280;
                }}
                .footer {{
                    text-align: center;
                    padding: 30px;
                    background-color: #f9fafb;
                    border-top: 1px solid #e5e7eb;
                }}
                .footer p {{
                    margin: 5px 0;
                    color: #6b7280;
                    font-size: 13px;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <h1>🔑 Login Verification</h1>
                    <p>Secure access to your account</p>
                </div>
                
                <div class="content">
                    <p class="greeting">Hello {full_name or 'there'}! 👋</p>
                    
                    <p class="message">
                        We received a login request for your account. Use the code below to complete your login.
                    </p>
                    
                    <div class="code-container">
                        <p class="code-label">Your Login Code</p>
                        <div class="code-box">{code}</div>
                    </div>
                    
                    <div class="expiry-notice">
                        <p>
                            ⏰ <strong>Important:</strong> This code will expire in <strong>15 minutes</strong>. 
                            If it expires, you can request a new one.
                        </p>
                    </div>
                    
                    <p class="message">
                        Enter this code on the login page to access your account.
                    </p>
                    
                    <div class="security-note">
                        <p>
                            🔒 <strong>Security Tip:</strong> If you didn't request this login code, 
                            please ignore this email and consider changing your password. Your account is safe and no action is required.
                        </p>
                    </div>
                </div>
                
                <div class="footer">
                    <p><strong>Need Help?</strong></p>
                    <p>If you have any questions, feel free to contact our support team.</p>
                    <p style="margin-top: 20px;">&copy; 2024 Your Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version for email clients that don't support HTML
        text_content = f"""
        Hello {full_name or 'there'}!
        
        We received a login request for your account. Use the code below to complete your login:
        
        Login Code: {code}
        
        This code will expire in 15 minutes.
        
        If you didn't request this login code, please ignore this email.
        
        © 2024 Your Company. All rights reserved.
        """
        
        # Send email via Resend API
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {RESEND_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'from': FROM_EMAIL,
                'to': [email],
                'subject': f'Your Login Code: {code}',
                'html': html_content,
                'text': text_content
            },
            timeout=10
        )
        
        if response.status_code == 200:
            response_data = response.json()
            email_id = response_data.get('id', 'unknown')
            print(f"✅ Login OTP email sent successfully via Resend to {email} (ID: {email_id})")
            return True
        else:
            error_message = response.text
            print(f"❌ Resend API Error: {response.status_code} - {error_message}")
            raise Exception(f"Resend API Error: {response.status_code} - {error_message}")
            
    except requests.exceptions.Timeout:
        print(f"❌ Resend API Timeout while sending login OTP to {email}")
        raise Exception("Email service timeout. Please try again.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Resend API Request Error: {str(e)}")
        raise Exception(f"Failed to connect to email service: {str(e)}")
    except Exception as e:
        print(f"❌ Resend Error: {str(e)}")
        raise Exception(f"Email sending failed: {str(e)}")

def send_email_background(email: str, code: str, full_name: Optional[str] = None):
    """Send email in background thread"""
    def send_email_task():
        try:
            send_verification_email_resend(email, code, full_name)
        except Exception as e:
            print(f"Background email error for {email}: {str(e)}")
    
    thread = threading.Thread(target=send_email_task)
    thread.daemon = True
    thread.start()

def send_login_otp_email_background(email: str, code: str, full_name: Optional[str] = None):
    """Send login OTP email in background thread"""
    def send_email_task():
        try:
            send_login_otp_email_resend(email, code, full_name)
        except Exception as e:
            print(f"Background login OTP email error for {email}: {str(e)}")
    
    thread = threading.Thread(target=send_email_task)
    thread.daemon = True
    thread.start()

def validate_email(email: str) -> bool:
    """Basic email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def parse_datetime_string(dt_str: str) -> datetime:
    """
    Parse datetime string from Supabase with various format support
    Handles formats like:
    - '2025-12-16T20:51:14.9658+00:00'
    - '2025-12-16T20:51:14.965800+00:00'
    - '2025-12-16T20:51:14Z'
    - '2025-12-16T20:51:14.965800Z'
    """
    if not dt_str:
        raise ValueError("Empty datetime string")
    
    dt_str_clean = dt_str.strip()
    
    # Handle Z timezone (convert to +00:00)
    if dt_str_clean.endswith('Z'):
        dt_str_clean = dt_str_clean[:-1] + '+00:00'
    
    # Normalize microseconds to 6 digits for consistent parsing
    # Match pattern: YYYY-MM-DDTHH:MM:SS.microseconds+timezone
    pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)([+\-]\d{2}:\d{2}|Z)?'
    match = re.match(pattern, dt_str_clean)
    
    if match:
        base_time = match.group(1)
        microseconds = match.group(2)
        timezone = match.group(3) or '+00:00'
        
        # Normalize microseconds to 6 digits
        if len(microseconds) < 6:
            microseconds = microseconds.ljust(6, '0')
        elif len(microseconds) > 6:
            microseconds = microseconds[:6]
        
        dt_str_clean = f"{base_time}.{microseconds}{timezone}"
    
    try:
        # Parse with fromisoformat
        parsed_dt = datetime.fromisoformat(dt_str_clean)
        
        # Convert to naive UTC datetime for comparison
        if parsed_dt.tzinfo:
            # Convert to UTC and remove timezone info
            parsed_dt = parsed_dt.astimezone(datetime.now().astimezone().tzinfo).replace(tzinfo=None)
        
        return parsed_dt
    except ValueError as e:
        # Fallback: try parsing without timezone
        try:
            # Remove timezone and parse
            dt_str_no_tz = re.sub(r'[+\-]\d{2}:\d{2}$', '', dt_str_clean)
            if dt_str_no_tz.endswith('Z'):
                dt_str_no_tz = dt_str_no_tz[:-1]
            
            # Try to parse the base format
            if '.' in dt_str_no_tz:
                base, micro = dt_str_no_tz.split('.')
                micro = micro[:6].ljust(6, '0')  # Normalize to 6 digits
                dt_str_no_tz = f"{base}.{micro}"
            
            parsed_dt = datetime.fromisoformat(dt_str_no_tz)
            return parsed_dt
        except Exception:
            raise ValueError(f"Unable to parse datetime string: {dt_str} - {str(e)}")

# Passkey/WebAuthn Helper Functions
def generate_challenge() -> str:
    """Generate a random challenge string for WebAuthn"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def store_passkey_credential(email: str, credential_id: str, public_key: bytes, sign_count: int, device_name: Optional[str] = None):
    """
    Store passkey credential in database
    We'll store credentials as JSON in the slay_users table
    """
    try:
        # Get existing user
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            raise ValueError("User not found")
        
        user = user_response.data[0]
        existing_credentials = user.get("passkey_credentials", [])
        
        if not isinstance(existing_credentials, list):
            existing_credentials = []
        
        # Remove any temporary challenge entries (cleanup)
        existing_credentials = [c for c in existing_credentials if not (isinstance(c, dict) and c.get("_temp"))]
        
        # Convert public_key bytes to base64 for storage
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        
        # Add new credential
        new_credential = {
            "credential_id": credential_id,
            "public_key": public_key_b64,
            "sign_count": sign_count,
            "device_name": device_name or "Unknown Device",
            "created_at": datetime.utcnow().isoformat()
        }
        
        existing_credentials.append(new_credential)
        
        # Update user with new credentials
        supabase.table("slay_users").update({
            "passkey_credentials": existing_credentials
        }).eq("email", email).execute()
        
        return True
    except Exception as e:
        print(f"Error storing passkey credential: {str(e)}")
        raise

def get_passkey_credentials(email: str) -> list:
    """Get all passkey credentials for a user"""
    try:
        user_response = supabase.table("slay_users").select("passkey_credentials").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return []
        
        credentials = user_response.data[0].get("passkey_credentials", [])
        if not isinstance(credentials, list):
            return []
        
        # Filter out temporary challenge entries
        return [c for c in credentials if not (isinstance(c, dict) and c.get("_temp"))]
    except Exception as e:
        print(f"Error getting passkey credentials: {str(e)}")
        return []

def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    try:
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return None
        
        return user_response.data[0]
    except Exception as e:
        print(f"Error getting user: {str(e)}")
        return None

def update_sign_count(email: str, credential_id: str, new_sign_count: int):
    """Update the sign count for a passkey credential"""
    try:
        credentials = get_passkey_credentials(email)
        
        for cred in credentials:
            if cred.get("credential_id") == credential_id:
                cred["sign_count"] = new_sign_count
                cred["last_used"] = datetime.utcnow().isoformat()
                break
        
        supabase.table("slay_users").update({
            "passkey_credentials": credentials
        }).eq("email", email).execute()
        
        return True
    except Exception as e:
        print(f"Error updating sign count: {str(e)}")
        raise

def store_webauthn_challenge(email: str, challenge_str: str, expiry_minutes: int = 5):
    """
    Store WebAuthn challenge. Handles both TEXT and VARCHAR(10) column types.
    If verification_code is too short, stores in passkey_credentials JSONB as metadata.
    """
    try:
        # Try storing in verification_code first (works if column is TEXT)
        supabase.table("slay_users").update({
            "verification_code": challenge_str,
            "verification_code_expiry": (datetime.utcnow() + timedelta(minutes=expiry_minutes)).isoformat()
        }).eq("email", email).execute()
        return True
    except Exception as db_error:
        # If verification_code is VARCHAR(10) and too short, use JSONB workaround
        error_str = str(db_error)
        if "too long" in error_str.lower() or "character varying" in error_str.lower() or "22001" in error_str:
            # Store challenge in passkey_credentials as temporary metadata
            user = get_user_by_email(email)
            if not user:
                raise ValueError("User not found")
            
            existing_credentials = user.get("passkey_credentials", [])
            if not isinstance(existing_credentials, list):
                existing_credentials = []
            
            # Add challenge as temporary entry (will be removed after use)
            # Store with a special prefix to identify it
            challenge_entry = {
                "_webauthn_challenge": challenge_str,
                "_challenge_expiry": (datetime.utcnow() + timedelta(minutes=expiry_minutes)).isoformat(),
                "_temp": True
            }
            
            # Prepend to credentials array (will be first entry)
            existing_credentials.insert(0, challenge_entry)
            
            supabase.table("slay_users").update({
                "passkey_credentials": existing_credentials,
                "verification_code_expiry": (datetime.utcnow() + timedelta(minutes=expiry_minutes)).isoformat()
            }).eq("email", email).execute()
            return True
        else:
            raise

def get_webauthn_challenge(email: str) -> Optional[str]:
    """
    Retrieve WebAuthn challenge. Checks both verification_code and passkey_credentials JSONB.
    """
    try:
        user = get_user_by_email(email)
        if not user:
            return None
        
        # First, try to get from verification_code
        verification_code = user.get("verification_code")
        if verification_code and len(verification_code) > 10:
            # Likely a WebAuthn challenge (longer than 6-digit code)
            return verification_code
        
        # If not in verification_code, check passkey_credentials for temp challenge
        credentials = user.get("passkey_credentials", [])
        if isinstance(credentials, list) and len(credentials) > 0:
            first_entry = credentials[0]
            if isinstance(first_entry, dict) and first_entry.get("_temp") and first_entry.get("_webauthn_challenge"):
                # Check if expired
                expiry_str = first_entry.get("_challenge_expiry")
                if expiry_str:
                    try:
                        expiry = parse_datetime_string(expiry_str)
                        if datetime.utcnow() < expiry:
                            return first_entry.get("_webauthn_challenge")
                    except:
                        pass
        
        return None
    except Exception as e:
        print(f"Error getting WebAuthn challenge: {str(e)}")
        return None

def clear_webauthn_challenge(email: str):
    """Clear WebAuthn challenge from both verification_code and passkey_credentials"""
    try:
        user = get_user_by_email(email)
        if not user:
            return
        
        # Clear verification_code
        update_data = {
            "verification_code": None,
            "verification_code_expiry": None
        }
        
        # Also remove temp challenge from passkey_credentials if present
        credentials = user.get("passkey_credentials", [])
        if isinstance(credentials, list) and len(credentials) > 0:
            # Remove temp challenge entries
            credentials = [c for c in credentials if not (isinstance(c, dict) and c.get("_temp"))]
            update_data["passkey_credentials"] = credentials
        
        supabase.table("slay_users").update(update_data).eq("email", email).execute()
    except Exception as e:
        print(f"Error clearing WebAuthn challenge: {str(e)}")

# Error Handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"success": False, "error": str(error)}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "error": "Internal server error"}), 500

# API Endpoints

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    resend_configured = bool(RESEND_API_KEY)
    supabase_configured = bool(SUPABASE_URL and SUPABASE_KEY)
    
    return jsonify({
        "status": "healthy",
        "service": "Mobile App Backend API - Email Verification (Resend)",
        "version": "3.0.0 (Resend Edition)",
        "timestamp": datetime.utcnow().isoformat(),
        "configuration": {
            "email_provider": "Resend",
            "resend_configured": resend_configured,
            "supabase_configured": supabase_configured,
            "from_email": FROM_EMAIL
        }
    }), 200

@app.route('/api/register', methods=['POST'])
def register_user():
    """
    Register a new user and send verification code via Resend
    Optionally accepts passkey credential for registration with passkey
    
    Request Body:
    {
        "email": "user@example.com",
        "full_name": "John Doe" (optional),
        "credential": {...} (optional) - WebAuthn credential from mobile app (iOS/Android) for passkey registration,
        "challenge": "..." (optional) - Challenge string used to generate the credential,
        "device_name": "iPhone 15" (optional) - Name of the device/authenticator
    }
    
    Note: If credential is provided, challenge must also be provided.
    The challenge should be generated by calling /api/passkey/register/begin first.
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        full_name = data.get('full_name')
        credential = data.get('credential')
        challenge = data.get('challenge')
        device_name = data.get('device_name', 'Unknown Device')
        
        # Validate required fields
        if not email:
            return jsonify({
                "success": False,
                "error": "Email is required"
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # If credential is provided, challenge must also be provided
        if credential and not challenge:
            return jsonify({
                "success": False,
                "error": "Challenge is required when providing a passkey credential"
            }), 400
        
        # Check if user already exists
        existing_user = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if existing_user.data and len(existing_user.data) > 0:
            # Check if already verified
            if existing_user.data[0].get("email_verified"):
                return jsonify({
                    "success": False,
                    "error": "Email already registered and verified"
                }), 400
            else:
                # User exists but not verified, resend code
                return resend_verification_code_internal(email)
        
        # Generate verification code
        verification_code = generate_verification_code()
        expiry_time = datetime.utcnow() + timedelta(minutes=15)
        
        # Create user record (unverified)
        user_data = {
            "email": email,
            "full_name": full_name,
            "email_verified": False,
            "verification_code": verification_code,
            "verification_code_expiry": expiry_time.isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        insert_response = supabase.table("slay_users").insert(user_data).execute()
        
        # Handle passkey registration if credential is provided
        passkey_registered = False
        credential_id = None
        
        if credential and challenge:
            try:
                # Convert challenge string to bytes
                try:
                    challenge_bytes = base64.urlsafe_b64decode(challenge + '==')
                except Exception:
                    # Try as regular base64
                    challenge_bytes = base64.b64decode(challenge)
                
                # Verify registration response
                # Clean credential to remove Ellipsis objects before JSON serialization
                cleaned_credential = remove_ellipsis(credential)
                verification = verify_registration_response(
                    credential=RegistrationCredential.parse_raw(json.dumps(cleaned_credential)),
                    expected_challenge=challenge_bytes,
                    expected_origin=ORIGIN,
                    expected_rp_id=RP_ID,
                )
                
                # Store the passkey credential
                credential_id_b64 = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').rstrip('=')
                
                store_passkey_credential(
                    email=email,
                    credential_id=credential_id_b64,
                    public_key=verification.credential_public_key,
                    sign_count=verification.sign_count,
                    device_name=device_name
                )
                
                passkey_registered = True
                credential_id = credential_id_b64
                
            except Exception as e:
                # If passkey verification fails, continue with normal registration
                # but log the error
                print(f"⚠️  Passkey registration failed during user registration: {str(e)}")
                # Don't fail the entire registration, just skip passkey
                passkey_registered = False
        
        # Send verification email via Resend in background
        send_email_background(email, verification_code, full_name)
        
        response_data = {
            "success": True,
            "message": "Registration successful. Please check your email for verification code.",
            "email": email,
            "note": "Check your inbox (and spam folder) for the verification email from Resend"
        }
        
        if passkey_registered:
            response_data["passkey_registered"] = True
            response_data["credential_id"] = credential_id
            response_data["message"] = "Registration successful with passkey. Please check your email for verification code."
        
        return jsonify(response_data), 201
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Registration failed: {str(e)}"
        }), 500

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    """
    Verify user email with the provided code
    
    Request Body:
    {
        "email": "user@example.com",
        "code": "123456"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        code = data.get('code')
        
        # Validate required fields
        if not email or not code:
            return jsonify({
                "success": False,
                "error": "Email and code are required"
            }), 400
        
        # Fetch user with verification code
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return jsonify({
                "success": False,
                "error": "User not found"
            }), 404
        
        user = user_response.data[0]
        
        # Check if already verified
        if user.get("email_verified"):
            return jsonify({
                "success": True,
                "message": "Email already verified"
            }), 200
        
        # Check verification code
        if user.get("verification_code") != code:
            return jsonify({
                "success": False,
                "error": "Invalid verification code"
            }), 400
        
        # Check if code expired
        expiry_str = user.get("verification_code_expiry")
        if expiry_str:
            try:
                expiry_time = parse_datetime_string(expiry_str)
                if datetime.utcnow() > expiry_time:
                    return jsonify({
                        "success": False,
                        "error": "Verification code expired. Please request a new code."
                    }), 400
            except ValueError as e:
                # If we can't parse the datetime, log error but don't fail verification
                print(f"⚠️  Warning: Could not parse expiry time '{expiry_str}': {str(e)}")
                # Continue with verification (assume not expired if we can't parse)
        
        # Update user as verified
        update_response = supabase.table("slay_users").update({
            "email_verified": True,
            "verified_at": datetime.utcnow().isoformat(),
            "verification_code": None,
            "verification_code_expiry": None
        }).eq("email", email).execute()
        
        return jsonify({
            "success": True,
            "message": "Email verified successfully! 🎉",
            "email": email
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Verification failed: {str(e)}"
        }), 500

@app.route('/api/resend-code', methods=['POST'])
def resend_verification_code():
    """
    Resend verification code to user's email via Resend
    
    Request Body:
    {
        "email": "user@example.com"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        
        if not email:
            return jsonify({
                "success": False,
                "error": "Email is required"
            }), 400
        
        return resend_verification_code_internal(email)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to resend code: {str(e)}"
        }), 500

def resend_verification_code_internal(email: str):
    """Internal function to resend verification code"""
    # Fetch user
    user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
    
    if not user_response.data or len(user_response.data) == 0:
        return jsonify({
            "success": False,
            "error": "User not found"
        }), 404
    
    user = user_response.data[0]
    
    # Check if already verified
    if user.get("email_verified"):
        return jsonify({
            "success": False,
            "error": "Email already verified"
        }), 400
    
    # Generate new verification code
    new_code = generate_verification_code()
    new_expiry = datetime.utcnow() + timedelta(minutes=15)
    
    # Update user with new code
    supabase.table("slay_users").update({
        "verification_code": new_code,
        "verification_code_expiry": new_expiry.isoformat()
    }).eq("email", email).execute()
    
    # Send email via Resend in background
    send_email_background(email, new_code, user.get("full_name"))
    
    return jsonify({
        "success": True,
        "message": "Verification code resent via Resend. Please check your email.",
        "email": email
    }), 200

@app.route('/api/verify-invite-code', methods=['POST'])
def verify_invite_code():
    """
    Verify invite code for user registration
    
    Request Body:
    {
        "email": "user@example.com",
        "invite_code": "SLAY1111"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        invite_code = data.get('invite_code')
        
        # Validate required fields
        if not email or not invite_code:
            return jsonify({
                "success": False,
                "error": "Email and invite_code are required"
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # Verify invite code
        VALID_INVITE_CODE = "SLAY1111"
        if invite_code != VALID_INVITE_CODE:
            return jsonify({
                "success": False,
                "error": "Invalid invite code"
            }), 400
        
        # Check if user exists in Supabase
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        current_time = datetime.utcnow().isoformat()
        
        if user_response.data and len(user_response.data) > 0:
            # User exists, update to mark as invited
            user = user_response.data[0]
            
            # Update user to mark as invited
            update_data = {
                "invited": True,
                "invited_at": current_time
            }
            
            supabase.table("slay_users").update(update_data).eq("email", email).execute()
        else:
            # User doesn't exist, create new user record with invited status
            return jsonify({
            "success": False,
            "error": f"Invite code verification failed: User not found"
        }), 500
        
        return jsonify({
            "success": True,
            "message": "Invite code verified successfully! 🎉",
            "email": email,
            "invited": True
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Invite code verification failed: {str(e)}"
        }), 500


@app.route('/api/validate-username', methods=['POST'])
def validate_username():
    """
    Validate a username and recommend alternatives if it's not valid or already taken.

    Request Body:
    {
        "username": "desired_username",
        "email": "user@example.com"
    }

    Response (valid and available):
    {
        "success": True,
        "valid": True,
        "available": True,
        "username": "desired_username"
    }

    Response (invalid or taken):
    {
        "success": True,
        "valid": False,
        "available": False,
        "username": "bad_or_taken_name",
        "message": "Reason why it's not valid/available",
        "suggestions": ["suggestion1", "suggestion2", ...]
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        raw_username = data.get("username", "")
        email = data.get("email")

        if not raw_username:
            return jsonify({
                "success": False,
                "error": "Username is required"
            }), 400

        if not email:
            return jsonify({
                "success": False,
                "error": "Email is required"
            }), 400

        # Validate email format using existing helper
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400

        username = raw_username.strip()

        # Basic format validation rules:
        # - 3 to 20 characters
        # - Letters, numbers, underscores, and dots
        # - Cannot start or end with '.' or '_'
        # - No spaces
        import re  # local import to keep top imports unchanged

        pattern = r'^[A-Za-z0-9](?:[A-Za-z0-9._]{1,18})[A-Za-z0-9]$'

        valid_format = bool(re.match(pattern, username))

        # Additional length guard (in case regex is edited in future)
        if len(username) < 3 or len(username) > 20:
            valid_format = False

        # Check if username already exists in Supabase (if column present)
        available = True
        if valid_format:
            try:
                existing = supabase.table("slay_users").select("id").eq("username", username).execute()
                if existing.data and len(existing.data) > 0:
                    available = False
            except Exception as e:
                # Don't hard-fail on DB schema issues; just report format validity
                print(f"⚠️ Username availability check failed: {str(e)}")

        # If valid format and available, save it in Supabase for this email and return success
        if valid_format and available:
            try:
                # Try to find existing user by email
                user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
                now_iso = datetime.utcnow().isoformat()

                if user_response.data and len(user_response.data) > 0:
                    # Update existing user with username
                    supabase.table("slay_users").update({
                        "username": username
                    }).eq("email", email).execute()
                else:
                    # Create a minimal user record with email and username
                    supabase.table("slay_users").insert({
                        "email": email,
                        "username": username,
                        "created_at": now_iso
                    }).execute()
            except Exception as e:
                # Fail clearly if we can't persist the username
                return jsonify({
                    "success": False,
                    "error": f"Failed to store username in database: {str(e)}"
                }), 500

            return jsonify({
                "success": True,
                "valid": True,
                "available": True,
                "username": username
            }), 200

        # Build reason message
        if not valid_format:
            message = (
                "Username must be 3-20 characters, use only letters, numbers, dots and underscores, "
                "and cannot start or end with a dot or underscore."
            )
        else:
            message = "Username is already taken."

        # Generate suggestions and pick a recommended username that is actually available
        base = re.sub(r'[^A-Za-z0-9]', '', username)
        if not base:
            base = "user"
        base = base[:15]  # leave room for suffixes

        import random

        suggestions = []
        tried = set()

        def add_candidate(candidate: str):
            cand = candidate[:20]  # enforce max length
            if cand not in tried:
                tried.add(cand)
                suggestions.append(cand)

        # Some candidate variants
        add_candidate(base)
        add_candidate(f"{base}{random.randint(1, 99)}")
        add_candidate(f"{base}_{random.randint(1, 999)}")
        add_candidate(f"{base}.{random.randint(1, 999)}")
        add_candidate(f"{base}{random.randint(1000, 9999)}")

        # Ensure we have a few more random options
        while len(suggestions) < 8:
            add_candidate(f"{base}{random.randint(1, 99999)}")

        recommended_username = None

        # Check Supabase to find the first available suggestion
        try:
            for candidate in suggestions:
                # Re-check format guard (in case base is weird)
                if len(candidate) < 3 or len(candidate) > 20:
                    continue
                if not re.match(pattern, candidate):
                    continue

                existing = supabase.table("slay_users").select("id").eq("username", candidate).execute()
                if not existing.data or len(existing.data) == 0:
                    recommended_username = candidate
                    break
        except Exception as e:
            print(f"⚠️ Username suggestion availability check failed: {str(e)}")

        # Fallback if DB check failed or all taken
        if not recommended_username and suggestions:
            recommended_username = suggestions[0]

        return jsonify({
            "success": True,
            "valid": valid_format,
            "available": available,
            "username": username,
            "message": message,
            "suggestions": suggestions,
            "recommended_username": recommended_username
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Username validation failed: {str(e)}"
        }), 500


@app.route('/api/user/<email>', methods=['GET'])
def get_user_status(email):
    """
    Get user verification status (for testing/debugging)
    """
    try:
        user_response = supabase.table("slay_users").select(
            "email, full_name, email_verified, created_at, verified_at"
        ).eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return jsonify({
                "success": False,
                "error": "User not found"
            }), 404
        
        return jsonify({
            "success": True,
            "user": user_response.data[0]
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to fetch user: {str(e)}"
        }), 500

@app.route('/api/login/request-otp', methods=['POST'])
def request_login_otp():
    """
    Request OTP for login via email
    
    Request Body:
    {
        "email": "user@example.com"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        
        # Validate required fields
        if not email:
            return jsonify({
                "success": False,
                "error": "Email is required"
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # Check if user exists and is verified
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return jsonify({
                "success": False,
                "error": "User not found. Please register first."
            }), 404
        
        user = user_response.data[0]
        
        # Check if user is verified
        if not user.get("email_verified"):
            return jsonify({
                "success": False,
                "error": "Email not verified. Please verify your email first."
            }), 400
        
        # Generate login OTP
        login_otp = generate_verification_code()
        expiry_time = datetime.utcnow() + timedelta(minutes=15)
        
        # Update user with login OTP
        supabase.table("slay_users").update({
            "verification_code": login_otp,
            "verification_code_expiry": expiry_time.isoformat()
        }).eq("email", email).execute()
        
        # Send login OTP email in background
        send_login_otp_email_background(email, login_otp, user.get("full_name"))
        
        return jsonify({
            "success": True,
            "message": "Login OTP sent to your email. Please check your inbox.",
            "email": email,
            "note": "OTP will expire in 15 minutes"
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to send login OTP: {str(e)}"
        }), 500

@app.route('/api/login/verify-otp', methods=['POST'])
def verify_login_otp():
    """
    Verify OTP and complete login
    
    Request Body:
    {
        "email": "user@example.com",
        "otp": "123456"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        otp = data.get('otp')
        
        # Validate required fields
        if not email or not otp:
            return jsonify({
                "success": False,
                "error": "Email and OTP are required"
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # Fetch user
        user_response = supabase.table("slay_users").select("*").eq("email", email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            return jsonify({
                "success": False,
                "error": "User not found"
            }), 404
        
        user = user_response.data[0]
        
        # Check if user is verified
        if not user.get("email_verified"):
            return jsonify({
                "success": False,
                "error": "Email not verified. Please verify your email first."
            }), 400
        
        # Check OTP
        stored_otp = user.get("verification_code")
        if stored_otp != otp:
            return jsonify({
                "success": False,
                "error": "Invalid OTP"
            }), 400
        
        # Check if OTP expired
        expiry_str = user.get("verification_code_expiry")
        if expiry_str:
            try:
                expiry_time = parse_datetime_string(expiry_str)
                if datetime.utcnow() > expiry_time:
                    return jsonify({
                        "success": False,
                        "error": "OTP expired. Please request a new one."
                    }), 400
            except ValueError as e:
                print(f"⚠️  Warning: Could not parse expiry time '{expiry_str}': {str(e)}")
        
        # Clear the OTP after successful verification
        supabase.table("slay_users").update({
            "verification_code": None,
            "verification_code_expiry": None
        }).eq("email", email).execute()
        
        # Return user info (excluding sensitive data)
        user_data = {
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "username": user.get("username"),
            "email_verified": user.get("email_verified"),
            "created_at": user.get("created_at")
        }
        
        return jsonify({
            "success": True,
            "message": "Login successful! 🎉",
            "user": user_data
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Login verification failed: {str(e)}"
        }), 500

@app.route('/api/passkey/register/begin', methods=['POST'])
def passkey_register_begin():
    """
    Begin passkey registration process
    Can be used for both existing users and new user registration
    
    Request Body:
    {
        "email": "user@example.com",
        "device_name": "iPhone 15" (optional),
        "for_registration": false (optional) - Set to true if this is for new user registration
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        device_name = data.get('device_name', 'Unknown Device')
        for_registration = data.get('for_registration', False)
        
        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        
        if not validate_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
        
        # Get user (optional if for_registration is true)
        user = get_user_by_email(email)
        
        # If not for registration, check if user exists and is verified
        if not for_registration:
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            
            if not user.get("email_verified"):
                return jsonify({"success": False, "error": "Email not verified. Please verify your email first."}), 400
            
            user_display_name = user.get("full_name") or email
        else:
            # For registration, use email as display name if user doesn't exist
            user_display_name = data.get('full_name') or email
        
        # Generate challenge (as base64 string for storage, convert to bytes for WebAuthn)
        challenge_str = generate_challenge()
        challenge_bytes = base64.urlsafe_b64decode(challenge_str + '==')
        
        # Generate registration options
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=email.encode('utf-8'),
            user_name=email,
            user_display_name=user_display_name,
            challenge=challenge_bytes,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            ),
        )
        
        # Store challenge temporarily
        # If user exists, store in user record; otherwise, we'll return it for client to store temporarily
        if user:
            store_webauthn_challenge(email, challenge_str, expiry_minutes=5)
        
        # Convert to JSON-serializable format
        try:
            # Try using model_dump_json for Pydantic v2 (handles bytes conversion automatically)
            options_dict = json.loads(registration_options.model_dump_json())
        except (AttributeError, TypeError, ValueError) as e:
            try:
                # Try using model_dump for Pydantic v2 with json mode
                options_dict = registration_options.model_dump(mode='json')
            except (AttributeError, TypeError, ValueError) as e:
                try:
                    # Try using dict() for Pydantic v1
                    options_dict = registration_options.dict()
                except (AttributeError, TypeError, ValueError) as e:
                    # Last resort: convert to dict manually using vars() or __dict__
                    try:
                        options_dict = vars(registration_options)
                    except (TypeError, AttributeError) as e:
                        # If it's not a simple object, try to convert recursively
                        options_dict = registration_options.__dict__ if hasattr(registration_options, '__dict__') else {}
        
        # Remove Ellipsis objects and convert bytes to base64 strings (recursive)
        # This ensures all bytes are converted even if model_dump didn't handle them
        # Also handles nested Pydantic models that weren't fully converted
        options_dict = remove_ellipsis(options_dict)
        
        # Double-check: try to serialize to catch any remaining issues
        try:
            json.dumps(options_dict)  # Test serialization
        except TypeError as e:
            # If there are still non-serializable objects, run remove_ellipsis again more aggressively
            # This recursive call will handle any nested objects that weren't converted
            options_dict = remove_ellipsis(options_dict)
            # Try one more time - if it still fails, we'll catch it in the outer try-except
            try:
                json.dumps(options_dict)
            except TypeError as serialization_error:
                # Log the error for debugging but try one more aggressive pass
                import traceback
                print(f"Warning: Serialization error after remove_ellipsis: {serialization_error}")
                print(f"Traceback: {traceback.format_exc()}")
                # Force convert any remaining objects to strings as last resort
                options_dict = remove_ellipsis(options_dict)
        
        response_data = {
            "success": True,
            "options": options_dict,
            "device_name": device_name
        }
        
        # If for registration and user doesn't exist, return challenge for client to include in register request
        if for_registration and not user:
            response_data["challenge"] = challenge_str
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to begin passkey registration: {str(e)}"
        }), 500

@app.route('/api/passkey/register/complete', methods=['POST'])
def passkey_register_complete():
    """
    Complete passkey registration
    
    Request Body:
    {
        "email": "user@example.com",
        "credential": {...},  // WebAuthn credential from mobile app (iOS/Android)
        "device_name": "iPhone 15" (optional)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        credential = data.get('credential')
        device_name = data.get('device_name', 'Unknown Device')
        
        if not email or not credential:
            return jsonify({"success": False, "error": "Email and credential are required"}), 400
        
        # Get user and stored challenge
        user = get_user_by_email(email)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        stored_challenge = get_webauthn_challenge(email)
        if not stored_challenge:
            return jsonify({"success": False, "error": "Registration session expired. Please start again."}), 400
        
        # Check challenge expiry
        expiry_str = user.get("verification_code_expiry")
        if expiry_str:
            try:
                expiry_time = parse_datetime_string(expiry_str)
                if datetime.utcnow() > expiry_time:
                    return jsonify({"success": False, "error": "Registration session expired. Please start again."}), 400
            except ValueError:
                pass
        
        # Verify registration response
        try:
            # Convert stored challenge string back to bytes
            challenge_bytes = base64.urlsafe_b64decode(stored_challenge + '==')
            
            # Clean credential to remove Ellipsis objects before JSON serialization
            cleaned_credential = remove_ellipsis(credential)
            verification = verify_registration_response(
                credential=RegistrationCredential.parse_raw(json.dumps(cleaned_credential)),
                expected_challenge=challenge_bytes,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
            )
            
            # Store the passkey credential
            credential_id_b64 = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').rstrip('=')
            
            store_passkey_credential(
                email=email,
                credential_id=credential_id_b64,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                device_name=device_name
            )
            
            # Clear challenge (handles both verification_code and JSONB storage)
            clear_webauthn_challenge(email)
            
            return jsonify({
                "success": True,
                "message": "Passkey registered successfully! 🎉",
                "credential_id": credential_id_b64
            }), 200
            
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Passkey verification failed: {str(e)}"
            }), 400
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to complete passkey registration: {str(e)}"
        }), 500

@app.route('/api/passkey/login/begin', methods=['POST'])
def passkey_login_begin():
    """
    Begin passkey authentication process
    
    Request Body:
    {
        "email": "user@example.com" (required)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        
        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        
        if not validate_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
        
        # Generate challenge (as base64 string for storage, convert to bytes for WebAuthn)
        challenge_str = generate_challenge()
        challenge_bytes = base64.urlsafe_b64decode(challenge_str + '==')
        
        allowed_credentials = []
        
        user = get_user_by_email(email)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        if not user.get("email_verified"):
            return jsonify({"success": False, "error": "Email not verified"}), 400
        
        # Get user's passkey credentials
        credentials = get_passkey_credentials(email)
        
        for cred in credentials:
            try:
                credential_id_bytes = base64.urlsafe_b64decode(cred["credential_id"] + '==')
                allowed_credentials.append(
                    PublicKeyCredentialDescriptor(
                        id=credential_id_bytes,
                        type="public-key"
                    )
                )
            except Exception as e:
                print(f"Error processing credential: {str(e)}")
                continue
        
        # Generate authentication options
        authentication_options = generate_authentication_options(
            rp_id=RP_ID,
            challenge=challenge_bytes,
            allow_credentials=allowed_credentials if allowed_credentials else None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        # Store challenge temporarily (handles both TEXT and VARCHAR(10) columns)
        store_webauthn_challenge(email, challenge_str, expiry_minutes=5)
        
        # Convert to JSON-serializable format
        try:
            # Try using model_dump_json for Pydantic v2 (handles bytes conversion automatically)
            options_dict = json.loads(authentication_options.model_dump_json())
        except (AttributeError, TypeError, ValueError) as e:
            try:
                # Try using model_dump for Pydantic v2 with json mode
                options_dict = authentication_options.model_dump(mode='json')
            except (AttributeError, TypeError, ValueError) as e:
                try:
                    # Try using dict() for Pydantic v1
                    options_dict = authentication_options.dict()
                except (AttributeError, TypeError, ValueError) as e:
                    # Last resort: convert to dict manually using vars() or __dict__
                    try:
                        options_dict = vars(authentication_options)
                    except (TypeError, AttributeError) as e:
                        # If it's not a simple object, try to convert recursively
                        options_dict = authentication_options.__dict__ if hasattr(authentication_options, '__dict__') else {}
        
        # Remove Ellipsis objects and convert bytes to base64 strings (recursive)
        # This ensures all bytes are converted even if model_dump didn't handle them
        # Also handles nested Pydantic models that weren't fully converted
        options_dict = remove_ellipsis(options_dict)
        
        # Double-check: try to serialize to catch any remaining issues
        try:
            json.dumps(options_dict)  # Test serialization
        except TypeError as e:
            # If there are still non-serializable objects, run remove_ellipsis again more aggressively
            # This recursive call will handle any nested objects that weren't converted
            options_dict = remove_ellipsis(options_dict)
            # Try one more time - if it still fails, we'll catch it in the outer try-except
            try:
                json.dumps(options_dict)
            except TypeError as serialization_error:
                # Log the error for debugging but try one more aggressive pass
                import traceback
                print(f"Warning: Serialization error after remove_ellipsis: {serialization_error}")
                print(f"Traceback: {traceback.format_exc()}")
                # Force convert any remaining objects to strings as last resort
                options_dict = remove_ellipsis(options_dict)
            # Try one more time
            json.dumps(options_dict)
        
        return jsonify({
            "success": True,
            "options": options_dict
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to begin passkey login: {str(e)}"
        }), 500

@app.route('/api/passkey/login/complete', methods=['POST'])
def passkey_login_complete():
    """
    Complete passkey authentication
    
    Request Body:
    {
        "email": "user@example.com",  // Required
        "credential": {...}  // WebAuthn credential from browser
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        credential = data.get('credential')
        
        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        
        if not credential:
            return jsonify({"success": False, "error": "Credential is required"}), 400
        
        if not validate_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
        
        # Extract credential ID from the credential
        credential_id_raw = credential.get('id', '')
        credential_id_b64 = credential_id_raw
        
        # Get user by email
        user = get_user_by_email(email)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        # Find the matching credential
        credentials = get_passkey_credentials(email)
        matching_cred = None
        
        for cred in credentials:
            if cred.get("credential_id") == credential_id_b64:
                matching_cred = cred
                break
        
        if not matching_cred:
            return jsonify({"success": False, "error": "Credential not found for this user"}), 404
        
        # Get stored challenge
        stored_challenge = user.get("verification_code")
        if not stored_challenge:
            return jsonify({"success": False, "error": "Login session expired. Please start again."}), 400
        
        # Check challenge expiry
        expiry_str = user.get("verification_code_expiry")
        if expiry_str:
            try:
                expiry_time = parse_datetime_string(expiry_str)
                if datetime.utcnow() > expiry_time:
                    return jsonify({"success": False, "error": "Login session expired. Please start again."}), 400
            except ValueError:
                pass
        
        # Get public key from stored credential
        public_key_bytes = base64.b64decode(matching_cred["public_key"])
        expected_sign_count = matching_cred.get("sign_count", 0)
        
        # Verify authentication response
        try:
            # Convert stored challenge string back to bytes
            challenge_bytes = base64.urlsafe_b64decode(stored_challenge + '==')
            
            # Clean credential to remove Ellipsis objects before JSON serialization
            cleaned_credential = remove_ellipsis(credential)
            verification = verify_authentication_response(
                credential=AuthenticationCredential.parse_raw(json.dumps(cleaned_credential)),
                expected_challenge=challenge_bytes,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                credential_public_key=public_key_bytes,
                credential_current_sign_count=expected_sign_count,
            )
            
            # Update sign count
            update_sign_count(email, credential_id_b64, verification.new_sign_count)
            
            # Clear challenge (handles both verification_code and JSONB storage)
            clear_webauthn_challenge(email)
            
            # Return user info
            user_data = {
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "username": user.get("username"),
                "email_verified": user.get("email_verified"),
                "created_at": user.get("created_at")
            }
            
            return jsonify({
                "success": True,
                "message": "Passkey login successful! 🎉",
                "user": user_data
            }), 200
            
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Passkey verification failed: {str(e)}"
            }), 400
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to complete passkey login: {str(e)}"
        }), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current API configuration"""
    return jsonify({
        "email_provider": "Resend",
        "resend_configured": bool(RESEND_API_KEY),
        "supabase_configured": bool(SUPABASE_URL and SUPABASE_KEY),
        "from_email": FROM_EMAIL,
        "resend_docs": "https://resend.com/docs",
        "setup_guide": "See RESEND_SETUP.md for configuration instructions"
    }), 200

@app.route('/docs', methods=['GET'])
def api_docs():
    """Comprehensive API documentation endpoint"""
    docs_data = {
        "title": "Mobile App Backend API Documentation",
        "version": "3.0.0 (Resend Edition)",
        "description": "A RESTful API backend for mobile applications (iOS/Android) providing email verification, passwordless authentication (OTP + Passkeys), and user management using Resend email service and Supabase database",
        "base_url": request.host_url.rstrip('/'),
        "endpoints": {
            "GET /": {
                "description": "API information and endpoint list",
                "method": "GET",
                "path": "/",
                "response": {
                    "service": "Mobile App Backend API",
                    "version": "3.0.0 (Resend Edition)",
                    "endpoints": "List of all available endpoints"
                }
            },
            "GET /docs": {
                "description": "This comprehensive API documentation in JSON format",
                "method": "GET",
                "path": "/docs",
                "response_example": {
                    "title": "Mobile App Backend API Documentation",
                    "version": "3.0.0 (Resend Edition)",
                    "description": "A RESTful API backend for mobile applications...",
                    "base_url": "http://localhost:5000",
                    "endpoints": {}
                }
            },
            "GET /docs/html": {
                "description": "Interactive HTML documentation page with a user-friendly interface for browsing all API endpoints. This endpoint provides a beautiful, searchable, and interactive documentation interface that displays all API endpoints with their details, request/response examples, and status codes.",
                "method": "GET",
                "path": "/docs/html",
                "response_example": "Returns an HTML page with interactive API documentation",
                "usage": {
                    "description": "Access the interactive HTML documentation by visiting this endpoint in a web browser",
                    "steps": [
                        "1. Open your web browser and navigate to: http://your-api-url/docs/html",
                        "2. The page will automatically load all API endpoint documentation",
                        "3. Use the search box at the top to filter endpoints by name, method, or path",
                        "4. Click on any endpoint card to expand and view detailed information",
                        "5. Copy request/response examples using the 'Copy' buttons",
                        "6. View status codes, request bodies, and response examples for each endpoint"
                    ],
                    "features": [
                        "Interactive endpoint cards that expand/collapse on click",
                        "Search functionality to quickly find specific endpoints",
                        "Copy-to-clipboard buttons for code examples",
                        "Color-coded HTTP methods (GET, POST, PUT, DELETE)",
                        "Status code badges with color indicators",
                        "Grouped endpoints by category (Authentication, Passkey, User Management, etc.)",
                        "Responsive design that works on desktop and mobile devices"
                    ],
                    "example_urls": [
                        "http://localhost:5000/docs/html (local development)",
                        "https://your-api-domain.com/docs/html (production)"
                    ]
                },
                "status_codes": {
                    "200": "HTML documentation page successfully returned",
                    "500": "Internal server error (if /docs endpoint fails)"
                },
                "notes": [
                    "This endpoint fetches data from the /docs endpoint internally",
                    "The HTML page is fully self-contained with embedded JavaScript",
                    "No authentication required - publicly accessible",
                    "Works best in modern web browsers (Chrome, Firefox, Safari, Edge)",
                    "For programmatic access, use /docs endpoint instead which returns JSON"
                ]
            },
            "GET /api/health": {
                "description": "Health check endpoint to verify API status and configuration",
                "method": "GET",
                "path": "/api/health",
                "response_example": {
                    "status": "healthy",
                    "service": "Mobile App Backend API - Email Verification (Resend)",
                    "version": "3.0.0 (Resend Edition)",
                    "timestamp": "2024-01-01T00:00:00.000000",
                    "configuration": {
                        "email_provider": "Resend",
                        "resend_configured": True,
                        "supabase_configured": True,
                        "from_email": "onboarding@resend.dev"
                    }
                }
            },
            "GET /api/config": {
                "description": "Get current API configuration details",
                "method": "GET",
                "path": "/api/config",
                "response_example": {
                    "email_provider": "Resend",
                    "resend_configured": True,
                    "supabase_configured": True,
                    "from_email": "onboarding@resend.dev",
                    "resend_docs": "https://resend.com/docs"
                }
            },
            "POST /api/register": {
                "description": "Register a new user and send verification code via email",
                "method": "POST",
                "path": "/api/register",
                "request_body": {
                    "email": "string (required) - Valid email address",
                    "full_name": "string (optional) - User's full name"
                },
                "request_example": {
                    "email": "user@example.com",
                    "full_name": "John Doe"
                },
                "response_success": {
                    "success": True,
                    "message": "Registration successful. Please check your email for verification code.",
                    "email": "user@example.com",
                    "note": "Check your inbox (and spam folder) for the verification email from Resend"
                },
                "response_error": {
                    "success": False,
                    "error": "Error message describing what went wrong"
                },
                "status_codes": {
                    "201": "Registration successful",
                    "400": "Bad request (invalid email, email already verified, etc.)",
                    "500": "Internal server error"
                }
            },
            "POST /api/verify-email": {
                "description": "Verify user email with the provided verification code",
                "method": "POST",
                "path": "/api/verify-email",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "code": "string (required) - 6-digit verification code"
                },
                "request_example": {
                    "email": "user@example.com",
                    "code": "123456"
                },
                "response_success": {
                    "success": True,
                    "message": "Email verified successfully! 🎉",
                    "email": "user@example.com"
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (invalid code, expired code, user not found, etc.)"
                },
                "status_codes": {
                    "200": "Email verified successfully or already verified",
                    "400": "Bad request (invalid code, expired code, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "Verification codes expire after 15 minutes",
                    "If code expires, use /api/resend-code to get a new one"
                ]
            },
            "POST /api/resend-code": {
                "description": "Resend verification code to user's email",
                "method": "POST",
                "path": "/api/resend-code",
                "request_body": {
                    "email": "string (required) - User's email address"
                },
                "request_example": {
                    "email": "user@example.com"
                },
                "response_success": {
                    "success": True,
                    "message": "Verification code resent via Resend. Please check your email.",
                    "email": "user@example.com"
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (user not found, email already verified, etc.)"
                },
                "status_codes": {
                    "200": "Code resent successfully",
                    "400": "Bad request (email already verified, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                }
            },
            "POST /api/login/request-otp": {
                "description": "Request OTP for login via email. User must be registered and email verified.",
                "method": "POST",
                "path": "/api/login/request-otp",
                "request_body": {
                    "email": "string (required) - User's email address"
                },
                "request_example": {
                    "email": "user@example.com"
                },
                "response_success": {
                    "success": True,
                    "message": "Login OTP sent to your email. Please check your inbox.",
                    "email": "user@example.com",
                    "note": "OTP will expire in 15 minutes"
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (user not found, email not verified, etc.)"
                },
                "status_codes": {
                    "200": "OTP sent successfully",
                    "400": "Bad request (invalid email format, email not verified, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "User must be registered and have verified their email",
                    "OTP expires after 15 minutes",
                    "OTP is sent via Resend email service"
                ]
            },
            "POST /api/login/verify-otp": {
                "description": "Verify OTP and complete login",
                "method": "POST",
                "path": "/api/login/verify-otp",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "otp": "string (required) - 6-digit OTP code"
                },
                "request_example": {
                    "email": "user@example.com",
                    "otp": "123456"
                },
                "response_success": {
                    "success": True,
                    "message": "Login successful! 🎉",
                    "user": {
                        "email": "user@example.com",
                        "full_name": "John Doe",
                        "username": "johndoe",
                        "email_verified": True,
                        "created_at": "2024-01-01T00:00:00.000000"
                    }
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (invalid OTP, expired OTP, user not found, etc.)"
                },
                "status_codes": {
                    "200": "Login successful",
                    "400": "Bad request (invalid OTP, expired OTP, email not verified, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "OTP must be requested first using /api/login/request-otp",
                    "OTP expires after 15 minutes",
                    "OTP is cleared after successful login",
                    "Returns user information on successful login"
                ]
            },
            "POST /api/passkey/register/begin": {
                "description": "Begin passkey registration process. Generates WebAuthn registration options for mobile app (iOS/Android).",
                "method": "POST",
                "path": "/api/passkey/register/begin",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "device_name": "string (optional) - Name of the device/authenticator"
                },
                "request_example": {
                    "email": "user@example.com",
                    "device_name": "iPhone 15"
                },
                "response_success": {
                    "success": True,
                    "options": {
                        "rp": {"id": "slay.money", "name": "Slay Money"},
                        "user": {"id": "...", "name": "user@example.com", "displayName": "John Doe"},
                        "challenge": "...",
                        "pubKeyCredParams": [...],
                        "authenticatorSelection": {...},
                        "timeout": 60000
                    },
                    "device_name": "iPhone 15"
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (user not found, email not verified, etc.)"
                },
                "status_codes": {
                    "200": "Registration options generated successfully",
                    "400": "Bad request (invalid email format, email not verified, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "User must be registered and email verified",
                    "Challenge expires after 5 minutes",
                    "Mobile app should use the returned options with platform WebAuthn API (iOS: ASAuthorizationController, Android: Fido2ApiClient)",
                    "After creating credential, call /api/passkey/register/complete"
                ]
            },
            "POST /api/passkey/register/complete": {
                "description": "Complete passkey registration. Verifies and stores the passkey credential from mobile app (iOS/Android).",
                "method": "POST",
                "path": "/api/passkey/register/complete",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "credential": "object (required) - WebAuthn credential object from mobile app WebAuthn API (iOS/Android)",
                    "device_name": "string (optional) - Name of the device/authenticator"
                },
                "request_example": {
                    "email": "user@example.com",
                    "credential": {
                        "id": "...",
                        "rawId": "...",
                        "response": {...},
                        "type": "public-key"
                    },
                    "device_name": "iPhone 15"
                },
                "response_success": {
                    "success": True,
                    "message": "Passkey registered successfully! 🎉",
                    "credential_id": "..."
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (verification failed, session expired, etc.)"
                },
                "status_codes": {
                    "200": "Passkey registered successfully",
                    "400": "Bad request (verification failed, invalid credential, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "Must be called after /api/passkey/register/begin",
                    "Credential is stored securely in the database",
                    "User can now use this passkey for authentication"
                ]
            },
            "POST /api/passkey/login/begin": {
                "description": "Begin passkey authentication process. Generates WebAuthn authentication options for mobile app (iOS/Android).",
                "method": "POST",
                "path": "/api/passkey/login/begin",
                "request_body": {
                    "email": "string (required) - User's email address"
                },
                "request_example": {
                    "email": "user@example.com"
                },
                "response_success": {
                    "success": True,
                    "options": {
                        "rpId": "slay.money",
                        "challenge": "...",
                        "allowCredentials": [...],
                        "userVerification": "preferred",
                        "timeout": 60000
                    }
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (user not found, email not verified, etc.)"
                },
                "status_codes": {
                    "200": "Authentication options generated successfully",
                    "400": "Bad request (invalid email format, email not verified, etc.)",
                    "404": "User not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "If email is provided, only returns options for that user's credentials",
                    "If email is not provided, returns options for all credentials (discoverable login)",
                    "Challenge expires after 5 minutes",
                    "Mobile app should use the returned options with platform WebAuthn API (iOS: ASAuthorizationController, Android: Fido2ApiClient)",
                    "After authenticating, call /api/passkey/login/complete"
                ]
            },
            "POST /api/passkey/login/complete": {
                "description": "Complete passkey authentication. Verifies the passkey from mobile app (iOS/Android) and logs the user in.",
                "method": "POST",
                "path": "/api/passkey/login/complete",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "credential": "object (required) - WebAuthn credential object from mobile app WebAuthn API (iOS/Android)"
                },
                "request_example": {
                    "email": "user@example.com",
                    "credential": {
                        "id": "...",
                        "rawId": "...",
                        "response": {...},
                        "type": "public-key"
                    }
                },
                "response_success": {
                    "success": True,
                    "message": "Passkey login successful! 🎉",
                    "user": {
                        "email": "user@example.com",
                        "full_name": "John Doe",
                        "username": "johndoe",
                        "email_verified": True,
                        "created_at": "2024-01-01T00:00:00.000000"
                    }
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (verification failed, credential not found, etc.)"
                },
                "status_codes": {
                    "200": "Login successful",
                    "400": "Bad request (verification failed, invalid credential, etc.)",
                    "404": "User or credential not found",
                    "500": "Internal server error"
                },
                "notes": [
                    "Must be called after /api/passkey/login/begin",
                    "Sign count is updated after successful authentication",
                    "Returns user information on successful login",
                    "Email is required for authentication"
                ]
            },
            "POST /api/validate-username": {
                "description": "Validate a username and recommend alternatives if it's not valid or already taken",
                "method": "POST",
                "path": "/api/validate-username",
                "request_body": {
                    "username": "string (required) - Desired username to validate",
                    "email": "string (required) - User's email address that this username should be associated with"
                },
                "request_example": {
                    "username": "cool_username",
                    "email": "user@example.com"
                },
                "response_success_valid": {
                    "success": True,
                    "valid": True,
                    "available": True,
                    "username": "cool_username"
                },
                "response_success_invalid_or_taken": {
                    "success": True,
                    "valid": False,
                    "available": False,
                    "username": "cool_username",
                    "message": "Username is already taken.",
                    "suggestions": [
                        "cool_username1",
                        "cool_username_23"
                    ],
                    "recommended_username": "cool_username_23"
                },
                "status_codes": {
                    "200": "Request processed successfully (username details returned regardless of validity)",
                    "400": "Bad request (missing username field)",
                    "500": "Internal server error"
                },
                "notes": [
                    "Usernames must be 3-20 characters long",
                    "Allowed characters: letters, numbers, dots, and underscores",
                    "Usernames cannot start or end with a dot or underscore",
                    "If username is invalid or taken, suggestions are returned",
                    "If username is valid and available, it is stored in Supabase for the given email",
                    "If username is invalid or taken, a recommended_username is returned that is checked for availability"
                ]
            },
            "POST /api/verify-invite-code": {
                "description": "Verify invite code for user registration and update Supabase to mark user as invited",
                "method": "POST",
                "path": "/api/verify-invite-code",
                "request_body": {
                    "email": "string (required) - User's email address",
                    "invite_code": "string (required) - Invite code (must be SLAY1111)"
                },
                "request_example": {
                    "email": "user@example.com",
                    "invite_code": "SLAY1111"
                },
                "response_success": {
                    "success": True,
                    "message": "Invite code verified successfully! 🎉",
                    "email": "user@example.com",
                    "invited": True
                },
                "response_error": {
                    "success": False,
                    "error": "Error message (invalid invite code, invalid email format, etc.)"
                },
                "status_codes": {
                    "200": "Invite code verified successfully and user marked as invited in Supabase",
                    "400": "Bad request (invalid invite code, invalid email format, missing fields)",
                    "500": "Internal server error"
                },
                "notes": [
                    "The valid invite code is: SLAY1111",
                    "Email format is validated before invite code verification",
                    "If user exists in Supabase, their record is updated with invited=True and invited_at timestamp",
                    "If user doesn't exist, a new user record is created with invited=True",
                    "If user is already invited, returns success with already_invited flag"
                ]
            },
            "GET /api/user/<email>": {
                "description": "Get user verification status (for testing/debugging)",
                "method": "GET",
                "path": "/api/user/<email>",
                "path_parameters": {
                    "email": "string (required) - User's email address (URL encoded)"
                },
                "example_path": "/api/user/user%40example.com",
                "response_success": {
                    "success": True,
                    "user": {
                        "email": "user@example.com",
                        "full_name": "John Doe",
                        "email_verified": True,
                        "created_at": "2024-01-01T00:00:00.000000",
                        "verified_at": "2024-01-01T00:05:00.000000"
                    }
                },
                "response_error": {
                    "success": False,
                    "error": "User not found"
                },
                "status_codes": {
                    "200": "User found",
                    "404": "User not found",
                    "500": "Internal server error"
                }
            }
        },
        "authentication": {
            "type": "None",
            "note": "This API does not require authentication. All endpoints are publicly accessible."
        },
        "error_handling": {
            "format": "All error responses follow this format:",
            "example": {
                "success": False,
                "error": "Descriptive error message"
            },
            "common_status_codes": {
                "400": "Bad Request - Invalid input or validation error",
                "404": "Not Found - Resource not found",
                "500": "Internal Server Error - Server-side error"
            }
        },
        "rate_limiting": {
            "note": "Rate limiting may be implemented in production. Check response headers for rate limit information."
        },
        "email_service": {
            "provider": "Resend",
            "verification_code_expiry": "15 minutes",
            "code_format": "6-digit numeric code",
            "documentation": "https://resend.com/docs"
        },
        "database": {
            "provider": "Supabase",
            "note": "User data is stored in Supabase database"
        },
        "examples": {
            "register_user": {
                "curl": "curl -X POST http://localhost:5000/api/register -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"full_name\":\"John Doe\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/register', json={'email': 'user@example.com', 'full_name': 'John Doe'})"
            },
            "verify_email": {
                "curl": "curl -X POST http://localhost:5000/api/verify-email -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"code\":\"123456\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/verify-email', json={'email': 'user@example.com', 'code': '123456'})"
            },
            "resend_code": {
                "curl": "curl -X POST http://localhost:5000/api/resend-code -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/resend-code', json={'email': 'user@example.com'})"
            },
            "verify_invite_code": {
                "curl": "curl -X POST http://localhost:5000/api/verify-invite-code -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"invite_code\":\"SLAY1111\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/verify-invite-code', json={'email': 'user@example.com', 'invite_code': 'SLAY1111'})"
            },
            "login_request_otp": {
                "curl": "curl -X POST http://localhost:5000/api/login/request-otp -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/login/request-otp', json={'email': 'user@example.com'})"
            },
            "login_verify_otp": {
                "curl": "curl -X POST http://localhost:5000/api/login/verify-otp -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"otp\":\"123456\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/login/verify-otp', json={'email': 'user@example.com', 'otp': '123456'})"
            },
            "passkey_register_begin": {
                "curl": "curl -X POST http://localhost:5000/api/passkey/register/begin -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"device_name\":\"iPhone 15\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/passkey/register/begin', json={'email': 'user@example.com', 'device_name': 'iPhone 15'})",
                "note": "Use the returned options with mobile app WebAuthn API (iOS: ASAuthorizationController, Android: Fido2ApiClient)"
            },
            "passkey_register_complete": {
                "curl": "curl -X POST http://localhost:5000/api/passkey/register/complete -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"credential\":{...},\"device_name\":\"iPhone 15\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/passkey/register/complete', json={'email': 'user@example.com', 'credential': credential_object, 'device_name': 'iPhone 15'})",
                "note": "Credential object comes from mobile app WebAuthn API response (iOS/Android)"
            },
            "passkey_login_begin": {
                "curl": "curl -X POST http://localhost:5000/api/passkey/login/begin -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\"}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/passkey/login/begin', json={'email': 'user@example.com'})",
                "note": "Use the returned options with mobile app WebAuthn API (iOS: ASAuthorizationController, Android: Fido2ApiClient)"
            },
            "passkey_login_complete": {
                "curl": "curl -X POST http://localhost:5000/api/passkey/login/complete -H 'Content-Type: application/json' -d '{\"email\":\"user@example.com\",\"credential\":{...}}'",
                "python": "import requests\nresponse = requests.post('http://localhost:5000/api/passkey/login/complete', json={'email': 'user@example.com', 'credential': credential_object})",
                "note": "Credential object comes from mobile app WebAuthn API response (iOS/Android)"
            }
        },
        "support": {
            "documentation": "See RESEND_SETUP.md for setup instructions",
            "resend_docs": "https://resend.com/docs"
        }
    }
    # Remove Ellipsis objects to make JSON serializable
    cleaned_docs_data = remove_ellipsis(docs_data)
    return jsonify(cleaned_docs_data), 200

@app.route('/docs/html', methods=['GET'])
def api_docs_html():
    """Interactive HTML API documentation"""
    base_url = request.host_url.rstrip('/')
    
    # Get the same docs data as /docs endpoint by calling it internally
    from flask import render_template_string
    import json
    
    # Call the api_docs function to get the data
    # We'll use Flask's test client to call our own endpoint
    with app.test_client() as client:
        try:
            response = client.get('/docs')
            if response.status_code == 200:
                docs_data = response.get_json()
            else:
                docs_data = {"endpoints": {}}
        except Exception as e:
            # Fallback if something goes wrong
            docs_data = {"endpoints": {}}
    
    # Clean the data and prepare JSON
    cleaned_docs_data = remove_ellipsis(docs_data)
    endpoints_json = json.dumps(cleaned_docs_data.get("endpoints", {}))
    
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - {{ version }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .header .version {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            margin-top: 10px;
            font-size: 0.9em;
        }
        
        .content {
            padding: 40px;
        }
        
        .search-box {
            margin-bottom: 30px;
        }
        
        .search-box input {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            transition: border-color 0.3s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .endpoint-group {
            margin-bottom: 30px;
        }
        
        .endpoint-card {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.3s;
        }
        
        .endpoint-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .endpoint-header {
            background: #f8f9fa;
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }
        
        .endpoint-header:hover {
            background: #f0f0f0;
        }
        
        .endpoint-method {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
            margin-right: 10px;
        }
        
        .method-get { background: #61affe; color: white; }
        .method-post { background: #49cc90; color: white; }
        .method-put { background: #fca130; color: white; }
        .method-delete { background: #f93e3e; color: white; }
        
        .endpoint-path {
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            font-weight: 600;
            flex-grow: 1;
        }
        
        .endpoint-toggle {
            font-size: 1.5em;
            transition: transform 0.3s;
        }
        
        .endpoint-toggle.open {
            transform: rotate(180deg);
        }
        
        .endpoint-content {
            padding: 0 20px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out, padding 0.3s;
        }
        
        .endpoint-content.open {
            max-height: 5000px;
            padding: 20px;
        }
        
        .endpoint-section {
            margin-bottom: 20px;
        }
        
        .endpoint-section h4 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            position: relative;
            margin: 10px 0;
        }
        
        .code-block code {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre;
        }
        
        .copy-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #667eea;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            transition: background 0.3s;
        }
        
        .copy-btn:hover {
            background: #5568d3;
        }
        
        .copy-btn.copied {
            background: #49cc90;
        }
        
        .json-example {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .json-example pre {
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .status-code {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .status-200 { background: #49cc90; color: white; }
        .status-201 { background: #49cc90; color: white; }
        .status-400 { background: #fca130; color: white; }
        .status-404 { background: #f93e3e; color: white; }
        .status-500 { background: #f93e3e; color: white; }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 5px;
        }
        
        .badge-required { background: #f93e3e; color: white; }
        .badge-optional { background: #61affe; color: white; }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        
        .info-box.warning {
            background: #fff3e0;
            border-left-color: #ff9800;
        }
        
        .info-box.success {
            background: #e8f5e9;
            border-left-color: #4caf50;
        }
        
        .hidden {
            display: none;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .content {
                padding: 20px;
            }
            
            .endpoint-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .endpoint-path {
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p>{{ description }}</p>
            <span class="version">Version {{ version }}</span>
        </div>
        
        <div class="content">
            <div class="info-box success" style="margin-bottom: 30px;">
                <h4 style="margin-top: 0; color: #2e7d32;">📚 How to Use This Documentation</h4>
                <p><strong>Welcome to the Interactive API Documentation!</strong> This page provides a comprehensive, searchable interface for exploring all available API endpoints.</p>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>Search Endpoints:</strong> Use the search box above to filter endpoints by name, method (GET, POST, etc.), or path</li>
                    <li><strong>View Details:</strong> Click on any endpoint card to expand and see detailed information including request/response examples</li>
                    <li><strong>Copy Examples:</strong> Click the "Copy" button on any code block to copy request/response examples to your clipboard</li>
                    <li><strong>Browse by Category:</strong> Endpoints are automatically grouped by category (Authentication, Passkey, User Management, etc.)</li>
                    <li><strong>Status Codes:</strong> Each endpoint shows color-coded HTTP status codes with descriptions</li>
                </ul>
                <p style="margin-bottom: 0;"><strong>💡 Tip:</strong> For programmatic access to this documentation, use the <code>/docs</code> endpoint which returns JSON format.</p>
            </div>
            
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search endpoints by name, method, or path...">
            </div>
            
            <div id="endpointsContainer">
                <!-- Endpoints will be dynamically inserted here -->
            </div>
        </div>
        
        <div class="footer">
            <p>Base URL: <code>{{ base_url }}</code></p>
            <p>For JSON documentation, visit <a href="/docs">/docs</a> | You are currently viewing the <a href="/docs/html">HTML documentation</a></p>
            <p style="margin-top: 10px; font-size: 0.9em; color: #999;">This interactive documentation is automatically generated from the API endpoints. All examples are based on the current API structure.</p>
        </div>
    </div>
    
    <script>
        const baseUrl = '{{ base_url }}';
        
        // Use embedded endpoints data
        try {
            const endpointsData = {{ endpoints_json|safe }};
            if (endpointsData && Object.keys(endpointsData).length > 0) {
                renderEndpoints(endpointsData);
            } else {
                // Fallback: try fetching from /docs endpoint
                fetch(baseUrl + '/docs')
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data && data.endpoints) {
                            renderEndpoints(data.endpoints);
                        } else {
                            throw new Error('Invalid response format: missing endpoints');
                        }
                    })
                    .catch(error => {
                        console.error('Error loading documentation:', error);
                        const errorMsg = error.message || 'Unknown error occurred';
                        document.getElementById('endpointsContainer').innerHTML = 
                            '<div class="info-box warning">' +
                            '<h4>Error loading documentation</h4>' +
                            '<p>' + errorMsg + '</p>' +
                            '<p>Please check the mobile app logs or API response for more details.</p>' +
                            '<p>Try visiting <a href="/docs" target="_blank">/docs</a> to verify the API is working.</p>' +
                            '</div>';
                    });
            }
        } catch (error) {
            console.error('Error parsing endpoints data:', error);
            document.getElementById('endpointsContainer').innerHTML = 
                '<div class="info-box warning">Error parsing documentation data. Please try again.</div>';
        }
        
        function renderEndpoints(endpoints) {
            const container = document.getElementById('endpointsContainer');
            let html = '';
            
            // Group endpoints by category
            const categories = {
                'General': [],
                'Authentication': [],
                'Passkey': [],
                'User Management': []
            };
            
            for (const [key, endpoint] of Object.entries(endpoints)) {
                const method = endpoint.method || key.split(' ')[0];
                const path = endpoint.path || key.split(' ').slice(1).join(' ');
                
                let category = 'General';
                if (path.includes('login') || path.includes('verify-email') || path.includes('register')) {
                    category = 'Authentication';
                } else if (path.includes('passkey')) {
                    category = 'Passkey';
                } else if (path.includes('user') || path.includes('username')) {
                    category = 'User Management';
                }
                
                categories[category].push({key, endpoint, method, path});
            }
            
            // Render by category
            for (const [categoryName, categoryEndpoints] of Object.entries(categories)) {
                if (categoryEndpoints.length === 0) continue;
                
                html += `<div class="endpoint-group">
                    <h2 style="color: #667eea; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e0e0e0;">${categoryName}</h2>`;
                
                categoryEndpoints.forEach(({key, endpoint, method, path}) => {
                    html += renderEndpoint(key, endpoint, method, path);
                });
                
                html += '</div>';
            }
            
            container.innerHTML = html;
            attachEventListeners();
        }
        
        function renderEndpoint(key, endpoint, method, path) {
            const methodClass = `method-${method.toLowerCase()}`;
            const endpointId = key.replace(/[^a-zA-Z0-9]/g, '_');
            
            let html = `
                <div class="endpoint-card" data-endpoint="${key.toLowerCase()}">
                    <div class="endpoint-header" onclick="toggleEndpoint('${endpointId}')">
                        <div>
                            <span class="endpoint-method ${methodClass}">${method}</span>
                            <span class="endpoint-path">${path}</span>
                        </div>
                        <span class="endpoint-toggle" id="toggle_${endpointId}">▼</span>
                    </div>
                    <div class="endpoint-content" id="content_${endpointId}">
            `;
            
            if (endpoint.description) {
                html += `<div class="endpoint-section">
                    <h4>Description</h4>
                    <p>${endpoint.description}</p>
                </div>`;
            }
            
            if (endpoint.request_body) {
                html += `<div class="endpoint-section">
                    <h4>Request Body</h4>
                    <div class="json-example"><pre>${formatObject(endpoint.request_body)}</pre></div>
                </div>`;
            }
            
            if (endpoint.request_example) {
                html += `<div class="endpoint-section">
                    <h4>Request Example</h4>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyToClipboard(this, ${JSON.stringify(JSON.stringify(endpoint.request_example, null, 2))})">Copy</button>
                        <code>${JSON.stringify(endpoint.request_example, null, 2)}</code>
                    </div>
                </div>`;
            }
            
            if (endpoint.response_example || endpoint.response_success) {
                const response = endpoint.response_example || endpoint.response_success;
                html += `<div class="endpoint-section">
                    <h4>Response Example</h4>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyToClipboard(this, ${JSON.stringify(JSON.stringify(response, null, 2))})">Copy</button>
                        <code>${JSON.stringify(response, null, 2)}</code>
                    </div>
                </div>`;
            }
            
            if (endpoint.status_codes) {
                html += `<div class="endpoint-section">
                    <h4>Status Codes</h4>`;
                for (const [code, description] of Object.entries(endpoint.status_codes)) {
                    html += `<div style="margin: 5px 0;">
                        <span class="status-code status-${code}">${code}</span>
                        <span>${description}</span>
                    </div>`;
                }
                html += `</div>`;
            }
            
            if (endpoint.notes) {
                html += `<div class="endpoint-section">
                    <h4>Notes</h4>
                    <ul>`;
                endpoint.notes.forEach(note => {
                    html += `<li>${note}</li>`;
                });
                html += `</ul></div>`;
            }
            
            html += `</div></div>`;
            return html;
        }
        
        function formatObject(obj) {
            if (typeof obj === 'string') {
                return obj;
            }
            return JSON.stringify(obj, null, 2);
        }
        
        function toggleEndpoint(id) {
            const content = document.getElementById('content_' + id);
            const toggle = document.getElementById('toggle_' + id);
            
            content.classList.toggle('open');
            toggle.classList.toggle('open');
        }
        
        function copyToClipboard(btn, text) {
            navigator.clipboard.writeText(text).then(() => {
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 2000);
            });
        }
        
        function attachEventListeners() {
            // Search functionality
            const searchInput = document.getElementById('searchInput');
            searchInput.addEventListener('input', (e) => {
                const searchTerm = e.target.value.toLowerCase();
                const cards = document.querySelectorAll('.endpoint-card');
                
                cards.forEach(card => {
                    const text = card.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        }
    </script>
</body>
</html>
    """
    
    return render_template_string(html_template, 
                                 title="Mobile App Backend API Documentation",
                                 version="3.0.0 (Resend Edition)",
                                 description="A RESTful API backend for mobile applications (iOS/Android) providing email verification, passwordless authentication (OTP + Passkeys), and user management using Resend email service and Supabase database",
                                 base_url=base_url,
                                 endpoints_json=endpoints_json)

# Root endpoint
@app.route('/', methods=['GET'])
def index():
    """API information endpoint"""
    return jsonify({
        "service": "Mobile App Backend API - Email Verification & Authentication",
        "version": "3.0.0 (Resend Edition)",
        "email_provider": "Resend",
        "client": "Mobile Applications (iOS/Android)",
        "endpoints": {
            "docs": "GET /docs - Comprehensive API documentation (JSON)",
            "docs_html": "GET /docs/html - Interactive HTML API documentation",
            "health": "GET /api/health",
            "config": "GET /api/config",
            "register": "POST /api/register",
            "verify": "POST /api/verify-email",
            "resend": "POST /api/resend-code",
            "login_request_otp": "POST /api/login/request-otp",
            "login_verify_otp": "POST /api/login/verify-otp",
            "passkey_register_begin": "POST /api/passkey/register/begin",
            "passkey_register_complete": "POST /api/passkey/register/complete",
            "passkey_login_begin": "POST /api/passkey/login/begin",
            "passkey_login_complete": "POST /api/passkey/login/complete",
            "validate_username": "POST /api/validate-username",
            "verify_invite": "POST /api/verify-invite-code",
            "user_status": "GET /api/user/<email>"
        },
        "documentation": "GET /docs for JSON documentation, GET /docs/html for interactive HTML documentation, or see RESEND_SETUP.md for setup instructions"
    }), 200

if __name__ == '__main__':
    # Load environment variables from .env file
    from dotenv import load_dotenv
    load_dotenv()
    
    # Re-load variables after dotenv
    RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
    FROM_EMAIL = os.getenv("FROM_EMAIL", "onboarding@resend.dev")
    
    # Display configuration on startup
    print("\n" + "="*70)
    print("🚀 MOBILE APP BACKEND API - RESEND EDITION")
    print("="*70)
    print(f"Email Provider: Resend (https://resend.com)")
    print(f"From Email: {FROM_EMAIL}")
    print(f"Resend API Key: {'✅ Configured' if RESEND_API_KEY else '❌ Not Set'}")
    print(f"Supabase URL: {SUPABASE_URL[:40] + '...' if len(SUPABASE_URL) > 40 else SUPABASE_URL}")
    print(f"Supabase Key: {'✅ Configured' if SUPABASE_KEY else '❌ Not Set'}")
    print(f"RP ID (Relying Party): {RP_ID}")
    print(f"Client: Mobile Apps (iOS/Android)")
    print("="*70)
    
    if not RESEND_API_KEY:
        print("\n⚠️  WARNING: RESEND_API_KEY not set!")
        print("Get your API key from: https://resend.com/api-keys")
        print("Add it to your .env file: RESEND_API_KEY=re_xxxxxxxxxxxx\n")
    
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("\n⚠️  WARNING: Supabase credentials not set!")
        print("Add them to your .env file\n")
    
    # Run the Flask app
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"\n✅ Server starting on http://localhost:{port}")
    print(f"📚 API Documentation (JSON): http://localhost:{port}/docs")
    print(f"🌐 API Documentation (HTML): http://localhost:{port}/docs/html")
    print(f"📖 API Info: http://localhost:{port}/")
    print(f"❤️  Health Check: http://localhost:{port}/api/health")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
