"""
Email Verification API using Flask and Supabase - RESEND VERSION
Configured to use Resend API for professional email delivery
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import os
import random
import string
from datetime import datetime, timedelta
from typing import Optional
import threading
import requests

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Validate Supabase configuration
if not SUPABASE_URL or not SUPABASE_KEY:
    print("⚠️  WARNING: SUPABASE_URL or SUPABASE_KEY not set in environment variables")
    print("Please set them in your .env file")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Resend Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "re_VgndXmD1_GVpJezaQpNZU4M3B3uAnJ6XV")
FROM_EMAIL = os.getenv("FROM_EMAIL", "onboarding@resend.dev")  # Default Resend test email

# Helper Functions
def generate_verification_code(length: int = 6) -> str:
    """Generate a random numeric verification code"""
    return ''.join(random.choices(string.digits, k=length))

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

def validate_email(email: str) -> bool:
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

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
        "service": "Email Verification API (Resend)",
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
    
    Request Body:
    {
        "email": "user@example.com",
        "full_name": "John Doe" (optional)
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        full_name = data.get('full_name')
        
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
        
        # Send verification email via Resend in background
        send_email_background(email, verification_code, full_name)
        
        return jsonify({
            "success": True,
            "message": "Registration successful. Please check your email for verification code.",
            "email": email,
            "note": "Check your inbox (and spam folder) for the verification email from Resend"
        }), 201
        
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
            expiry_time = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
            if datetime.utcnow() > expiry_time.replace(tzinfo=None):
                return jsonify({
                    "success": False,
                    "error": "Verification code expired. Please request a new code."
                }), 400
        
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
    return jsonify({
        "title": "Email Verification API Documentation",
        "version": "3.0.0 (Resend Edition)",
        "description": "A RESTful API for email verification using Resend email service and Supabase database",
        "base_url": request.host_url.rstrip('/'),
        "endpoints": {
            "GET /": {
                "description": "API information and endpoint list",
                "method": "GET",
                "path": "/",
                "response": {
                    "service": "Email Verification API",
                    "version": "3.0.0 (Resend Edition)",
                    "endpoints": "List of all available endpoints"
                }
            },
            "GET /docs": {
                "description": "This comprehensive API documentation",
                "method": "GET",
                "path": "/docs"
            },
            "GET /api/health": {
                "description": "Health check endpoint to verify API status and configuration",
                "method": "GET",
                "path": "/api/health",
                "response_example": {
                    "status": "healthy",
                    "service": "Email Verification API (Resend)",
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
            }
        },
        "support": {
            "documentation": "See RESEND_SETUP.md for setup instructions",
            "resend_docs": "https://resend.com/docs"
        }
    }), 200

# Root endpoint
@app.route('/', methods=['GET'])
def index():
    """API information endpoint"""
    return jsonify({
        "service": "Email Verification API",
        "version": "3.0.0 (Resend Edition)",
        "email_provider": "Resend",
        "endpoints": {
            "docs": "GET /docs - Comprehensive API documentation",
            "health": "GET /api/health",
            "config": "GET /api/config",
            "register": "POST /api/register",
            "verify": "POST /api/verify-email",
            "resend": "POST /api/resend-code",
            "user_status": "GET /api/user/<email>"
        },
        "documentation": "GET /docs for full API documentation or see RESEND_SETUP.md for setup instructions"
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
    print("🚀 EMAIL VERIFICATION API - RESEND EDITION")
    print("="*70)
    print(f"Email Provider: Resend (https://resend.com)")
    print(f"From Email: {FROM_EMAIL}")
    print(f"Resend API Key: {'✅ Configured' if RESEND_API_KEY else '❌ Not Set'}")
    print(f"Supabase URL: {SUPABASE_URL[:40] + '...' if len(SUPABASE_URL) > 40 else SUPABASE_URL}")
    print(f"Supabase Key: {'✅ Configured' if SUPABASE_KEY else '❌ Not Set'}")
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
    print(f"📚 API Documentation: http://localhost:{port}/docs")
    print(f"📖 API Info: http://localhost:{port}/")
    print(f"❤️  Health Check: http://localhost:{port}/api/health")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
