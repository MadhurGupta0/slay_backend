"""
Email Verification API using Flask and Supabase
Handles new user registration and email 
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
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "your-project-url.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Helper Functions
def generate_verification_code(length: int = 6) -> str:
    """Generate a random numeric verification code"""
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(email: str, code: str, full_name: Optional[str] = None):
    """
    Send verification email using Supabase Edge Function or SMTP
    This function should be customized based on your email service
    """
    try:
        # Option 1: Using Supabase Edge Function
        response = supabase.functions.invoke(
            "send-verification-email",
            invoke_options={
                "body": {
                    "email": email,
                    "code": code,
                    "full_name": full_name
                }
            }
        )
        return response
    except Exception as e:
        print(f"Error sending email: {e}")
        raise Exception("Failed to send verification email")

def send_email_background(email: str, code: str, full_name: Optional[str] = None):
    """Send email in background thread"""
    thread = threading.Thread(target=send_verification_email, args=(email, code, full_name))
    thread.daemon = True
    thread.start()

def validate_email(email: str) -> bool:
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "Valid"

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
    return jsonify({
        "status": "healthy",
        "service": "Email Verification API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/api/register', methods=['POST'])
def register_user():
    """
    Register a new user and send verification code
    
    Request Body:
    {
        "email": "user@example.com",
        "password": "SecurePass123!",
        "full_name": "John Doe" (optional)
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name')
        
        # Validate required fields
        if not email or not password:
            return jsonify({
                "success": False,
                "error": "Email and password are required"
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({
                "success": False,
                "error": message
            }), 400
        
        # Check if user already exists
        existing_user = supabase.table("users").select("*").eq("email", email).execute()
        
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
            "password_hash": password,  # In production, hash this with bcrypt!
            "full_name": full_name,
            "email_verified": False,
            "verification_code": verification_code,
            "verification_code_expiry": expiry_time.isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        insert_response = supabase.table("users").insert(user_data).execute()
        
        # Send verification email in background
        send_email_background(email, verification_code, full_name)
        
        return jsonify({
            "success": True,
            "message": "Registration successful. Please check your email for verification code.",
            "email": email
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
        user_response = supabase.table("users").select("*").eq("email", email).execute()
        
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
        update_response = supabase.table("users").update({
            "email_verified": True,
            "verified_at": datetime.utcnow().isoformat(),
            "verification_code": None,
            "verification_code_expiry": None
        }).eq("email", email).execute()
        
        return jsonify({
            "success": True,
            "message": "Email verified successfully!",
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
    Resend verification code to user's email
    
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
    user_response = supabase.table("users").select("*").eq("email", email).execute()
    
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
    supabase.table("users").update({
        "verification_code": new_code,
        "verification_code_expiry": new_expiry.isoformat()
    }).eq("email", email).execute()
    
    # Send email in background
    send_email_background(email, new_code, user.get("full_name"))
    
    return jsonify({
        "success": True,
        "message": "Verification code resent. Please check your email.",
        "email": email
    }), 200

@app.route('/api/user/<email>', methods=['GET'])
def get_user_status(email):
    """
    Get user verification status (for testing/debugging)
    """
    try:
        user_response = supabase.table("users").select(
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

@app.route('/docs', methods=['GET'])
def api_docs():
    """Return API documentation (paths, methods, request/response examples)."""
    docs = {
        "service": "Email Verification API",
        "version": "1.0.0",
        "endpoints": [
            {
                "path": "/api/health",
                "method": "GET",
                "description": "Health check",
                "request_example": None,
                "response_example": {
                    "status": "healthy",
                    "service": "Email Verification API",
                    "version": "1.0.0",
                    "timestamp": "2025-12-16T00:00:00.000000"
                },
                "status_codes": [200]
            },
            {
                "path": "/api/register",
                "method": "POST",
                "description": "Register a new user and send verification code",
                "request_example": {
                    "email": "user@example.com",
                    "password": "SecurePass123!",
                    "full_name": "John Doe"
                },
                "response_example": {
                    "success": True,
                    "message": "Registration successful. Please check your email for verification code.",
                    "email": "user@example.com"
                },
                "error_examples": [
                    {"status":400, "body": {"success": False, "error": "Email and password are required"}},
                    {"status":400, "body": {"success": False, "error": "Invalid email format"}},
                    {"status":400, "body": {"success": False, "error": "Password must be at least 8 characters long"}},
                    {"status":500, "body": {"success": False, "error": "Registration failed: <reason>"}}
                ],
                "status_codes": [201, 400, 500]
            },
            {
                "path": "/api/verify-email",
                "method": "POST",
                "description": "Verify user email with provided code",
                "request_example": {
                    "email": "user@example.com",
                    "code": "123456"
                },
                "response_example": {
                    "success": True,
                    "message": "Email verified successfully!",
                    "email": "user@example.com"
                },
                "error_examples": [
                    {"status":400, "body": {"success": False, "error": "Email and code are required"}},
                    {"status":400, "body": {"success": False, "error": "Invalid verification code"}},
                    {"status":400, "body": {"success": False, "error": "Verification code expired. Please request a new code."}},
                    {"status":404, "body": {"success": False, "error": "User not found"}},
                    {"status":500, "body": {"success": False, "error": "Verification failed: <reason>"}}
                ],
                "status_codes": [200, 400, 404, 500]
            },
            {
                "path": "/api/resend-code",
                "method": "POST",
                "description": "Resend verification code to user's email",
                "request_example": {"email": "user@example.com"},
                "response_example": {"success": True, "message": "Verification code resent. Please check your email.", "email": "user@example.com"},
                "error_examples": [
                    {"status":400, "body": {"success": False, "error": "Email is required"}},
                    {"status":404, "body": {"success": False, "error": "User not found"}},
                    {"status":500, "body": {"success": False, "error": "Failed to resend code: <reason>"}}
                ],
                "status_codes": [200, 400, 404, 500]
            },
            {
                "path": "/api/user/<email>",
                "method": "GET",
                "description": "Get user verification status",
                "request_example": None,
                "response_example": {
                    "success": True,
                    "user": {
                        "email": "user@example.com",
                        "full_name": "John Doe",
                        "email_verified": False,
                        "created_at": "2025-12-16T00:00:00.000000",
                        "verified_at": None
                    }
                },
                "status_codes": [200, 404, 500]
            }
        ]
    }

    return jsonify(docs), 200

# Root endpoint
@app.route('/', methods=['GET'])
def index():
    """API information endpoint"""
    return jsonify({
        "service": "Email Verification API",
        "version": "1.0.0",
        "endpoints": {
            "health": "GET /api/health",
            "register": "POST /api/register",
            "verify": "POST /api/verify-email",
            "resend": "POST /api/resend-code",
            "user_status": "GET /api/user/<email>"
        },
        "documentation": "See README.md for detailed API documentation"
    }), 200

if __name__ == '__main__':
    # Load environment variables from .env file
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run the Flask app
    port = int(os.getenv('PORT', 8000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"Starting Email Verification API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=debug)
