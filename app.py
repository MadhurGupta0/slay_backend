"""
Email Verification API using Supabase
Handles new user registration and email verification
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
import os
import random
import string
from datetime import datetime, timedelta
from typing import Optional
import uvicorn

# Initialize FastAPI app
app = FastAPI(title="Email Verification API", version="1.0.0")

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "your-project-url.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Models
class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class VerifyCode(BaseModel):
    email: EmailStr
    code: str

class ResendCode(BaseModel):
    email: EmailStr

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
        # You'll need to create an Edge Function for sending emails
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
        raise HTTPException(status_code=500, detail="Failed to send verification email")

# API Endpoints

@app.post("/api/register")
async def register_user(user: UserRegistration, background_tasks: BackgroundTasks):
    """
    Register a new user and send verification code
    """
    try:
        # Check if user already exists
        existing_user = supabase.table("users").select("*").eq("email", user.email).execute()
        
        if existing_user.data and len(existing_user.data) > 0:
            # Check if already verified
            if existing_user.data[0].get("email_verified"):
                raise HTTPException(status_code=400, detail="Email already registered and verified")
            else:
                # User exists but not verified, resend code
                return await resend_verification_code(ResendCode(email=user.email))
        
        # Generate verification code
        verification_code = generate_verification_code()
        expiry_time = datetime.utcnow() + timedelta(minutes=15)  # Code expires in 15 minutes
        
        # Create user record (unverified)
        user_data = {
            "email": user.email,
            "password_hash": user.password,  # In production, hash this with bcrypt!
            "full_name": user.full_name,
            "email_verified": False,
            "verification_code": verification_code,
            "verification_code_expiry": expiry_time.isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        insert_response = supabase.table("users").insert(user_data).execute()
        
        # Send verification email in background
        background_tasks.add_task(send_verification_email, user.email, verification_code, user.full_name)
        
        return {
            "success": True,
            "message": "Registration successful. Please check your email for verification code.",
            "email": user.email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/api/verify-email")
async def verify_email(verify_data: VerifyCode):
    """
    Verify user email with the provided code
    """
    try:
        # Fetch user with verification code
        user_response = supabase.table("users").select("*").eq("email", verify_data.email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = user_response.data[0]
        
        # Check if already verified
        if user.get("email_verified"):
            return {
                "success": True,
                "message": "Email already verified"
            }
        
        # Check verification code
        if user.get("verification_code") != verify_data.code:
            raise HTTPException(status_code=400, detail="Invalid verification code")
        
        # Check if code expired
        expiry_time = datetime.fromisoformat(user.get("verification_code_expiry").replace('Z', '+00:00'))
        if datetime.utcnow() > expiry_time.replace(tzinfo=None):
            raise HTTPException(status_code=400, detail="Verification code expired. Please request a new code.")
        
        # Update user as verified
        update_response = supabase.table("users").update({
            "email_verified": True,
            "verified_at": datetime.utcnow().isoformat(),
            "verification_code": None,  # Clear the code
            "verification_code_expiry": None
        }).eq("email", verify_data.email).execute()
        
        return {
            "success": True,
            "message": "Email verified successfully!",
            "email": verify_data.email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.post("/api/resend-code")
async def resend_verification_code(resend_data: ResendCode, background_tasks: BackgroundTasks = BackgroundTasks()):
    """
    Resend verification code to user's email
    """
    try:
        # Fetch user
        user_response = supabase.table("users").select("*").eq("email", resend_data.email).execute()
        
        if not user_response.data or len(user_response.data) == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = user_response.data[0]
        
        # Check if already verified
        if user.get("email_verified"):
            raise HTTPException(status_code=400, detail="Email already verified")
        
        # Generate new verification code
        new_code = generate_verification_code()
        new_expiry = datetime.utcnow() + timedelta(minutes=15)
        
        # Update user with new code
        supabase.table("users").update({
            "verification_code": new_code,
            "verification_code_expiry": new_expiry.isoformat()
        }).eq("email", resend_data.email).execute()
        
        # Send email in background
        background_tasks.add_task(send_verification_email, resend_data.email, new_code, user.get("full_name"))
        
        return {
            "success": True,
            "message": "Verification code resent. Please check your email.",
            "email": resend_data.email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resend code: {str(e)}")


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "Email Verification API"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
