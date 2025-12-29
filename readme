# API Endpoints - Mobile App Backend Documentation

This document provides a comprehensive explanation of each endpoint in the Email Verification API backend for mobile applications (iOS/Android), how they work, and their internal mechanisms.

## Table of Contents
1. [System Overview](#system-overview)
2. [Health & Configuration Endpoints](#health--configuration-endpoints)
3. [Authentication & Registration Endpoints](#authentication--registration-endpoints)
4. [Email Verification Endpoints](#email-verification-endpoints)
5. [Login Endpoints](#login-endpoints)
6. [Passkey/WebAuthn Endpoints](#passkeywebauthn-endpoints)
7. [User Management Endpoints](#user-management-endpoints)
8. [Documentation Endpoints](#documentation-endpoints)

---

## System Overview

**Framework**: Flask (Python)
**Database**: Supabase (PostgreSQL)
**Email Service**: Resend API
**Authentication**: WebAuthn/Passkeys + OTP
**Client**: Mobile Applications (iOS/Android)

The API backend handles:
- User registration with email verification for mobile apps
- Passwordless authentication via OTP and Passkeys (iOS/Android compatible)
- Username validation and management
- Invite code verification
- Mobile device passkey registration and authentication

---

## Mobile App Integration

### Platform Support
- **iOS**: Uses `ASAuthorizationController` for Passkey/WebAuthn operations
- **Android**: Uses `Fido2ApiClient` for Passkey/WebAuthn operations
- Both platforms support OTP-based authentication via email

### API Communication
- All endpoints accept and return JSON
- Use standard HTTP methods (GET, POST)
- Include proper headers: `Content-Type: application/json`
- Handle network errors and timeouts appropriately
- Implement retry logic for failed requests

### Authentication Flow Recommendations
1. **Registration**: Register user → Verify email → Optional: Register passkey
2. **Login**: Request OTP OR use Passkey authentication
3. **Session Management**: Store user data securely on device after successful login

### Mobile-Specific Considerations
- **Network Handling**: Implement offline detection and queue requests if needed
- **Security**: Store sensitive data (tokens, user info) in secure storage (Keychain/Keystore)
- **Error Handling**: Provide user-friendly error messages for network and API errors
- **Push Notifications**: Consider implementing push notifications for OTP delivery (future enhancement)

---

## Health & Configuration Endpoints

### 1. `GET /api/health`

**Purpose**: Health check endpoint to verify API status and configuration

**How it works**:
1. Checks if Resend API key is configured
2. Checks if Supabase credentials are configured
3. Returns current system status with timestamp

**Response Structure**:
```json
{
  "status": "healthy",
  "service": "Email Verification API (Resend)",
  "version": "3.0.0 (Resend Edition)",
  "timestamp": "2024-01-01T00:00:00.000000",
  "configuration": {
    "email_provider": "Resend",
    "resend_configured": true,
    "supabase_configured": true,
    "from_email": "onboarding@slay.money"
  }
}
```

**Use Cases**:
- Mobile app startup health check
- Monitoring system health
- Verifying configuration during deployment
- Load balancer health checks

---

### 2. `GET /api/config`

**Purpose**: Get current API configuration details

**How it works**:
1. Returns static configuration information
2. Includes links to documentation
3. Shows which services are configured

**Response Structure**:
```json
{
  "email_provider": "Resend",
  "resend_configured": true,
  "supabase_configured": true,
  "from_email": "onboarding@slay.money",
  "resend_docs": "https://resend.com/docs",
  "setup_guide": "See RESEND_SETUP.md for configuration instructions"
}
```

**Use Cases**:
- Mobile app configuration (iOS/Android)
- Debugging configuration issues
- Setting up mobile client applications

---

## Authentication & Registration Endpoints

### 3. `POST /api/register`

**Purpose**: Register a new user and initiate email verification. Optionally registers a passkey simultaneously.

**Request Body**:
```json
{
  "email": "user@example.com",
  "full_name": "John Doe",           // Optional
  "credential": {...},                // Optional - WebAuthn credential
  "challenge": "...",                 // Optional - Required if credential provided
  "device_name": "iPhone 15"          // Optional - Device name for passkey
}
```

**How it works**:

1. **Validation Phase**:
   - Validates email format using regex pattern
   - Checks if email already exists in database
   - If user exists and is verified → returns error
   - If user exists but not verified → resends verification code

2. **Code Generation**:
   - Generates a 6-digit random verification code
   - Sets expiry time to 15 minutes from now
   - Uses `generate_verification_code()` helper function

3. **User Creation**:
   - Creates new user record in `slay_users` table with:
     - Email address
     - Full name (if provided)
     - `email_verified: false`
     - Verification code
     - Code expiry timestamp
     - Creation timestamp

4. **Passkey Registration (Optional)**:
   - If credential and challenge are provided:
     - Decodes challenge from base64
     - Verifies WebAuthn registration response using `verify_registration_response()`
     - Stores passkey credential in database
     - Links credential to user email
   - If passkey verification fails, registration continues without passkey

5. **Email Sending**:
   - Sends verification email asynchronously via `send_email_background()`
   - Uses Resend API to send HTML email with verification code
   - Email includes expiry warning and security notes

**Response (Success - 201)**:
```json
{
  "success": true,
  "message": "Registration successful. Please check your email for verification code.",
  "email": "user@example.com",
  "note": "Check your inbox (and spam folder) for the verification email from Resend",
  "passkey_registered": true,        // Only if passkey was registered
  "credential_id": "..."             // Only if passkey was registered
}
```

**Error Responses**:
- `400`: Invalid email format, email already verified, missing required fields
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Validates email format
- `generate_verification_code()`: Creates 6-digit random code
- `send_email_background()`: Async email sending
- `store_passkey_credential()`: Stores WebAuthn credentials

---

### 4. `POST /api/verify-email`

**Purpose**: Verify user's email address using the verification code sent to their email.

**Request Body**:
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**How it works**:

1. **Validation**:
   - Validates email and code are provided
   - Fetches user from database by email

2. **Checks**:
   - Verifies user exists (404 if not found)
   - Checks if email is already verified (returns success if already verified)
   - Validates code matches stored verification code
   - Checks if code has expired (15 minutes expiry)

3. **Verification Process**:
   - Updates user record:
     - Sets `email_verified: true`
     - Sets `verified_at` timestamp
     - Clears `verification_code` (sets to null)
     - Clears `verification_code_expiry` (sets to null)

4. **Response**:
   - Returns success message confirming verification

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Email verified successfully! 🎉",
  "email": "user@example.com"
}
```

**Error Responses**:
- `400`: Invalid code, code expired, missing fields
- `404`: User not found
- `500`: Internal server error

**Key Functions Used**:
- `parse_datetime_string()`: Parses expiry timestamp
- Supabase update operation

---

### 5. `POST /api/resend-code`

**Purpose**: Resend verification code to user's email if the original code expired or wasn't received.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**How it works**:

1. **Validation**:
   - Validates email is provided
   - Fetches user from database

2. **Checks**:
   - Verifies user exists
   - Checks if email is already verified (returns error if verified)
   - User must be unverified to resend code

3. **Code Regeneration**:
   - Generates new 6-digit verification code
   - Sets new expiry time (15 minutes from now)
   - Updates user record with new code and expiry

4. **Email Sending**:
   - Sends new verification email via Resend API
   - Uses same email template as registration

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Verification code resent via Resend. Please check your email.",
  "email": "user@example.com"
}
```

**Error Responses**:
- `400`: Email already verified, missing email
- `404`: User not found
- `500`: Internal server error

**Key Functions Used**:
- `resend_verification_code_internal()`: Internal helper function
- `generate_verification_code()`: Creates new code
- `send_email_background()`: Sends email

---

### 6. `POST /api/verify-invite-code`

**Purpose**: Verify an invite code to grant access to registration. Marks user as "invited" in the database.

**Request Body**:
```json
{
  "email": "user@example.com",
  "invite_code": "SLAY1111"
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Validates invite code format
   - Checks if invite code matches hardcoded value: `"SLAY1111"`

2. **User Lookup**:
   - Searches for user by email in database
   - If user doesn't exist → returns error (must register first)

3. **Invitation Marking**:
   - Updates existing user record:
     - Sets `invited: true`
     - Sets `invited_at` timestamp

4. **Response**:
   - Returns success with invitation status

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Invite code verified successfully! 🎉",
  "email": "user@example.com",
  "invited": true
}
```

**Error Responses**:
- `400`: Invalid invite code, invalid email format
- `500`: User not found (must register first)

**Note**: The invite code `SLAY1111` is currently hardcoded. For production, consider moving this to environment variables or a database table.

---

### 7. `POST /api/validate-username`

**Purpose**: Validate a username format, check availability, and optionally save it to the user's profile. Provides suggestions if username is invalid or taken.

**Request Body**:
```json
{
  "username": "desired_username",
  "email": "user@example.com"
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Strips whitespace from username

2. **Format Validation**:
   - Username rules:
     - 3 to 20 characters
     - Letters, numbers, underscores (.), and dots (.)
     - Cannot start or end with `.` or `_`
     - No spaces allowed
   - Uses regex: `^[A-Za-z0-9](?:[A-Za-z0-9._]{1,18})[A-Za-z0-9]$`

3. **Availability Check**:
   - Queries database for existing username
   - Returns `available: false` if username is taken

4. **If Valid and Available**:
   - Saves username to user record (updates existing user or creates minimal user record)
   - Returns success response

5. **If Invalid or Taken**:
   - Generates suggestions:
     - Creates base name (removes invalid characters)
     - Generates variants with random numbers
     - Checks availability of each suggestion
     - Returns first available suggestion as `recommended_username`
   - Returns suggestions list with explanation

**Response (Valid & Available - 200)**:
```json
{
  "success": true,
  "valid": true,
  "available": true,
  "username": "desired_username"
}
```

**Response (Invalid/Taken - 200)**:
```json
{
  "success": true,
  "valid": false,
  "available": false,
  "username": "bad_username",
  "message": "Username must be 3-20 characters...",
  "suggestions": ["user123", "user_456", ...],
  "recommended_username": "user789"
}
```

**Error Responses**:
- `400`: Missing username or email, invalid email format
- `500`: Database error

**Key Functions Used**:
- `validate_email()`: Email validation
- Supabase query operations
- Regex pattern matching

---

## Login Endpoints

### 8. `POST /api/login/request-otp`

**Purpose**: Request a one-time password (OTP) for passwordless login. Sends OTP to user's email.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Fetches user from database

2. **User Checks**:
   - Verifies user exists (404 if not found)
   - Verifies email is already verified (requires verified email for login)
   - If email not verified → returns error asking to verify first

3. **OTP Generation**:
   - Generates 6-digit random OTP
   - Sets expiry time to 15 minutes
   - Updates user record with OTP and expiry

4. **Email Sending**:
   - Sends login OTP email via `send_login_otp_email_background()`
   - Uses different email template than verification email

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Login OTP sent to your email. Please check your inbox.",
  "email": "user@example.com",
  "note": "OTP will expire in 15 minutes"
}
```

**Error Responses**:
- `400`: Invalid email format, email not verified
- `404`: User not found
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Email validation
- `generate_verification_code()`: Creates OTP
- `send_login_otp_email_background()`: Sends login email

---

### 9. `POST /api/login/verify-otp`

**Purpose**: Verify OTP and complete login. Returns user information upon successful authentication.

**Request Body**:
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Validates OTP is provided
   - Fetches user from database

2. **Authentication Checks**:
   - Verifies user exists
   - Verifies email is verified (must be verified to login)
   - Validates OTP matches stored code
   - Checks if OTP has expired (15 minutes)

3. **Login Process**:
   - Clears OTP from user record (sets to null)
   - Clears OTP expiry (sets to null)
   - Prepares user data (excluding sensitive information)

4. **Response**:
   - Returns user information:
     - Email
     - Full name
     - Username
     - Email verified status
     - Creation timestamp

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Login successful! 🎉",
  "user": {
    "email": "user@example.com",
    "full_name": "John Doe",
    "username": "johndoe",
    "email_verified": true,
    "created_at": "2024-01-01T00:00:00"
  }
}
```

**Error Responses**:
- `400`: Invalid OTP, OTP expired, email not verified
- `404`: User not found
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Email validation
- `parse_datetime_string()`: Checks OTP expiry
- Supabase update operation

---

## Passkey/WebAuthn Endpoints

### 10. `POST /api/passkey/register/begin`

**Purpose**: Begin the passkey registration process. Generates WebAuthn challenge and registration options for the mobile app (iOS/Android).

**Request Body**:
```json
{
  "email": "user@example.com",
  "device_name": "iPhone 15",         // Optional
  "for_registration": false            // Optional - true if registering new user
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Gets user from database (optional if `for_registration: true`)

2. **User Checks** (if not for registration):
   - Verifies user exists
   - Verifies email is verified

3. **Challenge Generation**:
   - Generates random 32-byte challenge
   - Encodes as base64 URL-safe string
   - Stores challenge temporarily in user record with 5-minute expiry

4. **Registration Options Generation**:
   - Uses `generate_registration_options()` from webauthn library
   - Configuration:
     - `rp_id`: Relying Party ID (domain or app identifier for mobile)
     - `rp_name`: "Slay Money"
     - `user_id`: Email encoded as bytes
     - `user_name`: Email
     - `user_display_name`: Full name or email
     - Challenge: Generated challenge bytes
     - Authenticator selection: Prefers user verification

5. **Response Preparation**:
   - Converts options to JSON-serializable format
   - Removes Ellipsis objects (Python/JSON compatibility)
   - If for registration and user doesn't exist, includes challenge in response for client to store

**Response (Success - 200)**:
```json
{
  "success": true,
  "options": {
    "rp": {...},
    "user": {...},
    "challenge": "...",
    "pubKeyCredParams": [...],
    "authenticatorSelection": {...},
    "timeout": 60000
  },
  "device_name": "iPhone 15",
  "challenge": "..."  // Only if for_registration and user doesn't exist
}
```

**Error Responses**:
- `400`: Invalid email format, email not verified
- `404`: User not found (if not for registration)
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Email validation
- `generate_challenge()`: Creates WebAuthn challenge
- `generate_registration_options()`: Creates WebAuthn options
- `remove_ellipsis()`: JSON serialization helper

**Next Steps**: Mobile app uses these options with the platform's WebAuthn/Passkey API (iOS ASAuthorizationController or Android Fido2ApiClient), then calls `/api/passkey/register/complete` with the credential.

---

### 11. `POST /api/passkey/register/complete`

**Purpose**: Complete passkey registration by verifying the WebAuthn credential from the mobile app (iOS/Android).

**Request Body**:
```json
{
  "email": "user@example.com",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "clientDataJSON": "...",
      "attestationObject": "..."
    },
    "type": "public-key"
  },
  "device_name": "iPhone 15"  // Optional
}
```

**How it works**:

1. **Validation**:
   - Validates email and credential are provided
   - Fetches user from database
   - Retrieves stored challenge from user record

2. **Challenge Verification**:
   - Verifies stored challenge exists
   - Checks challenge hasn't expired (5 minutes)
   - Decodes challenge from base64 to bytes

3. **Credential Verification**:
   - Cleans credential (removes Ellipsis objects)
   - Uses `verify_registration_response()` from webauthn library
   - Verifies:
     - Challenge matches stored challenge
     - Origin matches expected origin
     - RP ID matches expected domain
     - Attestation is valid

4. **Credential Storage**:
   - Encodes credential ID as base64
   - Stores credential in database:
     - Credential ID
     - Public key (base64 encoded)
     - Sign count (initial: 0)
     - Device name
     - Creation timestamp
   - Stores in `passkey_credentials` array field in user record

5. **Cleanup**:
   - Clears stored challenge from user record

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Passkey registered successfully! 🎉",
  "credential_id": "base64_encoded_id"
}
```

**Error Responses**:
- `400`: Missing fields, session expired, verification failed
- `404`: User not found
- `500`: Internal server error

**Key Functions Used**:
- `get_user_by_email()`: Fetches user
- `verify_registration_response()`: WebAuthn verification
- `store_passkey_credential()`: Stores credential
- `parse_datetime_string()`: Checks expiry
- `remove_ellipsis()`: JSON cleanup

---

### 12. `POST /api/passkey/login/begin`

**Purpose**: Begin passkey authentication for mobile app. Generates authentication challenge and returns user's registered passkeys.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**How it works**:

1. **Validation**:
   - Validates email format
   - Fetches user from database

2. **User Checks**:
   - Verifies user exists
   - Verifies email is verified

3. **Challenge Generation**:
   - Generates random 32-byte challenge
   - Encodes as base64 URL-safe string
   - Stores challenge temporarily in user record with 5-minute expiry

4. **Get User's Passkeys**:
   - Retrieves all passkey credentials for user
   - Converts credential IDs from base64 to bytes
   - Creates `PublicKeyCredentialDescriptor` objects for each credential

5. **Authentication Options Generation**:
   - Uses `generate_authentication_options()` from webauthn library
   - Configuration:
     - `rp_id`: Relying Party ID (domain or app identifier for mobile)
     - Challenge: Generated challenge bytes
     - `allow_credentials`: List of user's registered passkeys
     - User verification: Preferred

**Response (Success - 200)**:
```json
{
  "success": true,
  "options": {
    "rpId": "slay.money",
    "challenge": "...",
    "allowCredentials": [...],
    "userVerification": "preferred",
    "timeout": 60000
  }
}
```

**Note**: The `rpId` should match your app's domain or configured relying party identifier. For mobile apps, ensure this matches your backend's domain configuration.

**Error Responses**:
- `400`: Invalid email format, email not verified
- `404`: User not found, no passkeys registered
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Email validation
- `get_user_by_email()`: Fetches user
- `get_passkey_credentials()`: Gets user's passkeys
- `generate_challenge()`: Creates challenge
- `generate_authentication_options()`: Creates auth options

**Next Steps**: Mobile app uses these options with the platform's WebAuthn/Passkey API (iOS ASAuthorizationController or Android Fido2ApiClient), then calls `/api/passkey/login/complete` with the authentication credential.

---

### 13. `POST /api/passkey/login/complete`

**Purpose**: Complete passkey authentication by verifying the WebAuthn authentication credential from the mobile app (iOS/Android).

**Request Body**:
```json
{
  "email": "user@example.com",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "clientDataJSON": "...",
      "authenticatorData": "...",
      "signature": "...",
      "userHandle": "..."
    },
    "type": "public-key"
  }
}
```

**How it works**:

1. **Validation**:
   - Validates email and credential are provided
   - Validates email format
   - Fetches user from database

2. **Credential Matching**:
   - Extracts credential ID from request
   - Retrieves all user's passkey credentials
   - Finds matching credential by credential ID

3. **Challenge Verification**:
   - Retrieves stored challenge from user record
   - Verifies challenge exists and hasn't expired (5 minutes)
   - Decodes challenge from base64 to bytes

4. **Authentication Verification**:
   - Gets public key from matching credential (decodes from base64)
   - Gets expected sign count from credential
   - Uses `verify_authentication_response()` from webauthn library
   - Verifies:
     - Challenge matches stored challenge
     - Origin matches expected origin
     - RP ID matches expected domain
     - Signature is valid
     - Sign count has increased (prevents replay attacks)

5. **Update Sign Count**:
   - Updates credential's sign count with new value from verification
   - Updates last used timestamp

6. **Cleanup**:
   - Clears stored challenge from user record

7. **Response**:
   - Returns user information (same structure as OTP login)

**Response (Success - 200)**:
```json
{
  "success": true,
  "message": "Passkey login successful! 🎉",
  "user": {
    "email": "user@example.com",
    "full_name": "John Doe",
    "username": "johndoe",
    "email_verified": true,
    "created_at": "2024-01-01T00:00:00"
  }
}
```

**Error Responses**:
- `400`: Missing fields, invalid credential, verification failed, session expired
- `404`: User not found, credential not found
- `500`: Internal server error

**Key Functions Used**:
- `validate_email()`: Email validation
- `get_user_by_email()`: Fetches user
- `get_passkey_credentials()`: Gets user's passkeys
- `verify_authentication_response()`: WebAuthn verification
- `update_sign_count()`: Updates sign count
- `parse_datetime_string()`: Checks expiry
- `remove_ellipsis()`: JSON cleanup

**Security Features**:
- Sign count prevents replay attacks
- Challenge expiry prevents stale requests
- Origin and RP ID verification prevents phishing

---

## User Management Endpoints

### 14. `GET /api/user/<email>`

**Purpose**: Get user verification status and basic information (for testing/debugging).

**URL Parameters**:
- `email`: User's email address (in URL path)

**How it works**:

1. **Query**:
   - Fetches user from database by email
   - Selects specific fields (excludes sensitive data):
     - Email
     - Full name
     - Email verified status
     - Creation timestamp
     - Verification timestamp

2. **Response**:
   - Returns user data if found
   - Returns 404 if user not found

**Response (Success - 200)**:
```json
{
  "success": true,
  "user": {
    "email": "user@example.com",
    "full_name": "John Doe",
    "email_verified": true,
    "created_at": "2024-01-01T00:00:00",
    "verified_at": "2024-01-01T00:05:00"
  }
}
```

**Error Responses**:
- `404`: User not found
- `500`: Internal server error

**Note**: This endpoint is primarily for debugging. In production, consider adding authentication/authorization. For mobile apps, ensure proper API key or token-based authentication.

---

## Documentation Endpoints

### 15. `GET /`

**Purpose**: API information and endpoint list.

**How it works**:
- Returns basic API information
- Lists all available endpoints with their methods and paths
- Provides service metadata

**Response (Success - 200)**:
```json
{
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
  "documentation": "GET /docs for full API documentation or see RESEND_SETUP.md for setup instructions"
}
```

---

### 16. `GET /docs`

**Purpose**: Comprehensive API documentation in JSON format.

**How it works**:
- Returns detailed documentation for all endpoints
- Includes request/response examples
- Provides status codes and error information
- Structured JSON format for programmatic access

**Response**: Large JSON object with complete API documentation including:
- Endpoint descriptions
- Request/response schemas
- Status codes
- Error messages
- Examples

---

### 17. `GET /docs/html`

**Purpose**: Interactive HTML API documentation with search functionality.

**How it works**:
1. Calls internal `/docs` endpoint to get documentation data
2. Renders HTML template with:
   - Searchable endpoint list
   - Expandable endpoint cards
   - Formatted request/response examples
   - Color-coded HTTP methods
3. Provides interactive UI for browsing documentation

**Response**: HTML page with styled documentation interface.

---

## Helper Functions Explained

### `generate_verification_code(length=6)`
- Generates random numeric code
- Uses `random.choices()` with digits
- Default length: 6 digits

### `validate_email(email)`
- Validates email format using regex
- Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

### `send_email_background(email, code, full_name)`
- Sends verification email asynchronously using threading
- Uses Resend API
- HTML email template with code display

### `send_login_otp_email_background(email, code, full_name)`
- Similar to above but uses login OTP email template

### `generate_challenge()`
- Generates 32 random bytes
- Encodes as base64 URL-safe string
- Used for WebAuthn challenges

### `store_passkey_credential(email, credential_id, public_key, sign_count, device_name)`
- Stores passkey in user's `passkey_credentials` array
- Encodes public key as base64 for storage
- Includes metadata (device name, timestamps)

### `get_passkey_credentials(email)`
- Retrieves all passkeys for a user
- Returns array of credential objects

### `get_user_by_email(email)`
- Fetches user record from database
- Returns user dict or None

### `parse_datetime_string(dt_str)`
- Parses datetime strings from Supabase
- Handles various formats and timezones
- Normalizes to UTC

### `remove_ellipsis(obj)`
- Removes Ellipsis objects for JSON serialization
- Converts bytes to base64 strings
- Recursively processes nested structures

---

## Database Schema

The API uses the `slay_users` table with the following key fields:

- `email`: Primary identifier
- `full_name`: User's name
- `username`: Optional username
- `email_verified`: Boolean flag
- `verification_code`: Temporary code (OTP/verification)
- `verification_code_expiry`: Code expiry timestamp
- `verified_at`: Email verification timestamp
- `invited`: Boolean flag
- `invited_at`: Invitation timestamp
- `passkey_credentials`: JSON array of passkey credentials
- `created_at`: Account creation timestamp

---

## Security Considerations

1. **Code Expiry**: All codes expire after 15 minutes (5 minutes for WebAuthn challenges)
2. **Sign Count**: Passkeys use sign count to prevent replay attacks
3. **Origin Verification**: WebAuthn verifies request origin (mobile app bundle ID/package name)
4. **RP ID Verification**: WebAuthn verifies relying party identifier (domain or app identifier)
5. **Email Verification**: Requires verified email for login
6. **No Password Storage**: Passwordless authentication only

---

## Error Handling

All endpoints follow consistent error response format:
```json
{
  "success": false,
  "error": "Error message description"
}
```

HTTP Status Codes:
- `200`: Success
- `201`: Created (registration)
- `400`: Bad Request (validation errors)
- `404`: Not Found (user/resource not found)
- `500`: Internal Server Error

---

## API Flow Examples

### New User Registration Flow:
1. `POST /api/register` → Creates user, sends verification email
2. User enters code from email
3. `POST /api/verify-email` → Verifies email
4. User can now login

### Passkey Registration Flow (Mobile App):
1. `POST /api/passkey/register/begin` → Get registration options
2. Mobile app WebAuthn/Passkey API (iOS/Android) → Creates credential
3. `POST /api/passkey/register/complete` → Verifies and stores credential

### Login Flow (OTP):
1. `POST /api/login/request-otp` → Sends OTP email
2. User enters OTP from email
3. `POST /api/login/verify-otp` → Authenticates user

### Login Flow (Passkey - Mobile App):
1. `POST /api/passkey/login/begin` → Get authentication options
2. Mobile app WebAuthn/Passkey API (iOS/Android) → Authenticates with passkey
3. `POST /api/passkey/login/complete` → Verifies and logs in user

---

This documentation covers all 17 endpoints in the mobile app backend API. Each endpoint is designed to handle specific aspects of user registration, authentication, and management using modern passwordless authentication methods compatible with iOS and Android mobile applications.


