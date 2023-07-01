import re
import pyotp
import io
import base64
import qrcode
import pushbullet
from datetime import datetime, timedelta

def validate_username(username):
    # Define a regular expression pattern to validate the username
    # For example, allow alphanumeric characters and underscores
    pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(pattern, username) is not None

def validate_password(password):
    # Define a regular expression pattern to validate the password with a minimum length of 8 characters
    # Allow alphanumeric characters, spaces, and specific special characters
    pattern = r'^[a-zA-Z0-9 !\\"#$%&\'()*+,\-./:;<=>?@\[\]^_`{|}~]{8,}$'
    return re.match(pattern, password) is not None

def validate_TOTP(totp):
    pattern = r'^[0-9]{6}$'
    return re.match(pattern, totp) is not None

def sanitize_input(input_string):
    # Apply input sanitization to remove or escape potentially harmful characters
    # For example, replace "<" with "&lt;" and ">" with "&gt;"
    sanitized_string = input_string.replace('<', '&lt;').replace('>', '&gt;')
    return sanitized_string

def QR_generate(key,new_username):  
    uri = pyotp.totp.TOTP(key).provisioning_uri(name=f'{new_username}`s authentication code',   # Create user's URI
                                                issuer_name='bemsi')
    qr_img = qrcode.make(uri)   # Create QR Code
    qr_bytes = io.BytesIO()
    qr_img.save(qr_bytes, format='PNG')
    qr_bytes.seek(0)
    return base64.b64encode(qr_bytes.getvalue()).decode('utf-8')

def track_failed_attempt(username, failed_attempts):
    MAX_FAILED_ATTEMPTS = 4
    BLOCK_DURATION = 30
    if username in failed_attempts:
        # Increment the number of failed attempts
        failed_attempts[username]['attempts'] += 1
    else:
        # Create a new entry for the username
        failed_attempts[username] = {
            'attempts': 1,
            'timestamp': datetime.now(),
            'blocked' : False
        }

    # Check if the threshold for blocking is reached
    if failed_attempts[username]['attempts'] >= MAX_FAILED_ATTEMPTS:
        # Check if the block duration has expired
        if (datetime.now() - failed_attempts[username]['timestamp']) < timedelta(seconds=BLOCK_DURATION):
            # Set the flag to indicate that the username is blocked
            failed_attempts[username]['blocked'] = True
        else:
            # Reset the failed attempts if the block duration has expired
            failed_attempts[username] = {
            'attempts': 1,
            'timestamp': datetime.now(),
            'blocked' : False
        }

def push_notification(key,token):
    pb = pushbullet.Pushbullet(key) # User's API key
    push_title = 'AUTHENTICATION'
    push_message = f'CODE: {token}'
    pb.push_note(push_title, push_message)  # Send push notification to user's smartphone