# multi-authentication-flask
A website made in Python, flask with authentication using TOTP codes and PUSH notifications, along with other security measures.  
Read documentation_web.pdf for further insight.

## Secure website sketch

- Registration, logging in, TOTP and Push notification authorization, logging out

- Users data stored in encrypted SQL database

- User inputs are validated and sanitized

- Implemented Anti-brute force method. After 3 failed login attemps, username is blocked from logging for 30 seconds.

- Registering requires passing in API-key from user's pushbullet.com account

- Program generates QR code for TOTP on registration

- Logging in requires authorizing with TOTP and secure token from push notification

## Required libraries:
- flask
- pyotp
- secrets
- sqlite3
- cryptography
- re
- io
- base64
- qrcode
- datetime
- pushbullet.py

Required app for Push notification: PushBullet  
Android: https://play.google.com/store/apps/details?id=com.pushbullet.android&referrer=utm_source%3Dpushbullet.com  
iOS: https://apps.apple.com/us/app/pushbullet/id810352052?ls=1 [app not available in PL]  

Example app for TOTP: Google Authenticator  
Android: https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=pl&gl=US  
iOS: https://apps.apple.com/pl/app/google-authenticator/id388497605?l=pl  

## Instructions:  
After running code search for the following in web browser: http://localhost:5000/login
