from flask import Flask, render_template, request, redirect, session
import pyotp
import sql
from funcs import *
import secrets

app = Flask(__name__)

app.secret_key = secrets.token_urlsafe(10) # Secret key for session management
cryptkey = b'\xfb\xa9\xefi\x88I\xb0t\x87\xa8\x82\x076\x94\xa2\xcd\xda\x85\xf3m\xef\x07I\xbc\x87R\xea\x88Yk5\x95'
vector = b'\xea\x99\xc2Z\xb7\x7f\x01\xb7\xa4\xae8\x03\x03\xa5\xa5\xf7'
sql.connect_to_database()

log_attemps =  {}

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        username = sanitize_input(username)
        password = sanitize_input(password)

        track_failed_attempt(username,log_attemps)

        if(log_attemps[username]["blocked"]):
            return render_template('/login.html', error = 'Too many tries, wait 30 seconds.') 

        user_data = sql.retrieve_user(username,cryptkey,vector)

        if (user_data != None):        
            if (username==user_data[0] and password == user_data[1]):
                # Successful login
                secure_token = secrets.token_urlsafe(2)
                session['username'] = username
                session['secure_token'] = secure_token
                push_notification(user_data[3],secure_token)
                return redirect('/authentication')
            
        else:
            # Invalid credentials
            error = 'Invalid username or password'
            track_failed_attempt(username,log_attemps)
            return render_template('login.html', error=error)
          
    return render_template('login.html')

# Home
@app.route('/home')
def home():
    if 'logged_in' in session:
        username = session['logged_in']
        return render_template('home.html', username=username)
    
    else:
        return redirect('/login')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()
    if request.method == 'POST':
        new_username = request.form['register_username']
        new_password = request.form['register_password']
        repeat_password = request.form['repeat_password']
        apikey = request.form['apikey']

        if new_password != repeat_password:
            error = 'Passwords do not match!'
            return render_template('register.html', error=error)

        if not(validate_username(new_username) and validate_password(new_password)):
            error_string = "Username must contain only alphanumeric chars and underscores, password must at least 8 characters long"
            return render_template('/register.html', error = error_string)
        
        new_username = sanitize_input(new_username)
        new_password = sanitize_input(new_password)
        repeat_password = sanitize_input(repeat_password)
        apikey = sanitize_input(apikey)

        key = sql.generate_totp_secret()
        qr_base64 = QR_generate(key,new_username)
        sql.store_user(new_username, new_password, key, apikey, cryptkey, vector)
        session['qr_base64'] = qr_base64
        return redirect('/register_success')

    return render_template('register.html')

# Register_success
@app.route('/register_success', methods=['GET', 'POST'])
def register_success():
    if 'qr_base64' in session:
        qr_base64 = session['qr_base64']
        session.clear()
        return render_template('register_success.html', qr_base64=qr_base64)
    
    else:
        return redirect('/login')

# Authentication
@app.route('/authentication', methods=['GET', 'POST'])
def authentication():
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        pushcode = request.form['pushcode']
        authentication = request.form['auth']

        username = session['username']
        secure_token = session['secure_token']
        session.clear()

        authentication = sanitize_input(authentication)
        user_data = sql.retrieve_user(username,cryptkey,vector)
        totp = pyotp.TOTP(user_data[2])

        if (totp.verify(authentication) and pushcode == secure_token):
            session['logged_in'] = username
            return redirect('/home')
        
        else:
            session.clear()
            return redirect('/login')
    
    return render_template('authentication.html')

if __name__ == '__main__':
    app.run(debug=True)
