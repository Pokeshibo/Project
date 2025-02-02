from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, send, emit
import random
import smtplib
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Import models
from models import User, OTP, Message

# Email Configuration
def send_otp_email(receiver_email, otp):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASSWORD'])
        msg = f"Subject: Your OTP Code\n\nYour OTP is {otp}"
        server.sendmail(app.config['EMAIL_USER'], receiver_email, msg)
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            return "Email already registered!"
        
        # Generate OTP
        otp_code = str(random.randint(100000, 999999))
        new_otp = OTP(email=email, otp_code=otp_code)
        db.session.add(new_otp)
        db.session.commit()
        
        # Send OTP
        send_otp_email(email, otp_code)
        return redirect(url_for('verify_otp', email=email))
    return render_template('register.html')

@app.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        user_otp = request.form['otp']
        stored_otp = OTP.query.filter_by(email=email).order_by(OTP.created_at.desc()).first()
        
        if stored_otp and stored_otp.otp_code == user_otp:
            # Create user
            new_user = User(
                username=request.form['username'],
                email=email,
                password=request.form['password'],
                is_verified=True
            )
            db.session.add(new_user)
            db.session.delete(stored_otp)
            db.session.commit()
            return redirect(url_for('login'))
        return "Invalid OTP"
    return render_template('verify_otp.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        # Find user by email or username
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    online_users = User.query.filter_by(online=True).all()
    return render_template('dashboard.html', online_users=online_users)

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# Chat Socket Events
@socketio.on('message')
def handle_message(data):
    receiver = User.query.filter_by(username=data['receiver']).first()
    if receiver:
        new_message = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            content=data['message']
        )
        db.session.add(new_message)
        db.session.commit()
        emit('receive_message', {
            'sender': current_user.username,
            'message': data['message'],
            'timestamp': datetime.now().strftime("%H:%M")
        }, room=receiver.id)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        db.session.commit()
        emit('user_status', {'username': current_user.username, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        db.session.commit()
        emit('user_status', {'username': current_user.username, 'online': False}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
