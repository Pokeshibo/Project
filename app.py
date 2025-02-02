# app.py
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room
import random
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tital.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rupyargamimg60@gmail.com'
app.config['MAIL_PASSWORD'] = 'engd xffg syvt alhs'

db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    otp = db.Column(db.String(6))
    expiration = db.Column(db.DateTime)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Functions
def send_otp_email(email):
    otp = str(random.randint(100000, 999999))
    expiration = datetime.now() + timedelta(minutes=10)
    
    # Store OTP in database
    new_otp = OTP(email=email, otp=otp, expiration=expiration)
    db.session.add(new_otp)
    db.session.commit()
    
    # Send email
    msg = Message('Tital - Verify Your Email', sender='noreply@tital.com', recipients=[email])
    msg.body = f'Your OTP for Tital verification is: {otp}'
    mail.send(msg)

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/resend-otp')
def resend_otp():
    email = session.get('email')
    if email:
        send_otp_email(email)
        return 'OTP resent!'
    return 'Session expired'
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        if User.query.filter_by(email=email).first():
            return 'Email already registered!'
        if User.query.filter_by(username=username).first():
            return 'Username already taken!'
        
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        send_otp_email(email)
        session['email'] = email
        return redirect(url_for('verify_otp'))
    
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('email')
    if not email:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form['otp']
        stored_otp = OTP.query.filter_by(email=email).order_by(OTP.id.desc()).first()
        
        if stored_otp and stored_otp.otp == user_otp and stored_otp.expiration > datetime.now():
            user = User.query.filter_by(email=email).first()
            user.is_verified = True
            db.session.commit()
            return redirect(url_for('login'))
        
        return 'Invalid or expired OTP!'
    
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
        
        if user and check_password_hash(user.password, password):
            if user.is_verified:
                login_user(user)
                user.online = True
                user.last_seen = datetime.now()
                db.session.commit()
                return redirect(url_for('chat'))
            return 'Please verify your email first!'
        return 'Invalid credentials!'
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    current_user.last_seen = datetime.now()
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    online_users = User.query.filter_by(online=True).all()
    return render_template('chat.html', online_users=online_users)

# WebSocket Handlers
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        db.session.commit()
        emit('user_status', {'user_id': current_user.id, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        current_user.last_seen = datetime.now()
        db.session.commit()
        emit('user_status', {'user_id': current_user.id, 'online': False}, broadcast=True)

@socketio.on('message')
def handle_message(data):
    message = Message(
        sender_id=current_user.id,
        receiver_id=data['receiver_id'],
        content=data['content'],
        timestamp=datetime.now()
    )
    db.session.add(message)
    db.session.commit()
    
    emit('new_message', {
        'sender_id': current_user.id,
        'content': data['content'],
        'timestamp': datetime.now().strftime('%H:%M')
    }, room=data['receiver_id'])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
