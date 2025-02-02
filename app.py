# app.py
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mailman import Mail, EmailMessage
from flask_socketio import SocketIO, emit, join_room
import random
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey123!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tital.db'

# Mailman Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rupyargaming60@gmail.com'  # ← अपना Gmail डालें
app.config['MAIL_PASSWORD'] = 'engd xffg syvt alhs'     # ← App Password डालें
app.config['MAIL_DEFAULT_SENDER'] = 'Tital <noreply@tital.com>'

db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models with explicit table names
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime)

class OTP(db.Model):
    __tablename__ = 'otps'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    otp = db.Column(db.String(6))
    expiration = db.Column(db.DateTime)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_delivered = db.Column(db.Boolean, default=False)

# Initialize database within app context
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_otp_email(email):
    OTP.query.filter_by(email=email).delete()
    otp = str(random.randint(100000, 999999))
    expiration = datetime.now() + timedelta(minutes=10)
    
    new_otp = OTP(email=email, otp=otp, expiration=expiration)
    db.session.add(new_otp)
    db.session.commit()
    
    msg = EmailMessage(
        subject='Tital Email Verification',
        body=f'Your OTP is: {otp}\nValid for 10 minutes.',
        to=[email]
    )
    msg.send()

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        existing_user = User.query.filter(
            (User.email == email) | 
            (User.username == username)
        ).first()
        
        if existing_user:
            return 'Username/Email already exists!'
            
        new_user = User(
            username=username,
            email=email,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        
        send_otp_email(email)
        session['verify_email'] = email
        return redirect(url_for('verify_otp'))
        
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('verify_email')
    if not email:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form['otp']
        otp_record = OTP.query.filter_by(email=email).order_by(OTP.id.desc()).first()
        
        if not otp_record or otp_record.otp != user_otp:
            return 'Invalid OTP!'
            
        if otp_record.expiration < datetime.now():
            return 'OTP Expired!'
            
        user = User.query.filter_by(email=email).first()
        user.is_verified = True
        db.session.commit()
        
        session.pop('verify_email', None)
        login_user(user)
        return redirect(url_for('chat'))
    
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        user = User.query.filter(
            (User.email == identifier) | 
            (User.username == identifier)
        ).first()
        
        if not user or not check_password_hash(user.password, password):
            return 'Invalid credentials!'
            
        if not user.is_verified:
            return 'Please verify your email first!'
            
        login_user(user)
        user.online = True
        user.last_seen = datetime.now()
        db.session.commit()
        
        return redirect(url_for('chat'))
    
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
    online_users = User.query.filter(User.online == True, User.id != current_user.id).all()
    return render_template('chat.html', online_users=online_users)

# Socket.IO Handlers
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        raise ConnectionRefusedError('Unauthorized!')
    join_room(str(current_user.id))
    current_user.online = True
    db.session.commit()
    print(f"User {current_user.id} connected")
@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        current_user.last_seen = datetime.now()
        db.session.commit()
        emit('user_offline', {'user_id': current_user.id}, broadcast=True)
@app.route('/api/messages/<int:receiver_id>')
@login_required
def get_messages(receiver_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M'),
        'is_mine': msg.sender_id == current_user.id
    } for msg in messages])

# 3. Updated Socket.IO Handlers
@socketio.on('send_message')
def handle_send_message(data):
    try:
        print("Received message data:", data)
        
        # Validate input
        if 'receiver_id' not in data or 'content' not in data:
            raise ValueError("Invalid message format")
            
        receiver = User.query.get(data['receiver_id'])
        if not receiver:
            raise ValueError("Receiver not found")

        # Create message
        new_message = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            content=data['content']
        )
        db.session.add(new_message)
        db.session.commit()
        print("Message saved to DB:", new_message.id)

        # Prepare response
        message_data = {
            'id': new_message.id,
            'sender_id': current_user.id,
            'sender_name': current_user.username,
            'content': new_message.content,
            'timestamp': new_message.timestamp.strftime('%H:%M'),
            'is_delivered': False
        }

        # Emit to receiver
        emit('new_message', message_data, room=str(receiver.id))
        print("Emitted to receiver:", receiver.id)

        # Confirm to sender
        emit('message_confirmation', {
            'temp_id': data.get('temp_id'),
            'message_id': new_message.id
        }, room=str(current_user.id))

    except Exception as e:
        print("Error in send_message:", str(e))
        emit('message_error', {'error': str(e)}, room=str(current_user.id))
# 4. Add Message Delivery Tracking
@socketio.on('message_delivered')
def handle_delivery_confirmation(data):
    message = Message.query.get(data['message_id'])
    if message and message.receiver_id == current_user.id:
        message.is_delivered = True
        db.session.commit()
        emit('delivery_confirmation', {'message_id': message.id}, room=str(message.sender_id))
@socketio.on('join')
def handle_join(data):
    join_room(data['user_id'])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
