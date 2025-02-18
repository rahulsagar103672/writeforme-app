from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from werkzeug.exceptions import RequestEntityTooLarge
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Create upload directories
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
PDF_FOLDER = os.path.join(UPLOAD_FOLDER, 'pdfs')
HANDWRITTEN_FOLDER = os.path.join(UPLOAD_FOLDER, 'handwritten')

# Create directories if they don't exist
os.makedirs(PDF_FOLDER, exist_ok=True)
os.makedirs(HANDWRITTEN_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

ALLOWED_EXTENSIONS = {'pdf'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'requester' or 'provider'
    rating = db.Column(db.Float, default=0.0)
    requests = db.relationship('Request', backref='requester', lazy=True, foreign_keys='Request.requester_id')
    works = db.relationship('Request', backref='provider', lazy=True, foreign_keys='Request.provider_id')

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    pdf_file = db.Column(db.String(150), nullable=False)
    handwritten_file = db.Column(db.String(150), nullable=True)
    status = db.Column(db.String(20), default='pending')  # e.g., 'pending', 'in_progress', 'completed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    rating = db.Column(db.Integer, nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # Rating score (1-5)
    comment = db.Column(db.Text, nullable=True)  # Optional comment
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requester = db.relationship('User', foreign_keys=[requester_id])
    provider = db.relationship('User', foreign_keys=[provider_id])
    request = db.relationship('Request', backref='ratings')

with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])  # Assuming you have a User model
    return None

@app.route('/')
def home():
    user = get_current_user()  # Function to get the current user from session
    return render_template('home.html', user=user)

@app.route('/<path:path>')
def redirect_to_home(path):
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            password=generate_password_hash(password),
            role=role
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username  # Add username to session
            
            if user.role == 'provider':
                return redirect(url_for('provider_dashboard'))
            else:
                return redirect(url_for('requester_dashboard'))
        
        flash('Invalid username or password')
    user = get_current_user()  # Get the current user
    return render_template('login.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    return redirect(url_for('home'))  # Redirect to home after logout

@app.route('/requester/dashboard')
def requester_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.role != 'requester':
        return redirect(url_for('home'))
    
    requests = Request.query.filter_by(requester_id=user.id).all()

    # Calculate average ratings for providers
    for request in requests:
        request.provider_average_rating = (
            Rating.query.filter_by(provider_id=request.provider_id).with_entities(db.func.avg(Rating.score)).scalar() or 0
        )

    return render_template('requester_dashboard.html', user=user, requests=requests)

@app.route('/provider/dashboard')
def provider_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    provider = User.query.get(session['user_id'])
    if provider.role != 'provider':
        return redirect(url_for('home'))
    
    # Get available (pending) requests
    available_requests = Request.query.filter_by(status='pending').all()
    
    # Get provider's active works
    active_works = Request.query.filter_by(
        provider_id=provider.id,
        status='in_progress'
    ).all()
    
    # Get completed works
    completed_works = Request.query.filter_by(
        provider_id=provider.id,
        status='completed'
    ).all()

    # Get ratings for the provider
    ratings = Rating.query.filter_by(provider_id=provider.id).all()
    average_rating = (sum(r.score for r in ratings) / len(ratings)) if ratings else 0  # Default to 0 if no ratings

    return render_template('provider_dashboard.html',
                         available_requests=available_requests,
                         active_works=active_works,
                         completed_works=completed_works,
                         provider=provider,
                         average_rating=average_rating)  # Pass average_rating to the template

@app.route('/upload_request', methods=['POST'])
def upload_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'pdf' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('requester_dashboard'))
    
    file = request.files['pdf']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('requester_dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(PDF_FOLDER, filename)
        
        try:
            file.save(file_path)
            
            new_request = Request(
                requester_id=session['user_id'],
                pdf_file=filename,
                status='pending'
            )
            db.session.add(new_request)
            db.session.commit()
            
            flash('Request uploaded successfully')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}')
    
    return redirect(url_for('requester_dashboard'))

@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    request = Request.query.get_or_404(request_id)
    request.provider_id = session['user_id']
    request.status = 'in_progress'
    db.session.commit()
    
    flash('Request accepted')
    return redirect(url_for('provider_dashboard'))

@app.route('/submit_handwritten/<int:request_id>', methods=['POST'])
def submit_handwritten(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'handwritten' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('provider_dashboard'))
    
    file = request.files['handwritten']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('provider_dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(HANDWRITTEN_FOLDER, filename)
        
        try:
            file.save(file_path)
            work_request = Request.query.get_or_404(request_id)
            work_request.handwritten_file = filename
            work_request.status = 'completed'
            work_request.completed_at = datetime.utcnow()
            db.session.commit()
            flash('Handwritten document submitted successfully.')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}')
    else:
        flash('Only PDF files are allowed')
    
    return redirect(url_for('provider_dashboard'))

@app.route('/rate_work/<int:request_id>', methods=['POST'])
def rate_work(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    requester_id = session['user_id']
    request_obj = Request.query.get_or_404(request_id)

    # Ensure the requester is the one submitting the rating
    if request_obj.requester_id != requester_id:
        flash('You are not authorized to rate this work.')
        return redirect(url_for('requester_dashboard'))

    # Check if the requester has already rated this work
    existing_rating = Rating.query.filter_by(request_id=request_id, requester_id=requester_id).first()
    if existing_rating:
        flash('You have already rated this work. You cannot rate it again.')
        return redirect(url_for('requester_dashboard'))

    # Proceed to create a new rating
    score = request.form.get('score')
    comment = request.form.get('comment')

    new_rating = Rating(
        requester_id=requester_id,
        provider_id=request_obj.provider_id,
        request_id=request_id,
        score=int(score),
        comment=comment
    )
    db.session.add(new_rating)
    db.session.commit()

    flash('Thank you for your rating!')
    return redirect(url_for('requester_dashboard'))

@app.route('/chat/<int:request_id>')
def chat(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    request_obj = Request.query.get_or_404(request_id)
    messages = Message.query.filter_by(request_id=request_id).order_by(Message.timestamp).all()
    return render_template('chat.html', request=request_obj, messages=messages)

@app.route('/send_message/<int:request_id>', methods=['POST'])
def send_message(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form['message']
    request_obj = Request.query.get_or_404(request_id)
    
    sender_id = session['user_id']
    receiver_id = request_obj.provider_id if sender_id == request_obj.requester_id else request_obj.requester_id
    
    message = Message(
        sender_id=sender_id,
        receiver_id=receiver_id,
        request_id=request_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    return redirect(url_for('chat', request_id=request_id))

@app.route('/negotiate_price/<int:request_id>', methods=['POST'])
def negotiate_price(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    requester_id = session['user_id']
    request_obj = Request.query.get_or_404(request_id)

    # Ensure the requester is the one negotiating
    if request_obj.requester_id != requester_id:
        flash('You are not authorized to negotiate the price for this request.')
        return redirect(url_for('requester_dashboard'))

    negotiated_price = request.form.get('negotiated_price', type=float)

    # Set the negotiated price
    request_obj.negotiated_price = negotiated_price
    db.session.commit()

    flash('Negotiated price submitted successfully.')
    return redirect(url_for('requester_dashboard'))

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash('File is too large. Maximum size is 16MB.')
    return redirect(request.url)

@app.errorhandler(413)
def handle_request_too_large(e):
    flash('File is too large. Maximum size is 16MB.')
    return redirect(request.url)

# Add this route for serving uploaded files
@app.route('/uploads/<folder>/<filename>')
def uploaded_file(folder, filename):
    if 'user_id' not in session:
        abort(403)  # Unauthorized
        
    if folder not in ['pdfs', 'handwritten']:
        abort(404)  # Not Found
        
    try:
        return send_from_directory(
            os.path.join(app.config['UPLOAD_FOLDER'], folder), 
            filename,
            as_attachment=False
        )
    except FileNotFoundError:
        abort(404)  # File Not Found

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 