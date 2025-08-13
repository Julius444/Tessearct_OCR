import os
import cv2
import pytesseract
import base64
import numpy as np
import re
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import easyocr
from PIL import Image, ImageEnhance, ImageFilter
import difflib
from collections import Counter
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import json
from datetime import datetime, timedelta
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from enum import Enum
import sqlite3
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_prescriptions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Enums for user roles and prescription status
class UserRole(Enum):
    PATIENT = 'patient'
    PHARMACIST = 'pharmacist'
    ADMIN = 'admin'

class PrescriptionStatus(Enum):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    DISPENSED = 'dispensed'

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.PATIENT)
    
    # Personal Information
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20))
    date_of_birth = db.Column(db.Date)
    
    # Patient-specific fields
    patient_id = db.Column(db.String(20), unique=True, index=True)  # Hospital ID
    insurance_number = db.Column(db.String(50))
    emergency_contact = db.Column(db.String(100))
    
    # Pharmacist-specific fields
    license_number = db.Column(db.String(50), unique=True)
    pharmacy_name = db.Column(db.String(100))
    pharmacy_address = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    prescriptions = db.relationship('Prescription', backref='patient', lazy=True, 
                                  foreign_keys='Prescription.patient_id')
    approved_prescriptions = db.relationship('Prescription', backref='pharmacist', lazy=True,
                                           foreign_keys='Prescription.pharmacist_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def is_patient(self):
        return self.role == UserRole.PATIENT
    
    def is_pharmacist(self):
        return self.role == UserRole.PHARMACIST
    
    def is_admin(self):
        return self.role == UserRole.ADMIN
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'full_name': self.get_full_name(),
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }

class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    prescription_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    
    # Foreign Keys
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    pharmacist_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    
    # Prescription Details
    status = db.Column(db.Enum(PrescriptionStatus), default=PrescriptionStatus.PENDING, index=True)
    original_image_path = db.Column(db.String(255))
    extracted_text = db.Column(db.Text)
    ocr_confidence = db.Column(db.Float)
    ocr_method = db.Column(db.String(100))
    
    # Structured Prescription Data (JSON)
    structured_data = db.Column(db.Text)  # JSON string
    
    # Doctor/Hospital Information
    prescriber_name = db.Column(db.String(100))
    hospital_name = db.Column(db.String(100))
    prescription_date = db.Column(db.Date)
    
    # Processing Information
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    processed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    dispensed_at = db.Column(db.DateTime)
    
    # Notes and Comments
    patient_notes = db.Column(db.Text)
    pharmacist_notes = db.Column(db.Text)
    rejection_reason = db.Column(db.Text)
    
    # Relationships
    medications = db.relationship('PrescriptionMedication', backref='prescription', 
                                lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('PrescriptionAuditLog', backref='prescription', 
                               lazy=True, cascade='all, delete-orphan')
    
    def generate_prescription_number(self):
        """Generate unique prescription number"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"RX{timestamp}{str(uuid.uuid4())[:8].upper()}"
    
    def get_structured_data(self):
        """Parse structured data from JSON"""
        if self.structured_data:
            try:
                return json.loads(self.structured_data)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_structured_data(self, data):
        """Set structured data as JSON"""
        self.structured_data = json.dumps(data) if data else None
    
    def can_be_approved_by(self, user):
        """Check if user can approve this prescription"""
        return (user.is_pharmacist() and 
                self.status == PrescriptionStatus.PENDING and
                self.pharmacist_id != user.id)
    
    def to_dict(self):
        return {
            'id': self.id,
            'prescription_number': self.prescription_number,
            'patient_name': self.patient.get_full_name() if self.patient else 'Unknown',
            'pharmacist_name': self.pharmacist.get_full_name() if self.pharmacist else None,
            'status': self.status.value,
            'uploaded_at': self.uploaded_at.isoformat(),
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'ocr_confidence': self.ocr_confidence,
            'structured_data': self.get_structured_data()
        }

class PrescriptionMedication(db.Model):
    __tablename__ = 'prescription_medications'
    
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.id'), nullable=False)
    
    # Medication Details
    medication_name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50))
    frequency = db.Column(db.String(50))
    duration = db.Column(db.String(50))
    instructions = db.Column(db.Text)
    quantity_prescribed = db.Column(db.Integer)
    quantity_dispensed = db.Column(db.Integer, default=0)
    
    # Status
    is_dispensed = db.Column(db.Boolean, default=False)
    dispensed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'medication_name': self.medication_name,
            'dosage': self.dosage,
            'frequency': self.frequency,
            'duration': self.duration,
            'instructions': self.instructions,
            'quantity_prescribed': self.quantity_prescribed,
            'quantity_dispensed': self.quantity_dispensed,
            'is_dispensed': self.is_dispensed
        }

class PrescriptionAuditLog(db.Model):
    __tablename__ = 'prescription_audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    action = db.Column(db.String(50), nullable=False)  # 'uploaded', 'approved', 'rejected', 'dispensed'
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role decorators
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if isinstance(roles, str):
                roles_list = [roles]
            else:
                roles_list = roles
            
            if current_user.role.value not in roles_list:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Enhanced Medical Dictionary (same as before)
MEDICAL_DICT = {
    "medications": [
        # Common antibiotics
        "Amoxicillin", "Ampicillin", "Penicillin", "Erythromycin", "Azithromycin", 
        "Ciprofloxacin", "Doxycycline", "Metronidazole", "Cotrimoxazole", "Chloramphenicol",
        "Tetracycline", "Cephalexin", "Cloxacillin", "Gentamicin", "Streptomycin",
        
        # Pain relievers and anti-inflammatory
        "Paracetamol", "Acetaminophen", "Ibuprofen", "Aspirin", "Diclofenac", 
        "Indomethacin", "Tramadol", "Codeine", "Morphine", "Pethidine",
        
        # Antimalarials
        "Chloroquine", "Sulfadoxine", "Pyrimethamine", "Artemether", "Lumefantrine",
        "Quinine", "Doxycycline", "Mefloquine", "Artesunate", "Amodiaquine",
        "Coartem", "Fansidar", "Halfan",
        
        # Common brand names in Kenya
        "Panadol", "Brufen", "Flagyl", "Septrin", "Ampiclox", "Augmentin",
        "Zithromax", "Cipro", "Voltaren", "Ponstan", "Cafergot"
    ],
    
    "dosage_forms": [
        "tablet", "tablets", "tab", "tabs", "capsule", "capsules", "cap", "caps",
        "syrup", "suspension", "injection", "inj", "drops", "cream", "ointment",
        "gel", "lotion", "inhaler", "spray", "patch", "suppository", "powder"
    ],
    
    "frequencies": [
        "once", "twice", "thrice", "daily", "bid", "tid", "qid", "qds",
        "od", "bd", "tds", "prn", "stat", "sos", "ac", "pc", "hs"
    ],
    
    "units": [
        "mg", "gm", "g", "ml", "mcg", "µg", "ug", "units", "iu", "meq",
        "mmol", "kg", "lb", "tsp", "tbsp", "drops", "puffs", "patches"
    ]
}

# Flatten for quick lookup
ALL_MEDICAL_TERMS = set()
for category in MEDICAL_DICT.values():
    ALL_MEDICAL_TERMS.update([term.lower() for term in category])

# OCR Processor Class (simplified version)
class MedicalOCRProcessor:
    def __init__(self):
        self.easyocr_reader = None
        self._initialize_easyocr()
    
    def _initialize_easyocr(self):
        try:
            self.easyocr_reader = easyocr.Reader(['en'], gpu=False, verbose=False)
            logger.info("EasyOCR initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize EasyOCR: {e}")
    
    def process_prescription_image(self, image_path):
        """Process prescription image and return extracted data"""
        try:
            # Simplified preprocessing and OCR
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Could not read image")
            
            # Basic preprocessing
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            gray = cv2.bilateralFilter(gray, 11, 80, 80)
            
            # OCR with Tesseract
            text = pytesseract.image_to_string(gray, config='--oem 3 --psm 6')
            
            # Calculate confidence based on medical terms
            confidence = self._calculate_confidence(text)
            
            # Extract structured data
            structured_data = self._extract_structured_data(text)
            
            return {
                'text': text,
                'confidence': confidence,
                'method': 'tesseract_basic',
                'structured_data': structured_data
            }
        except Exception as e:
            logger.error(f"OCR processing error: {e}")
            return None
    
    def _calculate_confidence(self, text):
        if not text:
            return 0.0
        words = text.split()
        if not words:
            return 0.0
        medical_terms = sum(1 for word in words if word.lower() in ALL_MEDICAL_TERMS)
        return min(medical_terms / len(words), 1.0)
    
    def _extract_structured_data(self, text):
        """Extract structured prescription data"""
        medications = []
        for med in MEDICAL_DICT['medications']:
            if med.lower() in text.lower():
                medications.append(med)
        
        return {
            'medications': medications,
            'full_text': text
        }

# Initialize processor
processor = MedicalOCRProcessor()

# Upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database initialization
def create_tables():
    """Create all database tables"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@hospital.com',
                first_name='System',
                last_name='Administrator',
                role=UserRole.ADMIN
            )
            admin.set_password('admin123')  # Change this in production
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created")

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role', 'patient')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone_number = request.form.get('phone_number')
            
            # Validation
            if not all([username, email, password, first_name, last_name]):
                flash('All required fields must be filled', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('register.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long', 'error')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            # Create new user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                role=UserRole.PATIENT if role == 'patient' else UserRole.PHARMACIST
            )
            
            # Role-specific fields
            if role == 'patient':
                user.patient_id = request.form.get('patient_id')
                user.insurance_number = request.form.get('insurance_number')
            elif role == 'pharmacist':
                user.license_number = request.form.get('license_number')
                user.pharmacy_name = request.form.get('pharmacy_name')
                user.pharmacy_address = request.form.get('pharmacy_address')
            
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') == 'off'
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember_me)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.get_full_name()}!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_patient():
        # Patient dashboard
        prescriptions = Prescription.query.filter_by(patient_id=current_user.id)\
                                        .order_by(Prescription.uploaded_at.desc())\
                                        .limit(10).all()
        
        stats = {
            'total_prescriptions': Prescription.query.filter_by(patient_id=current_user.id).count(),
            'pending': Prescription.query.filter_by(patient_id=current_user.id, 
                                                   status=PrescriptionStatus.PENDING).count(),
            'approved': Prescription.query.filter_by(patient_id=current_user.id,
                                                    status=PrescriptionStatus.APPROVED).count(),
            'dispensed': Prescription.query.filter_by(patient_id=current_user.id,
                                                     status=PrescriptionStatus.DISPENSED).count()
        }
        
        return render_template('patient_dashboard.html', 
                             prescriptions=prescriptions, stats=stats)
    
    elif current_user.is_pharmacist():
        # Pharmacist dashboard
        pending_prescriptions = Prescription.query.filter_by(status=PrescriptionStatus.PENDING)\
                                                 .order_by(Prescription.uploaded_at.desc())\
                                                 .limit(20).all()
        
        my_approvals = Prescription.query.filter_by(pharmacist_id=current_user.id)\
                                        .order_by(Prescription.approved_at.desc())\
                                        .limit(10).all()
        
        stats = {
            'pending_prescriptions': Prescription.query.filter_by(status=PrescriptionStatus.PENDING).count(),
            'my_approvals': Prescription.query.filter_by(pharmacist_id=current_user.id).count(),
            'approved_today': Prescription.query.filter_by(pharmacist_id=current_user.id)\
                                               .filter(Prescription.approved_at >= datetime.today()).count()
        }
        
        return render_template('pharmacist_dashboard.html',
                             pending_prescriptions=pending_prescriptions,
                             my_approvals=my_approvals,
                             stats=stats)
    else:
        # Admin dashboard
        recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
        recent_prescriptions = Prescription.query.order_by(Prescription.uploaded_at.desc()).limit(10).all()
        
        stats = {
            'total_users': User.query.count(),
            'total_patients': User.query.filter_by(role=UserRole.PATIENT).count(),
            'total_pharmacists': User.query.filter_by(role=UserRole.PHARMACIST).count(),
            'total_prescriptions': Prescription.query.count(),
            'pending_prescriptions': Prescription.query.filter_by(status=PrescriptionStatus.PENDING).count()
        }
        
        return render_template('admin_dashboard.html',
                             recent_users=recent_users,
                             recent_prescriptions=recent_prescriptions,
                             stats=stats)

@app.route('/api/prescriptions')
@login_required
def api_prescriptions():
    """API endpoint to get prescriptions as JSON"""
    if current_user.is_patient():
        prescriptions = Prescription.query.filter_by(patient_id=current_user.id)\
                                        .order_by(Prescription.uploaded_at.desc()).all()
    elif current_user.is_pharmacist():
        prescriptions = Prescription.query.filter_by(status=PrescriptionStatus.PENDING)\
                                        .order_by(Prescription.uploaded_at.desc()).all()
    else:
        prescriptions = Prescription.query.order_by(Prescription.uploaded_at.desc()).all()
    
    return jsonify([p.to_dict() for p in prescriptions])

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            current_user.first_name = request.form.get('first_name', current_user.first_name)
            current_user.last_name = request.form.get('last_name', current_user.last_name)
            current_user.phone_number = request.form.get('phone_number', current_user.phone_number)
            current_user.email = request.form.get('email', current_user.email)
            
            # Role-specific fields
            if current_user.is_patient():
                current_user.patient_id = request.form.get('patient_id', current_user.patient_id)
                current_user.insurance_number = request.form.get('insurance_number', current_user.insurance_number)
                current_user.emergency_contact = request.form.get('emergency_contact', current_user.emergency_contact)
            elif current_user.is_pharmacist():
                current_user.license_number = request.form.get('license_number', current_user.license_number)
                current_user.pharmacy_name = request.form.get('pharmacy_name', current_user.pharmacy_name)
                current_user.pharmacy_address = request.form.get('pharmacy_address', current_user.pharmacy_address)
            
            # Password update
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            if current_password and new_password:
                if current_user.check_password(current_password):
                    if len(new_password) >= 6:
                        current_user.set_password(new_password)
                        flash('Password updated successfully', 'success')
                    else:
                        flash('New password must be at least 6 characters', 'error')
                else:
                    flash('Current password is incorrect', 'error')
            
            db.session.commit()
            flash('Profile updated successfully', 'success')
            
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            db.session.rollback()
            flash('Error updating profile', 'error')
    
    return render_template('profile.html')

@app.route('/dispense_prescription/<int:id>', methods=['POST'])
@login_required
@role_required('pharmacist')
def dispense_prescription(id):
    prescription = Prescription.query.get_or_404(id)
    
    if prescription.status != PrescriptionStatus.APPROVED or prescription.pharmacist_id != current_user.id:
        flash('You can only dispense prescriptions you have approved', 'error')
        return redirect(url_for('view_prescription', id=id))
    
    try:
        prescription.status = PrescriptionStatus.DISPENSED
        prescription.dispensed_at = datetime.utcnow()
        
        # Create audit log
        audit_log = PrescriptionAuditLog(
            prescription_id=prescription.id,
            user_id=current_user.id,
            action='dispensed',
            details='Prescription dispensed to patient'
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Prescription marked as dispensed', 'success')
        
    except Exception as e:
        logger.error(f"Dispensing error: {e}")
        db.session.rollback()
        flash('Error marking prescription as dispensed', 'error')
    
    return redirect(url_for('view_prescription', id=id))

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    page = request.args.get('page', 1, type=int)
    role_filter = request.args.get('role', '')
    
    query = User.query
    if role_filter:
        try:
            role_enum = UserRole(role_filter)
            query = query.filter_by(role=role_enum)
        except ValueError:
            pass
    
    users = query.order_by(User.created_at.desc())\
               .paginate(page=page, per_page=20, error_out=False)
    
    return render_template('admin_users.html', users=users, role_filter=role_filter)

@app.route('/admin/toggle_user/<int:id>')
@login_required
@role_required('admin')
def admin_toggle_user(id):
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        flash('You cannot deactivate your own account', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        flash(f'User {user.username} has been {status}', 'success')
        
    except Exception as e:
        logger.error(f"User toggle error: {e}")
        db.session.rollback()
        flash('Error updating user status', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/reports')
@login_required
@role_required(['pharmacist', 'admin'])
def reports():
    # Get date range from query params
    start_date = request.args.get('start_date', 
                                (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))
    
    try:
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        start_dt = datetime.now() - timedelta(days=30)
        end_dt = datetime.now()
    
    # Get prescription statistics
    base_query = Prescription.query.filter(
        Prescription.uploaded_at >= start_dt,
        Prescription.uploaded_at < end_dt
    )
    
    if current_user.is_pharmacist():
        base_query = base_query.filter_by(pharmacist_id=current_user.id)
    
    stats = {
        'total_prescriptions': base_query.count(),
        'pending': base_query.filter_by(status=PrescriptionStatus.PENDING).count(),
        'approved': base_query.filter_by(status=PrescriptionStatus.APPROVED).count(),
        'rejected': base_query.filter_by(status=PrescriptionStatus.REJECTED).count(),
        'dispensed': base_query.filter_by(status=PrescriptionStatus.DISPENSED).count(),
    }
    
    # Get daily prescription counts for chart
    daily_counts = []
    current_date = start_dt.date()
    while current_date <= end_dt.date():
        day_start = datetime.combine(current_date, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        
        count = base_query.filter(
            Prescription.uploaded_at >= day_start,
            Prescription.uploaded_at < day_end
        ).count()
        
        daily_counts.append({
            'date': current_date.strftime('%Y-%m-%d'),
            'count': count
        })
        
        current_date += timedelta(days=1)
    
    return render_template('reports.html', 
                         stats=stats,
                         daily_counts=daily_counts,
                         start_date=start_date,
                         end_date=end_date)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error_code=404,
                         error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html',
                         error_code=403,
                         error_message='Access forbidden'), 403

# Initialize database and run app
if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host='0.0.0.0', port=5000)

@app.route('/upload_prescription', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def upload_prescription():
    if request.method == 'POST':
        if 'prescription_image' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['prescription_image']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Please select a valid image file', 'error')
            return redirect(request.url)
        
        try:
            # Save uploaded file
            filename = str(uuid.uuid4()) + "_" + secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            # Process with OCR
            ocr_result = processor.process_prescription_image(filepath)
            
            if not ocr_result:
                flash('Could not process the image. Please try again.', 'error')
                os.remove(filepath)
                return redirect(request.url)
            
            # Create prescription record
            prescription = Prescription(
                prescription_number=Prescription().generate_prescription_number(),
                patient_id=current_user.id,
                original_image_path=filepath,
                extracted_text=ocr_result['text'],
                ocr_confidence=ocr_result['confidence'],
                ocr_method=ocr_result['method'],
                patient_notes=request.form.get('notes', ''),
                prescriber_name=request.form.get('prescriber_name', ''),
                hospital_name=request.form.get('hospital_name', '')
            )
            
            prescription.set_structured_data(ocr_result['structured_data'])
            
            db.session.add(prescription)
            db.session.commit()
            
            # Create audit log
            audit_log = PrescriptionAuditLog(
                prescription_id=prescription.id,
                user_id=current_user.id,
                action='uploaded',
                details='Prescription uploaded and processed with OCR'
            )
            db.session.add(audit_log)
            db.session.commit()
            
            flash('Prescription uploaded successfully!', 'success')
            return redirect(url_for('view_prescription', id=prescription.id))
            
        except Exception as e:
            logger.error(f"Upload error: {e}")
            db.session.rollback()
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            flash('Failed to upload prescription. Please try again.', 'error')
    
    return render_template('upload_prescription.html')

@app.route('/prescription/<int:id>')
@login_required
def view_prescription(id):
    prescription = Prescription.query.get_or_404(id)
    
    # Check permissions
    if current_user.is_patient() and prescription.patient_id != current_user.id:
        flash('You can only view your own prescriptions', 'error')
        return redirect(url_for('dashboard'))
    
    # Get image data for display
    image_data = None
    if prescription.original_image_path and os.path.exists(prescription.original_image_path):
        try:
            with open(prescription.original_image_path, 'rb') as f:
                image_data = base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            logger.error(f"Error reading image: {e}")
    
    return render_template('view_prescription.html', 
                         prescription=prescription,
                         image_data=image_data)

@app.route('/approve_prescription/<int:id>', methods=['POST'])
@login_required
@role_required('pharmacist')
def approve_prescription(id):
    prescription = Prescription.query.get_or_404(id)
    
    if not prescription.can_be_approved_by(current_user):
        flash('You cannot approve this prescription', 'error')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    notes = request.form.get('notes', '')
    
    try:
        if action == 'approve':
            prescription.status = PrescriptionStatus.APPROVED
            prescription.pharmacist_id = current_user.id
            prescription.approved_at = datetime.utcnow()
            prescription.pharmacist_notes = notes
            
            # Create audit log
            audit_log = PrescriptionAuditLog(
                prescription_id=prescription.id,
                user_id=current_user.id,
                action='approved',
                details=f'Prescription approved. Notes: {notes}'
            )
            
            flash('Prescription approved successfully', 'success')
            
        elif action == 'reject':
            prescription.status = PrescriptionStatus.REJECTED
            prescription.pharmacist_id = current_user.id
            prescription.processed_at = datetime.utcnow()
            prescription.rejection_reason = notes
            
            # Create audit log
            audit_log = PrescriptionAuditLog(
                prescription_id=prescription.id,
                user_id=current_user.id,
                action='rejected',
                details=f'Prescription rejected. Reason: {notes}'
            )
            
            flash('Prescription rejected', 'warning')
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Approval error: {e}")
        db.session.rollback()
        flash('Error processing approval', 'error')
    
    return redirect(url_for('view_prescription', id=id))

@app.route('/prescriptions')
@login_required
def list_prescriptions():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    if current_user.is_patient():
        query = Prescription.query.filter_by(patient_id=current_user.id)
    elif current_user.is_pharmacist():
        query = Prescription.query.filter_by(pharmacist_id=current_user.id)