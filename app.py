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
login_manager.login_view = 'login'  # This tells Flask-Login where to go for login
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
    prescriptions = db.relationship('Prescription', backref='user_patient', lazy=True, 
                                  foreign_keys='Prescription.patient_id', overlaps="prescriptions,user_patient")
    approved_prescriptions = db.relationship('Prescription', backref='user_pharmacist', lazy=True,
                                           foreign_keys='Prescription.pharmacist_id', overlaps="approved_prescriptions,user_pharmacist")
    
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
    prescription_number = db.Column(db.String(50), unique=True, nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pharmacist_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.Enum(PrescriptionStatus), default=PrescriptionStatus.PENDING)
    extracted_text = db.Column(db.Text)
    ocr_confidence = db.Column(db.Float)
    
    # Add prescriber_name and hospital_name field
    prescriber_name = db.Column(db.String(100))
    hospital_name = db.Column(db.String(100))
    
    patient = db.relationship('User', foreign_keys=[patient_id])  # Reference to the user
    pharmacist = db.relationship('User', foreign_keys=[pharmacist_id])  # Reference to the pharmacist

    def __repr__(self):
        return f'<Prescription {self.prescription_number}>'

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    # If user is authenticated, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.is_patient():
            return redirect(url_for('patient_dashboard'))
        elif current_user.is_pharmacist():
            return redirect(url_for('pharmacist_dashboard'))
        elif current_user.is_admin():
            return redirect(url_for('patient_dashboard'))  # Admin goes to patient dashboard first
    
    # Always start with the registration page
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Don't allow registration if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role', 'patient')  # Default to 'patient'
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone_number = request.form.get('phone_number')

            if not all([username, email, password, first_name, last_name]):
                flash('All required fields must be filled', 'error')
                return render_template('register.html')

            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('register.html')

            if len(password) < 6:
                flash('Password must be at least 6 characters long', 'error')
                return render_template('register.html')

            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return render_template('register.html')

            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('register.html')

            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                role=UserRole.PATIENT if role == 'patient' else UserRole.PHARMACIST
            )

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
    # If already authenticated, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.is_patient():
            return redirect(url_for('patient_dashboard'))
        elif current_user.is_pharmacist():
            return redirect(url_for('pharmacist_dashboard'))
        elif current_user.is_admin():
            return redirect(url_for('patient_dashboard'))  # Admin goes to patient dashboard first

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember_me)
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Redirect based on user role
            if user.role == UserRole.PATIENT:
                flash(f'Welcome back, {user.get_full_name()}!', 'success')
                return redirect(url_for('patient_dashboard'))
            elif user.role == UserRole.PHARMACIST:
                flash(f'Welcome back, {user.get_full_name()}!', 'success')
                return redirect(url_for('pharmacist_dashboard'))
            elif user.role == UserRole.ADMIN:
                flash(f'Welcome back, {user.get_full_name()}!', 'success')
                # Admin goes to patient dashboard first
                return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Create database tables when the app starts
def init_db():
    """Initialize the database tables"""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")

if __name__ == '__main__':
    # Initialize database
    init_db()
    app.run(debug=True)