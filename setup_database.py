import os
import sys
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# Add the parent directory to Python path to import the main app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, Prescription, PrescriptionStatus, UserRole
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_sample_users():
    """Create sample users for testing"""
    
    # Admin user
    admin = User(
        username='admin',
        email='admin@medscript.com',
        first_name='System',
        last_name='Administrator',
        role=UserRole.ADMIN
    )
    admin.set_password('admin123')
    
    # Sample patients
    patients = [
        {
            'username': 'patient1',
            'email': 'patient1@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'phone_number': '+254700123456',
            'patient_id': 'P001',
            'insurance_number': 'INS001',
            'emergency_contact': 'Jane Doe - +254700123457'
        },
        {
            'username': 'patient2',
            'email': 'patient2@example.com',
            'first_name': 'Mary',
            'last_name': 'Smith',
            'phone_number': '+254700123458',
            'patient_id': 'P002',
            'insurance_number': 'INS002',
            'emergency_contact': 'James Smith - +254700123459'
        },
        {
            'username': 'patient3',
            'email': 'patient3@example.com',
            'first_name': 'David',
            'last_name': 'Kimani',
            'phone_number': '+254700123460',
            'patient_id': 'P003',
            'insurance_number': 'INS003',
            'emergency_contact': 'Grace Kimani - +254700123461'
        }
    ]
    
    # Sample pharmacists
    pharmacists = [
        {
            'username': 'pharmacist1',
            'email': 'pharmacist1@pharmacy.com',
            'first_name': 'Dr. Sarah',
            'last_name': 'Wilson',
            'phone_number': '+254720123456',
            'license_number': 'PHARM001',
            'pharmacy_name': 'City Pharmacy',
            'pharmacy_address': '123 Kenyatta Avenue, Nairobi'
        },
        {
            'username': 'pharmacist2',
            'email': 'pharmacist2@pharmacy.com',
            'first_name': 'Dr. Michael',
            'last_name': 'Ochieng',
            'phone_number': '+254720123457',
            'license_number': 'PHARM002',
            'pharmacy_name': 'Westlands Pharmacy',
            'pharmacy_address': '456 Waiyaki Way, Westlands, Nairobi'
        }
    ]
    
    try:
        # Add admin
        if not User.query.filter_by(username='admin').first():
            db.session.add(admin)
            logger.info("Added admin user")
        
        # Add patients
        for patient_data in patients:
            if not User.query.filter_by(username=patient_data['username']).first():
                patient = User(**patient_data, role=UserRole.PATIENT)
                patient.set_password('password123')
                db.session.add(patient)
                logger.info(f"Added patient: {patient_data['username']}")
        
        # Add pharmacists
        for pharmacist_data in pharmacists:
            if not User.query.filter_by(username=pharmacist_data['username']).first():
                pharmacist = User(**pharmacist_data, role=UserRole.PHARMACIST)
                pharmacist.set_password('password123')
                db.session.add(pharmacist)
                logger.info(f"Added pharmacist: {pharmacist_data['username']}")
        
        db.session.commit()
        logger.info("Sample users created successfully")
        
    except Exception as e:
        logger.error(f"Error creating sample users: {e}")
        db.session.rollback()
        raise

def create_sample_prescriptions():
    """Create sample prescription data for testing"""
    
    try:
        # Get sample users
        patient1 = User.query.filter_by(username='patient1').first()
        patient2 = User.query.filter_by(username='patient2').first()
        patient3 = User.query.filter_by(username='patient3').first()
        pharmacist1 = User.query.filter_by(username='pharmacist1').first()
        pharmacist2 = User.query.filter_by(username='pharmacist2').first()
        
        if not all([patient1, patient2, patient3, pharmacist1, pharmacist2]):
            logger.error("Sample users not found. Please create users first.")
            return
        
        sample_prescriptions = [
            {
                'patient': patient1,
                'extracted_text': """
                REPUBLIC OF KENYA
                KENYATTA NATIONAL HOSPITAL
                
                Patient: John Doe
                Age: 35
                Date: 15/08/2025
                
                Rx:
                1. Amoxicillin 500mg tablets
                   Take 1 tablet three times daily for 7 days
                
                2. Paracetamol 500mg tablets
                   Take 1-2 tablets every 6 hours as needed for pain
                
                3. ORS sachets
                   Mix 1 sachet in 1 liter of clean water
                   Take as needed for dehydration
                
                Doctor: Dr. James Mwangi
                """,
                'prescriber_name': 'Dr. James Mwangi',
                'hospital_name': 'Kenyatta National Hospital',
                'ocr_confidence': 0.89,
                'status': PrescriptionStatus.APPROVED,
                'pharmacist': pharmacist1,
                'patient_notes': 'Feeling unwell with stomach issues'
            },
            {
                'patient': patient2,
                'extracted_text': """
                NAIROBI HOSPITAL
                
                Patient: Mary Smith
                Age: 28
                Date: 14/08/2025
                
                Diagnosis: Hypertension
                
                Treatment:
                1. Amlodipine 5mg tablets
                   Take 1 tablet once daily in the morning
                
                2. Hydrochlorothiazide 25mg tablets
                   Take 1 tablet once daily
                
                3. Continue for 3 months and review
                
                Dr. Susan Wanjiku
                """,
                'prescriber_name': 'Dr. Susan Wanjiku',
                'hospital_name': 'Nairobi Hospital',
                'ocr_confidence': 0.92,
                'status': PrescriptionStatus.DISPENSED,
                'pharmacist': pharmacist2,
                'patient_notes': 'Regular blood pressure medication refill'
            },
            {
                'patient': patient3,
                'extracted_text': """
                GERTRUDE'S CHILDREN'S HOSPITAL
                
                Patient: David Kimani
                Age: 8
                Date: 16/08/2025
                
                Diagnosis: Upper Respiratory Tract Infection
                
                Rx:
                1. Azithromycin suspension 200mg/5ml
                   Give 5ml once daily for 3 days
                
                2. Salbutamol inhaler
                   2 puffs twice daily as needed
                
                3. Plenty of fluids and rest
                
                Dr. Peter Kiprotich
                """,
                'prescriber_name': 'Dr. Peter Kiprotich',
                'hospital_name': "Gertrude's Children's Hospital",
                'ocr_confidence': 0.85,
                'status': PrescriptionStatus.PENDING,
                'pharmacist': None,
                'patient_notes': 'Child has been coughing for 3 days'
            },
            {
                'patient': patient1,
                'extracted_text': """
                RIFT VALLEY PROVINCIAL HOSPITAL
                
                Patient: John Doe
                Age: 35
                Date: 13/08/2025
                
                Diagnosis: Malaria
                
                Treatment:
                1. Coartem tablets (Artemether/Lumefantrine)
                   Take as per package instructions for 3 days
                
                2. Paracetamol 500mg
                   Take 1-2 tablets every 8 hours for fever
                
                3. Return if no improvement in 3 days
                
                Dr. Grace Mutindi
                """,
                'prescriber_name': 'Dr. Grace Mutindi',
                'hospital_name': 'Rift Valley Provincial Hospital',
                'ocr_confidence': 0.78,
                'status': PrescriptionStatus.REJECTED,
                'pharmacist': pharmacist1,
                'rejection_reason': 'Prescription image unclear, please provide better quality scan'
            },
            {
                'patient': patient2,
                'extracted_text': """
                MATER HOSPITAL
                
                Patient: Mary Smith
                Age: 28
                Date: 17/08/2025
                
                Diagnosis: Urinary Tract Infection
                
                Rx:
                1. Ciprofloxacin 500mg tablets
                   Take 1 tablet twice daily for 7 days
                
                2. Drink plenty of water
                3. Complete the full course even if feeling better
                
                Dr. Ahmed Hassan
                """,
                'prescriber_name': 'Dr. Ahmed Hassan',
                'hospital_name': 'Mater Hospital',
                'ocr_confidence': 0.94,
                'status': PrescriptionStatus.PENDING,
                'pharmacist': None,
                'patient_notes': 'Experiencing burning sensation'
            }
        ]
        
        for i, prescription_data in enumerate(sample_prescriptions):
            # Generate unique prescription number
            prescription_number = f"RX{datetime.now().strftime('%Y%m%d')}{str(i+1).zfill(3)}"
            
            # Create base prescription
            prescription = Prescription(
                prescription_number=prescription_number,
                patient_id=prescription_data['patient'].id,
                extracted_text=prescription_data['extracted_text'],
                prescriber_name=prescription_data['prescriber_name'],
                hospital_name=prescription_data['hospital_name'],
                ocr_confidence=prescription_data['ocr_confidence'],
                ocr_method='tesseract_sample',
                status=prescription_data['status'],
                patient_notes=prescription_data.get('patient_notes', ''),
                uploaded_at=datetime.now() - timedelta(days=i),
                structured_data='{"medications": ["Amoxicillin", "Paracetamol"], "full_text": "sample prescription"}'
            )
            
            # Set pharmacist and dates based on status
            if prescription_data['status'] in [PrescriptionStatus.APPROVED, PrescriptionStatus.DISPENSED, PrescriptionStatus.REJECTED]:
                prescription.pharmacist_id = prescription_data['pharmacist'].id
                prescription.processed_at = datetime.now() - timedelta(days=i-1)
                
                if prescription_data['status'] == PrescriptionStatus.APPROVED:
                    prescription.approved_at = datetime.now() - timedelta(days=i-1)
                elif prescription_data['status'] == PrescriptionStatus.DISPENSED:
                    prescription.approved_at = datetime.now() - timedelta(days=i-1)
                    prescription.dispensed_at = datetime.now() - timedelta(days=i-1, hours=2)
                elif prescription_data['status'] == PrescriptionStatus.REJECTED:
                    prescription.rejection_reason = prescription_data.get('rejection_reason', '')
            
            db.session.add(prescription)
            logger.info(f"Added sample prescription: {prescription_number}")
        
        db.session.commit()
        logger.info("Sample prescriptions created successfully")
        
    except Exception as e:
        logger.error(f"Error creating sample prescriptions: {e}")
        db.session.rollback()
        raise

def setup_database():
    """Main function to set up the database"""
    
    with app.app_context():
        try:
            # Create all tables
            logger.info("Creating database tables...")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Create sample users
            logger.info("Creating sample users...")
            create_sample_users()
            
            # Create sample prescriptions
            logger.info("Creating sample prescriptions...")
            create_sample_prescriptions()
            
            logger.info("Database setup completed successfully!")
            
            # Print login credentials
            print("\n" + "="*50)
            print("DATABASE SETUP COMPLETED!")
            print("="*50)
            print("\nSample Login Credentials:")
            print("-" * 30)
            print("Admin:")
            print("  Username: admin")
            print("  Password: admin123")
            print("\nPatients:")
            print("  Username: patient1, patient2, patient3")
            print("  Password: password123")
            print("\nPharmacists:")
            print("  Username: pharmacist1, pharmacist2")
            print("  Password: password123")
            print("\nDatabase file: medical_prescriptions.db")
            print("="*50)
            
        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            raise

if __name__ == '__main__':
    setup_database()