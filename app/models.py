from app import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'hospital', 'client'
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=True)
    client_info = db.relationship('Client', backref='user_client', uselist=False, lazy=True)

    @staticmethod
    def check_admin_credentials(username, password):
        # Predefined admin credentials (hardcoded for simplicity)
        predefined_username = 'admin'
        predefined_password = 'admin@123'  # You can hash this for better security, or use a more secure method
        if username == predefined_username and password == predefined_password:
            return True
        return False

class Hospital(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    gmap_location = db.Column(db.String(500), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    image = db.Column(db.LargeBinary, nullable=True)
    description = db.Column(db.Text, nullable=True)
    is_removed = db.Column(db.Boolean, default=False)  # New field to mark as removed
    removed_reason = db.Column(db.Text, nullable=True)  # New field for removal reason
    users = db.relationship('User', backref='hospital', lazy=True)


class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    availability = db.Column(db.String(200), nullable=False)  # Availability in a JSON string or simple format
    security_key = db.Column(db.String(200), nullable=False)  # New field for security key

    # Foreign key to hospital
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    hospital = db.relationship('Hospital', backref=db.backref('doctors', lazy=True))

    def __repr__(self):
        return f'<Doctor {self.name} ({self.specialty})>'
    
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_time = db.Column(db.String(100), nullable=False)  # Date & time when the appointment is booked
    status = db.Column(db.String(50), nullable=False, default="Pending")  # Status of the appointment ("Pending", "Confirmed", "Completed", "Cancelled")

    # Foreign keys
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    doctor = db.relationship('Doctor', backref=db.backref('appointments', lazy=True))
    client = db.relationship('User', backref=db.backref('appointments', lazy=True))

    def __repr__(self):
        return f'<Appointment {self.id} ({self.appointment_time})>'

class MedicalHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    medical_note = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign keys
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=True)  # Track the doctor editing

    # Relationships
    client = db.relationship('User', backref=db.backref('medical_histories', lazy=True))
    hospital = db.relationship('Hospital', backref=db.backref('medical_histories', lazy=True))
    doctor = db.relationship('Doctor', backref=db.backref('medical_histories', lazy=True))  # Track which doctor

    def __repr__(self):
        return f'<MedicalHistory {self.id} for client {self.client_id}>'
    
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(250), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)  # New field for phone number
    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Relationship to User
    user = db.relationship('User', backref=db.backref('client_details', lazy=True))

    def __repr__(self):
        return f'<Client {self.name}>'
    
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)  # Rating (e.g., 1 to 5)
    review_text = db.Column(db.Text, nullable=True)  # Optional text review
    reply_text = db.Column(db.Text, nullable=True)  # Reply from the hospital
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Time of review creation

    # Foreign keys
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)

    # Relationships
    client = db.relationship('User', backref=db.backref('reviews', lazy=True))
    hospital = db.relationship('Hospital', backref=db.backref('reviews', lazy=True))

    def __repr__(self):
        return f'<Review {self.rating} stars for hospital {self.hospital_id}>'
