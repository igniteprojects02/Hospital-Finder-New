import os
from flask import Flask, flash, redirect, url_for, render_template
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from app import db
from datetime import datetime
import random
from flask import redirect, url_for, render_template
from app.models import User, Hospital, Doctor,Appointment,MedicalHistory,Review, Client
from flask_login import login_required
from flask_login import login_user
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user
from flask_login import login_user, logout_user
from flask import Response
from twilio.rest import Client as TwilioClient

# Path to store the uploaded images
# UPLOAD_FOLDER = 'static/uploads/hospitals'

# # Ensure the directory exists
# if not os.path.exists(UPLOAD_FOLDER):
#     os.makedirs(UPLOAD_FOLDER)

# Allowed image extensions
from flask import render_template

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Blueprint setup
bp = Blueprint('hospital_routes', __name__)

# Hardcoded Twilio credentials (replace with your actual credentials)

# Initialize Twilio client with hardcoded credentials
twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
def generate_otp():
    """Generate a random 6-digit OTP."""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

@bp.route('/signup', methods=['GET', 'POST'])
def hospital_signup():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        description = data.get('description')
        phone_number = data.get('phone_number')  # New field

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already exists."}), 400

        # Check if the phone number already exists in Hospital
        if Hospital.query.filter_by(phone_number=phone_number).first():
            return jsonify({"message": "Phone number already registered."}), 400

        # Handle image upload
        if 'image' not in request.files:
            return jsonify({"message": "No image file part."}), 400
        image = request.files['image']
        if image and allowed_file(image.filename):
            image_data = image.read()
        else:
            return jsonify({"message": "Invalid image format. Only png, jpg, jpeg, gif allowed."}), 400

        # Create a new hospital instance with phone_number
        new_hospital = Hospital(
            name=data['name'],
            address=data['address'],
            gmap_location=data['gmap_location'],
            pin_code=data['pin_code'],
            phone_number=phone_number,  # Store phone number
            description=description,
            image=image_data,
            is_approved=False
        )
        
        # Add the hospital to the database
        db.session.add(new_hospital)
        db.session.commit()

        # Create the corresponding user with email and password (no username)
        hashed_password = generate_password_hash(password)
        user = User(
            username=f"hospital_{new_hospital.id}",  # Generate a dummy username if still needed
            email=email,
            password=hashed_password,
            role='hospital',
            hospital_id=new_hospital.id
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"message": f"Signup request for hospital '{new_hospital.name}' has been submitted."}), 201

    # Render the signup form for GET request
    return render_template('hospital/signup.html')


@bp.route('/hospital-image/<int:hospital_id>')
def get_hospital_image(hospital_id):
    hospital = Hospital.query.get(hospital_id)
    if hospital and hospital.image:
        return Response(hospital.image, mimetype='image/jpeg')  # Adjust MIME type depending on image format
    else:
        return jsonify({"message": "Image not found"}), 404
    
@bp.route('/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Fetch the hospital using the current user's `hospital_id`
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()

    if not hospital:
        return jsonify({"message": "Hospital not found."}), 404

    # Pass the hospital object to the template
    return render_template('hospital/dashboard.html', hospital=hospital)



from flask_login import login_user
from werkzeug.security import check_password_hash

# Hospital Login
@bp.route('/login', methods=['GET', 'POST'])
def hospital_login():
    if request.method == 'POST':
        data = request.get_json()

        # Validate incoming data (phone_number instead of username)
        phone_number = data.get('phone_number')
        password = data.get('password')
        if not phone_number or not password:
            return jsonify({"message": "Missing phone number or password"}), 400

        # Find the hospital by phone_number
        hospital = Hospital.query.filter_by(phone_number=phone_number).first()
        if not hospital:
            return jsonify({"message": "Invalid phone number"}), 401

        # Find the corresponding user by hospital_id
        user = User.query.filter_by(hospital_id=hospital.id, role='hospital').first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({"message": "Invalid credentials"}), 401

        # Check if the hospital is approved
        if not hospital.is_approved:
            return jsonify({"message": "Hospital is not approved. Please contact the administrator."}), 403

        # Log the user in
        login_user(user)

        return jsonify({
            "message": "Login successful",
            "user": {
                "email": user.email,
                "role": user.role,
                "hospital_name": hospital.name
            }
        }), 200

    # Render the login page for GET requests
    return render_template('hospital/login.html')
#Forgot Password Route with Custom OTP
@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        phone_number = data.get('phone_number')
        if not phone_number:
            return jsonify({"message": "Phone number is required."}), 400

        hospital = Hospital.query.filter_by(phone_number=phone_number).first()
        if not hospital:
            return jsonify({"message": "No hospital found with this phone number."}), 404

        user = User.query.filter_by(hospital_id=hospital.id, role='hospital').first()
        if not user:
            return jsonify({"message": "User account not found."}), 404

        # Generate and store OTP
        otp = generate_otp()
        session['reset_phone_number'] = phone_number
        session['otp'] = otp  # Store OTP in session (for simplicity; use DB in production)

        # Send OTP via Twilio SMS
        try:
            message = twilio_client.messages.create(
                body=f"Your OTP for password reset is: {otp}",
                from_=TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            print(f"OTP sent: {otp}, Message SID: {message.sid}")
            return jsonify({"message": "OTP sent to your phone number.", "redirect_url": "/hospital/reset-password"}), 200
        except Exception as e:
            print(f"Twilio Error: {str(e)}")
            return jsonify({"message": f"Error sending OTP: {str(e)}"}), 500

    return render_template('hospital/forgot-password.html')

# Reset Password Route with Custom OTP Verification
@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        data = request.get_json()
        phone_number = session.get('reset_phone_number')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if not phone_number or not otp or not new_password:
            return jsonify({"message": "Phone number, OTP, and new password are required."}), 400

        hospital = Hospital.query.filter_by(phone_number=phone_number).first()
        if not hospital:
            return jsonify({"message": "Invalid session or phone number."}), 404

        user = User.query.filter_by(hospital_id=hospital.id, role='hospital').first()
        if not user:
            return jsonify({"message": "User account not found."}), 404

        # Verify OTP
        stored_otp = session.get('otp')
        if otp != stored_otp:
            return jsonify({"message": "Invalid or expired OTP."}), 401

        # Reset the password
        user.password = generate_password_hash(new_password)
        db.session.commit()
        session.pop('reset_phone_number', None)
        session.pop('otp', None)  # Clear OTP from session
        return jsonify({"message": "Password reset successfully. Please log in.", "redirect_url": "/hospital/login"}), 200

    return render_template('hospital/reset-password.html')
import base64

@bp.route('/profile', methods=['GET'])
@login_required
def hospital_profile():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()

    if not hospital:
        return jsonify({"message": "Hospital profile not found."}), 404

    

    return jsonify({
        "id": hospital.id,
        "name": hospital.name,
        "address": hospital.address,
        "gmap_location": hospital.gmap_location,
        "pin_code": hospital.pin_code,
        "is_approved": hospital.is_approved,
        # "image": image_data,  # Base64-encoded image data
        "description": hospital.description
    }), 200

@bp.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_hospital_profile():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Fetch hospital details using the `hospital_id` from the current user
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()
    if not hospital:
        return jsonify({"message": "Hospital profile not found."}), 404

    if request.method == 'POST':
        # Handle profile update
        data = request.form
        hospital.name = data.get('name', hospital.name)
        hospital.address = data.get('address', hospital.address)
        hospital.gmap_location = data.get('gmap_location', hospital.gmap_location)
        hospital.pin_code = data.get('pin_code', hospital.pin_code)
        hospital.description = data.get('description', hospital.description)

        # Handle image upload (if present in the request)
        if 'image' in request.files:
            image = request.files['image']
            if image:
                hospital.image = image.read()

        # Save changes to the database
        db.session.commit()

        # Flash a success message and redirect
        flash("Profile updated successfully!", "success")
        return redirect('/hospital/dashboard')

    # Handle GET request: return the current profile data
    return render_template('hospital/edit-profile.html', hospital=hospital)


# POST /hospital/doctor/add - Add a new doctor

@bp.route('/doctors', methods=['GET'])
@login_required
def manage_doctor():
    return render_template('hospital/doctors.html')

@bp.route('/doctor/add', methods=['POST'])
@login_required
def add_doctor():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Ensure the hospital is approved, using current_user.hospital_id instead of current_user.id
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()
    if not hospital or not hospital.is_approved:
        return jsonify({"message": "Hospital is not approved."}), 403

    data = request.json
    name = data.get('name')
    specialty = data.get('specialty')
    availability = data.get('availability')
    security_key = data.get('security_key')  # Get the security key from the request

    if not name or not specialty or not availability or not security_key:
        return jsonify({"message": "Missing required fields."}), 400

    # Create a new doctor
    new_doctor = Doctor(
        name=name,
        specialty=specialty,
        availability=availability,
        hospital_id=hospital.id,
        security_key=generate_password_hash(security_key)  # Hash the security key for storage
    )
    # Add the doctor to the session and commit
    db.session.add(new_doctor)
    db.session.commit()

    return jsonify({"message": f"Doctor {new_doctor.name} added successfully!"}), 201
# GET /hospital/doctor/list - List all doctors for the hospital
@bp.route('/doctor/list', methods=['GET'])
@login_required
def list_doctors():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Ensure the hospital is approved, using current_user.hospital_id instead of current_user.id
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()
    if not hospital or not hospital.is_approved:
        return jsonify({"message": "Hospital is not approved."}), 403

    # Get all doctors for this hospital
    doctors = Doctor.query.filter_by(hospital_id=hospital.id).all()

    if not doctors:
        return jsonify({"message": "No doctors found."}), 404

    # Prepare doctor details to return in response
    doctors_data = [
        {
            "id": doctor.id,
            "name": doctor.name,
            "specialty": doctor.specialty,
            "availability": doctor.availability
        }
        for doctor in doctors
    ]

    return jsonify({"doctors": doctors_data}), 200
# PATCH /hospital/doctor/update/<int:doctor_id> - Update doctor details
@bp.route('/doctor/update/<int:doctor_id>', methods=['GET', 'PATCH'])
@login_required
def update_doctor(doctor_id):
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Ensure the hospital is approved
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()
    if not hospital or not hospital.is_approved:
        return jsonify({"message": "Hospital is not approved."}), 403

    # Fetch the doctor by ID
    doctor = Doctor.query.filter_by(id=doctor_id, hospital_id=hospital.id).first()
    if not doctor:
        return jsonify({"message": "Doctor not found."}), 404

    if request.method == 'GET':
        # Render the edit page with current doctor data
        return render_template('hospital/edit-doctor.html', doctor=doctor)

    if request.method == 'PATCH':
        # Update doctor details with provided data or keep existing values
        data = request.json
        doctor.name = data.get('name', doctor.name)
        doctor.specialty = data.get('specialty', doctor.specialty)
        doctor.availability = data.get('availability', doctor.availability)

        # Save changes to the database
        db.session.commit()

        return jsonify({"message": f"Doctor {doctor.name} updated successfully!"}), 200
# DELETE /hospital/doctor/delete/<int:doctor_id> - Delete a doctor
@bp.route('/doctor/delete/<int:doctor_id>', methods=['DELETE'])
@login_required
def delete_doctor(doctor_id):
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Ensure the hospital is approved
    hospital = Hospital.query.filter_by(id=current_user.hospital_id).first()
    if not hospital or not hospital.is_approved:
        return jsonify({"message": "Hospital is not approved."}), 403

    # Fetch the doctor by ID
    doctor = Doctor.query.filter_by(id=doctor_id, hospital_id=hospital.id).first()
    if not doctor:
        return jsonify({"message": "Doctor not found."}), 404

    # Delete the doctor from the database
    db.session.delete(doctor)
    db.session.commit()

    return jsonify({"message": f"Doctor {doctor.name} deleted successfully!"}), 200





# GET /hospital/appointments - View all appointments for a hospital
@bp.route('/appointments', methods=['GET'])
@login_required
def view_appointments():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Fetch appointments for the hospital's doctors
    appointments = Appointment.query.join(Doctor).filter(Doctor.hospital_id == current_user.hospital_id).all()

    # If no appointments, render the template with an empty list
    if not appointments:
        return render_template('hospital/appointments.html', appointments=[])

    # Prepare appointment details to render in template
    appointments_data = [
        {
            "id": appointment.id,
            "client": appointment.client.client_info.name,
            "doctor": appointment.doctor.name,
            "appointment_time": appointment.appointment_time,
            "status": appointment.status
        }
        for appointment in appointments
    ]
    return render_template('hospital/appointments.html', appointments=appointments_data)

# PUT /hospital/appointments/<int:appointment_id> - Update appointment status
@bp.route('/appointments/<int:appointment_id>', methods=['PUT'])
@login_required
def update_appointment_status(appointment_id):
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Fetch appointment by ID
    appointment = Appointment.query.get(appointment_id)
    if not appointment:
        return jsonify({"message": "Appointment not found."}), 404

    # Ensure the doctor belongs to the hospital
    if appointment.doctor.hospital_id != current_user.hospital_id:
        return jsonify({"message": "Unauthorized to update this appointment."}), 403

    # Update appointment status
    data = request.json
    status = data.get('status')
    if status not in ["Pending", "Confirmed", "Completed", "Cancelled"]:
        return jsonify({"message": "Invalid status."}), 400

    appointment.status = status
    db.session.commit()

    return jsonify({"message": f"Appointment status updated to {status}."}), 200


from flask import current_app  # Add this import for accessing the app context
from flask import Blueprint, request, flash, redirect, url_for, render_template
from app import db
from app.models import User, Hospital, Doctor, Appointment, MedicalHistory
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime
@bp.route('/appointments/edit_history/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def edit_medical_history_from_appointment(appointment_id):
    """
    Allows a hospital doctor to edit medical history after the appointment time has passed.
    Requires security key verification.
    """
    if current_user.role != 'hospital':
        return render_template('403.html'), 403

    # Fetch the appointment by ID
    appointment = Appointment.query.get_or_404(appointment_id)

    # Ensure the appointment belongs to this hospital
    if appointment.doctor.hospital_id != current_user.hospital_id:
        return render_template('403.html', message="Unauthorized to edit this appointment."), 403

    # Get the client and doctor from the appointment
    client = appointment.client
    doctor = appointment.doctor

    # Parse the appointment time from string to datetime
    try:
        appointment_time = datetime.strptime(appointment.appointment_time, '%Y-%m-%d %H:%M')
    except ValueError:
        flash('Invalid appointment time format in database.', 'error')
        return redirect(url_for('hospital_routes.view_appointments'))

    # Check if the current time is after the appointment time
    current_time = datetime.now()  # Adjust for timezone if needed
    if current_time < appointment_time:
        flash(f'Medical history can only be edited after the appointment time ({appointment.appointment_time}).', 'error')
        return redirect(url_for('hospital_routes.view_appointments'))

    # Fetch the medical history for the client (no doctor filter)
    medical_history = MedicalHistory.query.filter_by(client_id=client.id).all()

    if request.method == 'POST':
        medical_note = request.form.get('medical_note')
        security_key = request.form.get('security_key')

        if not medical_note:
            flash('Medical note is required.', 'error')
            return redirect(url_for('hospital_routes.edit_medical_history_from_appointment', appointment_id=appointment_id))

        # Verify the security key
        if not doctor or not check_password_hash(doctor.security_key, security_key):
            flash('Invalid security key.', 'error')
            return redirect(url_for('hospital_routes.edit_medical_history_from_appointment', appointment_id=appointment_id))

        # Create a new medical history entry
        new_history = MedicalHistory(
            medical_note=medical_note,
            client_id=client.id,
            hospital_id=current_user.hospital_id,
            doctor_id=doctor.id if doctor else None,
            timestamp=datetime.now()  # Explicitly set timestamp to current time
        )

        db.session.add(new_history)

        try:
            db.session.commit()
            flash('Medical history added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding medical history: {e}", 'error')

        return redirect(url_for('hospital_routes.edit_medical_history_from_appointment', appointment_id=appointment_id))

    # GET request: Render the edit page
    return render_template(
        'hospital/edit-history.html',
        client={"name": client.client_info.name, "age": client.client_info.age},
        medical_history=medical_history,
        doctor=doctor,
        appointment=appointment
    )

@bp.route('/client/<int:client_id>/history', methods=['GET'])
@login_required
def view_medical_history(client_id):
    if current_user.role != 'hospital':
        return render_template('403.html'), 403  # Unauthorized access template

    # Fetch the client
    client = User.query.get(client_id)
    if not client:
        return render_template('404.html', message="Client not found."), 404

    # Ensure the hospital is authorized to access this client's history
    hospital = Hospital.query.get(current_user.hospital_id)
    if not hospital:
        return render_template('404.html', message="Hospital not found."), 404

    # Check if the client has any appointment with the hospital's doctors
    appointment_exists = Appointment.query.join(Doctor).filter(
        Appointment.client_id == client_id,
        Doctor.hospital_id == hospital.id
    ).first()
    if not appointment_exists:
        return render_template('403.html', message="You can only access history for clients with appointments."), 403

    # Fetch medical history for the client
    medical_history = MedicalHistory.query.filter_by(client_id=client_id).all()

    return render_template('hospital/view-history.html', client={"id": client.id, "name": client.client_info.name, "age": client.client_info.age},
        medical_history=medical_history)


@bp.route('/clients', methods=['GET'])
@login_required
def view_clients():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    hospital = Hospital.query.get(current_user.hospital_id)
    if not hospital:
        return jsonify({"message": "Hospital not found."}), 404

    appointments = Appointment.query.join(Doctor).filter(Doctor.hospital_id == hospital.id).all()
    client_ids = {appointment.client_id for appointment in appointments}
    clients = User.query.filter(User.id.in_(client_ids), User.role == 'client').all()

    # If no clients, render the template with an empty list
    if not clients:
        return render_template('hospital/clients.html', clients=[])

    clients_data = [
        {
            "id": client.id,
            "username": client.username,
            "email": client.email,
            "client_details": {
                "name": client.client_info.name,
                "age": client.client_info.age,
                "address": client.client_info.address,
            } if client.client_info else None
        }
        for client in clients
    ]
    return render_template('hospital/clients.html', clients=clients_data)

from flask import request, jsonify, redirect,session

def custom_hospital_logout():
    """Custom logout function for the hospital."""
    if current_user.is_authenticated and current_user.role == 'hospital':
        # Perform additional tasks if needed, such as logging out specific sessions, clearing cookies, etc.
        session.pop('_user_id', None)  # Remove the user ID from the session
        session.clear()  # Clear the session data if necessary

        # Optionally, you can log any activity (e.g., logging the user out for auditing)
        # app.logger.info(f"Hospital {current_user.id} logged out")

        # Return a message or status
        return jsonify({"message": "Successfully logged out."}), 200
    else:
        return jsonify({"message": "Unauthorized access."}), 403


@bp.route('/logout', methods=['GET', 'POST'])
@login_required
def hospital_logout():
    if current_user.role != 'hospital':
        return jsonify({"message": "Unauthorized access."}), 403

    # Call the custom logout function
    logout_response = custom_hospital_logout()
    

    # If it's a POST request, handle the redirect after logging out
    if request.method == 'POST':
        logout_user()
        # Return the response for POST request and redirect to login page
        return redirect('/hospital/login')
         
    
    
    # Optionally handle GET request (you can redirect or show a message)
    return redirect('/hospital/login')  # Or return a custom page for GET requests


@bp.route('/reviews/<int:hospital_id>', methods=['GET'])
@login_required
def get_reviews(hospital_id):
    if current_user.role != 'hospital' or current_user.hospital_id != hospital_id:
        return jsonify({'error': 'Unauthorized access'}), 403

    reviews = Review.query.filter_by(hospital_id=hospital_id).all()
    reviews_data = [
        {
            'id': review.id,
            'rating': review.rating,
            'review_text': review.review_text,
            'reply_text': review.reply_text,
            'client_name': review.client.username,
            'timestamp': review.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        for review in reviews
    ]

    return jsonify(reviews_data), 200


@bp.route('/reply/<int:review_id>', methods=['POST'])
@login_required
def reply_to_review(review_id):
    if current_user.role != 'hospital':
        return jsonify({'error': 'Only hospitals can reply to reviews'}), 403

    review = Review.query.get_or_404(review_id)
    if review.hospital_id != current_user.hospital_id:
        return jsonify({'error': 'Unauthorized access'}), 403

    data = request.get_json()
    reply_text = data.get('reply_text')
    if not reply_text:
        return jsonify({'error': 'Reply text cannot be empty'}), 400

    review.reply_text = reply_text
    db.session.commit()

    return jsonify({'message': 'Reply added successfully!'}), 200

