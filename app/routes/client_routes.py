import os
import random
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, send_file, session  # Added session import
from flask_login import login_user, login_required, current_user, logout_user
from app import db
from app.models import User, Client, Hospital, Doctor, Appointment, MedicalHistory, Review
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from io import BytesIO
from fpdf import FPDF
from twilio.rest import Client as TwilioClient
import logging
import google.generativeai as genai
bp= Blueprint('client_routes', __name__)


# Hardcoded Twilio credentials (replace with your actual credentials)


# Initialize Twilio client with hardcoded credentials
twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
def generate_otp():
    """Generate a random 6-digit OTP."""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

# Client Sign-Up Route
from flask import render_template

# Client Sign-Up Route
@bp.route('/signup', methods=['GET', 'POST'])
def client_signup():
    if request.method == 'POST':
        # Expect form data since client signup likely involves file uploads or complex fields
        data = request.form
        
        # Validate the incoming data
        if not data.get('email') or not data.get('phone_number') or not data.get('password') or not data.get('name') or not data.get('age') or not data.get('address'):
            return jsonify({"message": "Missing required fields"}), 400

        # Check if the email or phone number already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"message": "Email already exists"}), 409
        if Client.query.filter_by(phone_number=data['phone_number']).first():
            return jsonify({"message": "Phone number already registered"}), 409

        # Create a new User (client) object
        hashed_password = generate_password_hash(data['password'])
        new_user = User(
            username=f"client_{data['phone_number']}",  # Generate a dummy username based on phone number
            email=data['email'],
            password=hashed_password,
            role='client'
        )

        db.session.add(new_user)
        db.session.commit()

        # Create the associated Client record
        new_client = Client(
            name=data['name'],
            age=data['age'],
            address=data['address'],
            phone_number=data['phone_number'],  # Store phone number
            user_id=new_user.id
        )

        db.session.add(new_client)
        db.session.commit()

        return jsonify({
            "message": "Client registered successfully",
            "client": {
                "phone_number": new_client.phone_number,  # Return phone_number instead of username
                "email": new_user.email,
                "name": new_client.name,
                "age": new_client.age,
                "address": new_client.address
            }
        }), 201
    
    # Render the signup page (GET request)
    return render_template('client/signup.html')

# Client Login Route (Updated to use phone_number instead of username)
@bp.route('/login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        data = request.get_json()

        # Validate the incoming data
        if not data.get('phone_number') or not data.get('password'):
            return jsonify({"message": "Missing required fields"}), 400

        # Find the client by phone_number
        client = Client.query.filter_by(phone_number=data['phone_number']).first()
        if not client:
            return jsonify({"message": "Invalid phone number"}), 401

        # Find the associated user
        user = User.query.filter_by(id=client.user_id, role='client').first()
        if not user or not check_password_hash(user.password, data['password']):
            return jsonify({"message": "Invalid credentials"}), 401

        # Log the user in using Flask-Login
        login_user(user)

        return jsonify({
            "message": "Login successful",
            "user": {
                "phone_number": client.phone_number,  # Return phone_number instead of username
                "email": user.email,
                "role": user.role
            }
        }), 200
    
    # Render the login page (GET request)
    return render_template('client/login.html')
# Forgot Password Route with Custom OTP
@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        phone_number = data.get('phone_number')
        if not phone_number:
            return jsonify({"message": "Phone number is required."}), 400

        client = Client.query.filter_by(phone_number=phone_number).first()
        if not client:
            return jsonify({"message": "No client found with this phone number."}), 404

        user = User.query.filter_by(id=client.user_id, role='client').first()
        if not user:
            return jsonify({"message": "User account not found."}), 404

        # Generate and store OTP
        otp = generate_otp()
        session['reset_phone_number'] = phone_number
        session['otp'] = otp

        # Send OTP via Twilio SMS
        try:
            message = twilio_client.messages.create(
                body=f"Your OTP for password reset is: {otp}",
                from_=TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            print(f"OTP sent: {otp}, Message SID: {message.sid}")
            return jsonify({"message": "OTP sent to your phone number.", "redirect_url": "/client/reset-password"}), 200
        except Exception as e:
            print(f"Twilio Error: {str(e)}")
            return jsonify({"message": f"Error sending OTP: {str(e)}"}), 500

    return render_template('client/forgot-password.html')

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

        client = Client.query.filter_by(phone_number=phone_number).first()
        if not client:
            return jsonify({"message": "Invalid session or phone number."}), 404

        user = User.query.filter_by(id=client.user_id, role='client').first()
        if not user:
            return jsonify({"message": "User account not found."}), 404

        stored_otp = session.get('otp')
        if otp != stored_otp:
            return jsonify({"message": "Invalid or expired OTP."}), 401

        user.password = generate_password_hash(new_password)
        db.session.commit()
        session.pop('reset_phone_number', None)
        session.pop('otp', None)
        return jsonify({"message": "Password reset successfully. Please log in.", "redirect_url": "/client/login"}), 200

    return render_template('client/reset-password.html')
@bp.route('/dashboard', methods=['GET'])
@login_required
def client_dashboard():
    return render_template('client/dashboard.html')

from flask import render_template

from sqlalchemy import func

from jinja2 import Template

import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@bp.route('/hospitals/search', methods=['GET'])
@login_required
def search_hospitals():
    query = request.args.get('query', default=None, type=str)
    sort_by = request.args.get('sort_by', default=None, type=str)

    logger.debug(f"Search query: {query}, Sort by: {sort_by}")

    # Base query for approved hospitals
    query_base = db.session.query(Hospital).filter(Hospital.is_approved == True)

    if query:
        try:
            # Search across address and pin_code
            query_base = query_base.filter(
                db.or_(
                    Hospital.address.ilike(f'%{query}%'),
                    Hospital.pin_code.ilike(f'%{query}%')
                )
            )
            # Debug the base query before adding review filter
            base_hospitals = query_base.all()
            logger.debug(f"Hospitals after address/pin_code filter: {len(base_hospitals)}")

            # Separate review search
            review_hospitals = db.session.query(Review.hospital_id).filter(
                Review.review_text.ilike(f'%{query}%')
            ).distinct().all()
            hospital_ids_from_reviews = [row[0] for row in review_hospitals]  # Extract hospital_id from tuple
            logger.debug(f"Hospital IDs from reviews: {hospital_ids_from_reviews}")

            # Combine with review filter if there are matching reviews
            if hospital_ids_from_reviews:
                query_base = db.session.query(Hospital).filter(
                    db.or_(
                        Hospital.id.in_(hospital_ids_from_reviews),
                        Hospital.id.in_([h.id for h in base_hospitals])  # Preserve address/pin_code results
                    ),
                    Hospital.is_approved == True
                )
            else:
                logger.debug("No review matches found, sticking with address/pin_code results")

        except Exception as e:
            logger.error(f"Error in query: {str(e)}")
            return render_template('client/hospital-search.html', error=f"Search error: {str(e)}", hospitals=[])

    # Sorting logic
    try:
        if sort_by == 'rating_desc':
            query_base = query_base.outerjoin(Review).group_by(Hospital.id).order_by(db.func.avg(Review.rating).desc().nullslast())
        elif sort_by == 'rating_asc':
            query_base = query_base.outerjoin(Review).group_by(Hospital.id).order_by(db.func.avg(Review.rating).asc().nullslast())
    except Exception as e:
        logger.error(f"Error in sorting: {str(e)}")
        return render_template('client/hospital-search.html', error=f"Sort error: {str(e)}", hospitals=[])

    # Execute query
    try:
        hospitals = query_base.all()
        logger.debug(f"Final hospital count: {len(hospitals)}")
    except Exception as e:
        logger.error(f"Error executing query: {str(e)}")
        return render_template('client/hospital-search.html', error=f"Database error: {str(e)}", hospitals=[])

    # Calculate average ratings
    hospitals_with_ratings = []
    for hospital in hospitals:
        reviews = Review.query.filter_by(hospital_id=hospital.id).all()
        average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
        hospitals_with_ratings.append((hospital, int(round(average_rating, 1))))

    return render_template('client/hospital-search.html', hospitals=hospitals_with_ratings, query=query, int=int)
@bp.route('/hospitals/<int:hospital_id>', methods=['GET'])
@login_required
def get_hospital_details(hospital_id):
    # Retrieve the hospital from the database by ID
    hospital = Hospital.query.get(hospital_id)
    
    if hospital is None:
        return render_template('client/hospital-search.html', error="Hospital not found")
    
    # Get the list of doctors for the hospital
    doctors = hospital.doctors  # Assuming you have a relationship defined as `doctors` in the Hospital model

    # Compute the average rating for the hospital
    from sqlalchemy.sql import func
    average_rating = db.session.query(func.avg(Review.rating)).filter_by(hospital_id=hospital_id).scalar()
    average_rating = round(average_rating) if average_rating else 0  # Default to 0 if no ratings

    return render_template(
        'client/hospital.html',
        hospital=hospital,
        doctors=doctors,
        average_rating=average_rating
    )
@bp.route('/hospital/<int:hospital_id>/doctors', methods=['GET'])
@login_required
def get_doctors_in_hospital(hospital_id):
    # Retrieve the hospital from the database
    hospital = Hospital.query.get(hospital_id)
    
    if hospital is None:
        # Render an error page or redirect with an error message
        return render_template('error.html', message="Hospital not found"), 404
    
    # Query the doctors for the specified hospital
    doctors = hospital.doctors  # Assuming you have a relationship defined as `doctors` in Hospital model
    
    # Render the doctors.html template with the hospital and doctors data
    return render_template('client/doctors.html', hospital=hospital, doctors=doctors)

from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



@bp.route('/appointments/book/<int:doctor_id>', methods=['GET', 'POST'])
@login_required
def book_appointment(doctor_id):
    """
    Handles appointment booking for a specific doctor.
    Prevents past dates and overlapping appointments with the same doctor.
    """
    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({"message": "Doctor not found"}), 404

    if request.method == 'GET':
        # Retrieve the client's existing appointments with this doctor
        appointments = Appointment.query.filter_by(doctor_id=doctor_id, client_id=current_user.id).all()
        return render_template('client/booking.html', doctor=doctor, appointments=appointments)

    elif request.method == 'POST':
        appointment_time_str = request.form.get('appointment_time')

        if not appointment_time_str:
            return render_template('client/booking.html', doctor=doctor, error_message="Missing required fields")

        # Ensure only clients can book
        if current_user.role != 'client':
            return render_template('client/booking.html', doctor=doctor, error_message="Only clients can book appointments")

        # Parse the appointment time from datetime-local input (e.g., "2025-03-20T14:30")
        try:
            appointment_time = datetime.strptime(appointment_time_str, '%Y-%m-%dT%H:%M')
            # Convert back to a consistent string format for storage
            appointment_time_str_db = appointment_time.strftime('%Y-%m-%d %H:%M')
        except ValueError:
            return render_template('client/booking.html', doctor=doctor, error_message="Invalid date format. Use YYYY-MM-DD HH:MM")

        # Check if the appointment time is in the past
        current_time = datetime.now()
        if appointment_time < current_time:
            return render_template('client/booking.html', doctor=doctor, error_message="Cannot book appointments in the past")

        # Check for existing appointments at the same time for this doctor
        existing_appointment = Appointment.query.filter(
            Appointment.doctor_id == doctor_id,
            Appointment.appointment_time == appointment_time_str_db,
            Appointment.status.in_(["Pending", "Confirmed"])  # Check both Pending and Confirmed
        ).first()

        if existing_appointment:
            if existing_appointment.client_id != current_user.id:
                return render_template('client/booking.html', doctor=doctor, error_message="This time slot is already booked by another client")
            else:
                return render_template('client/booking.html', doctor=doctor, error_message="You already have an appointment at this time")

        # Create the appointment
        appointment = Appointment(
            appointment_time=appointment_time_str_db,
            status="Pending",
            doctor_id=doctor.id,
            client_id=current_user.id
        )

        try:
            db.session.add(appointment)
            db.session.commit()
            appointments = Appointment.query.filter_by(doctor_id=doctor_id, client_id=current_user.id).all()
            return render_template(
                'client/booking.html',
                doctor=doctor,
                success_message="Appointment booked successfully",
                appointments=appointments
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error booking appointment: {str(e)}")
            return render_template('client/booking.html', doctor=doctor, error_message=f"Failed to book appointment: {str(e)}")
@bp.route('/appointments/cancel/<int:appointment_id>', methods=['GET'])
@login_required
def cancel_appointment(appointment_id):
    """
    Handles the cancellation of a client's appointment.
    """
    # Retrieve the appointment to be canceled
    appointment = Appointment.query.get(appointment_id)

    if not appointment:
        return jsonify({"message": "Appointment not found"}), 404

    # Check if the current user is the one who booked the appointment
    if appointment.client_id != current_user.id:
        return jsonify({"message": "You are not authorized to cancel this appointment"}), 403

    try:
        # Delete the appointment
        db.session.delete(appointment)
        db.session.commit()
        
        # Redirect back to the doctor's booking page with a success message
        return redirect(url_for('client_routes.book_appointment', doctor_id=appointment.doctor_id, success_message="Appointment canceled successfully"))
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Failed to cancel appointment", "error": str(e)}), 500
@bp.route('/medical-history', methods=['GET'])
@login_required
def get_current_user_medical_history():
    """
    Retrieves and displays the medical history of the logged-in client.
    """
    # Check if the logged-in user is a client
    if current_user.role != 'client':
        return jsonify({"message": "Access denied. Only clients can view medical history."}), 403

    # Retrieve the medical history for the logged-in client
    medical_histories = MedicalHistory.query.filter_by(client_id=current_user.id).all()

    if not medical_histories:
        return render_template('client/medical_history.html', message="No medical history found.")

    # Format the medical history for the template, including the hospital name and doctor's name
    history_list = []
    for history in medical_histories:
        hospital = Hospital.query.get(history.hospital_id)
        doctor = Doctor.query.get(history.doctor_id)  # Assuming there is a doctor_id field in the MedicalHistory model
        history_list.append({
            "id": history.id,
            "medical_note": history.medical_note,
            "timestamp": history.timestamp.isoformat(),
            "hospital_name": hospital.name if hospital else "Unknown",
            "doctor_name": doctor.name if doctor else "Unknown Doctor",  # Add the doctor's name
        })

    return render_template('client/medical_history.html', medical_histories=history_list)


@bp.route('/profile', methods=['GET'])
@login_required
def client_profile():
    profile = {
        
        "email": current_user.email,
        "client_info": {
            "name": current_user.client_info.name if current_user.client_info else None,
            "age": current_user.client_info.age if current_user.client_info else None,
            "address": current_user.client_info.address if current_user.client_info else None,
            "phonenumber":current_user.client_info.phone_number if current_user.client_info else None
        }
    }
    return render_template('client/profile.html', profile=profile)
from flask import flash, redirect, url_for

@bp.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def client_edit_profile():
    if request.method == 'POST':
        data = request.form

        # Update the User model
       
        if "email" in data:
            current_user.email = data["email"]

        # Update Client Info (if the user is a client)
        if current_user.role == 'client' and current_user.client_info:
            client_info = current_user.client_info

            if "name" in data:
                client_info.name = data["name"]

            if "age" in data:
                client_info.age = int(data["age"]) if data["age"].isdigit() else None

            if "address" in data:
                client_info.address = data["address"]

        # Commit changes to the database
        db.session.commit()

        # Flash a success message
        flash("Your profile has been updated successfully!", "success")
        return redirect(url_for('client_routes.client_profile'))  # Redirect to profile page

    # Render edit profile page
    profile = {
        
        "email": current_user.email,
        "client_info": {
            "name": current_user.client_info.name if current_user.client_info else None,
            "age": current_user.client_info.age if current_user.client_info else None,
            "address": current_user.client_info.address if current_user.client_info else None
        }
    }
    return render_template('client/edit-profile.html', profile=profile)

from flask import request, jsonify
import google.generativeai as genai

# Configure the API key
genai.configure(api_key="AIzaSyAqG82KPp49bu-zd2hg_Ss5Glf0wi1PCHY")
model = genai.GenerativeModel("gemini-1.5-flash")

@bp.route('/chatbot', methods=['POST'])
@login_required
def chatbot_response():
    data = request.get_json()
    symptom = data.get('symptom')

    # Generate response from Gemini
    gemini_response = model.generate_content(f"consider yourself as a medical professional. I am going to give you a Symptom, simply answer which doctor to consult and what might be the potential disease or diagnose. answer in just 2 t0 5 scentence. SYmpton: {symptom}. What could it be? Provide advice.")
    response_message = gemini_response.text

    # You can add logic here to link hospitals based on the symptom
    hospital_link = "/client/hospitals/search"

    return jsonify({
        'message': response_message,
        'hospital_link': hospital_link
    })


from flask import redirect, url_for

@bp.route('/logout', methods=['GET','POST'])
@login_required
def client_logout():
    if current_user.role != 'client':
        return jsonify({"message": "Unauthorized access."}), 403
    
    # Log out the user (invalidate the session)
    logout_user()

    # Redirect to the login page after logout
    return redirect('/client/login')  # Adjust 'auth.login' to match the actual blueprint and route name for login

@bp.route('/hospital/<int:hospital_id>/reviews/add', methods=['POST'])
@login_required
def add_hospital_review(hospital_id):
    if current_user.role != 'client':
        return redirect('/login')

    rating = int(request.form['rating'])
    review_text = request.form['review_text']

    if not (1 <= rating <= 5):
        flash('Rating must be between 1 and 5.')
        return redirect(f'/hospital/{hospital_id}/reviews')

    review = Review(rating=rating, review_text=review_text, client_id=current_user.id, hospital_id=hospital_id)
    db.session.add(review)
    db.session.commit()

    flash('Review submitted successfully!')
    return redirect(f'/client/hospital/{hospital_id}/reviews')
@bp.route('/hospital/<int:hospital_id>/reviews', methods=['GET'])
@login_required
def view_hospital_reviews(hospital_id):
    hospital = Hospital.query.get_or_404(hospital_id)

    # Fetch reviews for the hospital
    reviews = Review.query.filter_by(hospital_id=hospital_id).order_by(Review.timestamp.desc()).all()

    # Pass the reviews and hospital information to the template
    return render_template('client/hospital_reviews.html', hospital=hospital, reviews=reviews)



from io import BytesIO
from flask import send_file
from fpdf import FPDF

from flask import Blueprint, jsonify, send_file
from app import db
from app.models import User, Client, Hospital, Doctor, Appointment, MedicalHistory, Review
from flask_login import login_required, current_user
from io import BytesIO
from fpdf import FPDF

@bp.route('/download-medical-history-pdf', methods=['GET'])
@login_required
def download_medical_history_pdf():
    """
    Allows the logged-in client to download their medical history as a PDF, including client info.
    """
    # Check if the logged-in user is a client
    if current_user.role != 'client':
        return jsonify({"message": "Access denied. Only clients can download medical history."}), 403

    # Retrieve the medical history for the logged-in client
    medical_histories = MedicalHistory.query.filter_by(client_id=current_user.id).all()

    if not medical_histories:
        return jsonify({"message": "No medical history found."}), 404

    # Get client info from the Client model
    client_info = current_user.client_info  # Access via User.client_info relationship
    if not client_info:
        return jsonify({"message": "Client information not found."}), 500

    # Prepare the PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Set font for the title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="Medical History Report", ln=True, align='C')
    pdf.ln(10)

    # Add client information
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, txt="Patient Information", ln=True)
    pdf.set_font('Arial', '', 12)
    pdf.cell(200, 10, txt=f"Name: {client_info.name}", ln=True)
    pdf.cell(200, 10, txt=f"Age: {client_info.age}", ln=True)
    pdf.cell(200, 10, txt=f"Phone Number: {client_info.phone_number}", ln=True)
    pdf.ln(10)  # Add spacing after client info

    # Add medical history records
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, txt="Medical History", ln=True)
    pdf.set_font('Arial', '', 12)

    for history in medical_histories:
        hospital = history.hospital  # Access the Hospital object
        hospital_name = hospital.name if hospital else "Unknown Hospital"
        doctor = Doctor.query.get(history.doctor_id)
        doctor_name = doctor.name if doctor else "Unknown Doctor"

        pdf.ln(5)
        pdf.cell(200, 10, txt=f"Hospital: {hospital_name}", ln=True)
        pdf.cell(200, 10, txt=f"Doctor: {doctor_name}", ln=True)
        pdf.cell(200, 10, txt=f"Medical Note: {history.medical_note}", ln=True)
        pdf.cell(200, 10, txt=f"Timestamp: {history.timestamp}", ln=True)
        pdf.ln(5)  # Space between entries

    # Generate PDF as bytes
    pdf_output = pdf.output(dest='S').encode('latin1')
    pdf_stream = BytesIO(pdf_output)
    pdf_stream.seek(0)

    # Send the PDF as a downloadable file
    return send_file(pdf_stream, as_attachment=True, download_name="medical_history.pdf", mimetype="application/pdf")
