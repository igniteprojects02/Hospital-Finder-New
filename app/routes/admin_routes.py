from flask import Blueprint, jsonify, request,session
from app import db
from flask import redirect, url_for, render_template
import os
from flask_login import login_required
from app.models import Hospital, User
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

# 1. Get all pending signup requests (hospitals that are not approved yet)
bp = Blueprint('admin_routes', __name__)

@bp.route('/signup-requests', methods=['GET'])
@login_required
def get_signup_requests():
    hospitals = Hospital.query.filter_by(is_approved=False).all()
    return jsonify([
        {
            "id": h.id,
            "name": h.name,
            "address": h.address,
            "gmap_location": h.gmap_location,
            "phone_number":h.phone_number,
            "pin_code": h.pin_code,
            "description": h.description
        } for h in hospitals
    ])

@bp.route('/approve-hospital/<int:hospital_id>', methods=['POST'])
@login_required
def approve_hospital(hospital_id):
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    hospital = Hospital.query.get_or_404(hospital_id)
    if hospital.is_approved:
        return jsonify({"message": "Hospital is already approved."}), 400

    hospital.is_approved = True
    db.session.commit()
    return jsonify({"message": f"Hospital '{hospital.name}' approved!"}), 200

# Decline a hospital signup request (Delete hospital from signup list)
@bp.route('/decline-hospital/<int:hospital_id>', methods=['DELETE'])
@login_required
def decline_hospital(hospital_id):
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    hospital = Hospital.query.get_or_404(hospital_id)

    if hospital.is_approved:
        return jsonify({"message": "Approved hospitals cannot be declined."}), 400

    # Find and delete the associated user
    user = User.query.filter_by(hospital_id=hospital.id).first()
    if user:
        db.session.delete(user)

    # Delete the hospital
    db.session.delete(hospital)
    db.session.commit()

    return jsonify({"message": f"Hospital '{hospital.name}' signup request declined!"}), 200

# 4. Get all approved hospitals
@bp.route('/approved-hospitals', methods=['GET'])
@login_required
def get_approved_hospitals():
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    hospitals = Hospital.query.filter_by(is_approved=True).all()
    return jsonify([
        {
            "id": h.id,
            "name": h.name,
            "address": h.address,
            "gmap_location": h.gmap_location,
            "phone_number":h.phone_number,
            "pin_code": h.pin_code,
            "description": h.description
        } for h in hospitals
    ])



@bp.route('/remove-hospital/<int:hospital_id>', methods=['POST'])
@login_required
def remove_hospital(hospital_id):
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    hospital = Hospital.query.get_or_404(hospital_id)

    if not hospital.is_approved:
        return jsonify({"message": "Hospital is not approved."}), 400
    if hospital.is_removed:
        return jsonify({"message": "Hospital is already removed."}), 400

    # Expect JSON data with a 'reason' field
    data = request.get_json()
    reason = data.get('reason') if data else None
    if not reason:
        return jsonify({"message": "Reason for removal is required."}), 400

    # Mark hospital as removed and unapprove it
    hospital.is_removed = True
    hospital.removed_reason = reason
    hospital.is_approved = False  # Set is_approved to False (0)

    # Optionally, remove associated user (if desired)
    user = User.query.filter_by(hospital_id=hospital.id).first()
    if user:
        db.session.delete(user)

    db.session.commit()
    return jsonify({"message": f"Hospital '{hospital.name}' moved to trash with reason: {reason}"}), 200

# 6. New Trash Route: Get all removed hospitals
@bp.route('/trash', methods=['GET'])
@login_required
def get_trash():
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    removed_hospitals = Hospital.query.filter_by(is_removed=True).all()
    return jsonify([
        {
            "id": h.id,
            "name": h.name,
            "address": h.address,
            "gmap_location": h.gmap_location,
            "phone_number": h.phone_number,
            "pin_code": h.pin_code,
            "description": h.description,
            "removed_reason": h.removed_reason
        } for h in removed_hospitals
    ])

from flask import redirect, url_for

from flask import request

@bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized access."}), 403
    # Pop session variables (if you have specific session data to remove)
    session.pop('user_id', None)  # Example: Remove 'user_id' from session
    session.pop('some_other_session_var', None)  # Example: Another session variable

    """Logs out the current user and redirects to the login page."""
    # Check if the request is a POST request (for logout action)
    if request.method == 'POST':
        logout_user()
        return redirect('/admin/login')
    
    # If the method is GET, you could either display a confirmation page or redirect directly.
    return redirect('/admin/logout')  # Or you could show a logout confirmation message


@bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.is_json:  # Check if the request is JSON
            data = request.get_json()  # Parse the JSON data
            username = data.get('username')
            password = data.get('password')

            # Check the predefined admin credentials
            if User.check_admin_credentials(username, password):
                user = User.query.filter_by(username=username).first()
                if not user:
                    user = User(username=username, email='admin@example.com', password=generate_password_hash(password), role='admin')
                    db.session.add(user)
                    db.session.commit()

                login_user(user)
                # Return a redirect URL to the frontend
                return jsonify({"message": "Login successful", "redirect_url": "/admin/dashboard"}), 200  # Respond with success and redirect URL

            else:
                return jsonify({"message": "Invalid credentials"}), 401  # Invalid login credentials

        else:
            return render_template('admin/login.html')  # Handle regular form-based GET requests

    return render_template('admin/login.html')
@bp.route('/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')
