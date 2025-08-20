from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, send_from_directory, session
from sqlalchemy import func, text
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import os
import urllib.parse
import random
import json
from flask_mail import Message as MailMessage
from flask_login import login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from app import mail, db
from models import (
    BodyPart, Category, Procedure, User, Doctor, DoctorCategory,
    DoctorProcedure, Review, ReviewReply, Community, CommunityReply,
    CommunityTagging, UserPreference, Notification, Interaction,
    DoctorPhoto, DoctorAvailability, Lead, Message, CommunityModeration,
    Thread, ThreadAnalytics, Favorite, Appointment,
    Banner, BannerSlide
)
from app import db
import logging

# Import new admin systems
from admin_credit_system import admin_credit_bp
from admin_transaction_history import admin_history_bp, AdminHistoryService
from dispute_management_system import dispute_bp, DisputeService

# Create logger
logger = logging.getLogger(__name__)

# Define forms for authentication
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')
    
class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=50)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Sign Up')
    
class ReviewReplyForm(FlaskForm):
    reply_text = StringField('Reply', validators=[DataRequired()])
    submit = SubmitField('Submit Reply')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different one or login.')
            
    def validate_phone_number(self, phone_number):
        # Check if phone number is 10 digits and numeric
        if not phone_number.data.isdigit() or len(phone_number.data) != 10:
            raise ValidationError('Please enter a valid 10-digit phone number without spaces or special characters.')
            
        # Check if phone number is already in use
        user = User.query.filter_by(phone_number=phone_number.data).first()
        if user:
            raise ValidationError('This phone number is already registered. Please use a different one.')

# Create Blueprint for API routes
api = Blueprint('api_routes', __name__, url_prefix='/api')

# Create Blueprint for web routes
web = Blueprint('web', __name__)

# Authentication decorators
from functools import wraps
from flask import session, abort

# Using Flask-Login's login_required decorator instead of our custom one
# The login_required function is imported from flask_login

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Debug logging to see what's happening
        logger.info(f"Admin check - User authenticated: {current_user.is_authenticated}")
        if current_user.is_authenticated:
            logger.info(f"Admin check - User role: {current_user.role}")
            logger.info(f"Admin check - User email: {current_user.email}")
        
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page', 'danger')
            logger.warning(f"Admin access denied for user: {current_user.email if current_user.is_authenticated else 'anonymous'}")
            return redirect(url_for('web.index'))
        return f(*args, **kwargs)
    return decorated_function

def doctor_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'doctor':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('web.index'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to send email
def send_email(subject, recipients, template):
    """
    Send an email using Flask-Mail.
    
    Args:
        subject: Email subject
        recipients: List of email recipients
        template: HTML content of the email
    """
    try:
        msg = MailMessage(subject, recipients=recipients)
        msg.html = template
        mail.send(msg)
        logger.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False

# Helper function to calculate growth percentage
def calculate_growth_percentage(current, previous):
    """
    Calculate growth percentage between two periods with robust error handling.
    
    Args:
        current: Count in current period
        previous: Count in previous period
        
    Returns:
        Percentage growth (can be negative for decrease)
    """
    logger.debug(f"Calculating growth percentage: current={current}, previous={previous}")
    
    # Handle None values
    if current is None:
        logger.debug("Current value is None, defaulting to 0")
        current = 0
    if previous is None:
        logger.debug("Previous value is None, defaulting to 0")
        previous = 0
        
    # Convert to integers in case they're not
    try:
        current = int(current)
        previous = int(previous)
    except (TypeError, ValueError) as e:
        logger.error(f"Type conversion error in growth calculation: {str(e)}")
        return 0
    
    # Safety checks
    if not isinstance(current, (int, float)) or not isinstance(previous, (int, float)):
        logger.error(f"Invalid types in growth calculation: current={type(current)}, previous={type(previous)}")
        return 0
    
    if previous == 0:
        # If there was nothing before, but there is now, that's 100% growth
        growth = 100 if current > 0 else 0
        logger.debug(f"Previous is zero, setting growth to {growth}")
        return growth
        
    # Calculate percentage change
    try:
        change = ((current - previous) / previous) * 100
        # Round to nearest integer
        result = round(change)
        logger.debug(f"Calculated growth: {result}%")
        return result
    except Exception as e:
        # Catch any other unexpected errors
        logger.error(f"Error in growth calculation: {str(e)}")
        return 0

# Review retrieval, edit and delete endpoints
@web.route('/review/<int:id>', methods=['GET'])
@login_required
def get_review(id):
    """
    Get a specific review.
    
    Args:
        id: The ID of the review to retrieve
    """
    review = Review.query.filter_by(id=id, user_id=current_user.id).first()
    if not review:
        return jsonify({'success': False, 'message': 'Review not found or not authorized'}), 404
    
    return jsonify({
        'success': True, 
        'review': {
            'id': review.id,
            'rating': review.rating,
            'content': review.content,
            'created_at': review.created_at.isoformat() if review.created_at else None,
            'procedure_id': review.procedure_id,
            'doctor_id': review.doctor_id
        }
    })

@web.route('/review/edit/<int:id>', methods=['POST'])
@login_required
def edit_review(id):
    """
    Edit an existing review.
    
    Args:
        id: The ID of the review to edit
    """
    review = Review.query.filter_by(id=id, user_id=current_user.id).first()
    if not review:
        return jsonify({'success': False, 'message': 'Review not found or not authorized'}), 404
    
    data = request.get_json()
    if not data or 'rating' not in data or 'content' not in data:
        return jsonify({'success': False, 'message': 'Rating and content are required'}), 400
    
    review.rating = data['rating']
    review.content = data['content']
    review.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Review updated successfully'})

@web.route('/review/delete/<int:id>', methods=['POST'])
@login_required
def delete_review(id):
    """
    Delete a review.
    
    Args:
        id: The ID of the review to delete
    """
    review = Review.query.filter_by(id=id, user_id=current_user.id).first()
    if not review:
        return jsonify({'success': False, 'message': 'Review not found or not authorized'}), 404
    
    db.session.delete(review)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Review deleted successfully'})

# Appointment action endpoint
@web.route('/appointment/<action>/<int:id>', methods=['POST'])
@login_required
def appointment_action(action, id):
    """
    Handle appointment actions (confirm, complete, cancel, etc).
    
    Args:
        action: The action to perform on the appointment (confirm, complete, cancel)
        id: The ID of the appointment
    """
    if action not in ['confirm', 'complete', 'cancel']:
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    
    # In our system, appointments are stored in the leads table
    appointment = Lead.query.filter_by(id=id, user_id=current_user.id).first()
    if not appointment:
        return jsonify({'success': False, 'message': 'Appointment not found or not authorized'}), 404
    
    # Map actions to statuses
    status_map = {
        'confirm': 'confirmed',
        'complete': 'completed',
        'cancel': 'cancelled'
    }
    
    # Set the new status based on the action
    new_status = status_map.get(action)
    appointment.status = new_status
    
    # Add updated timestamp
    appointment.updated_at = datetime.utcnow()
    
    # Add a notification (if applicable)
    if action == 'confirm':
        # Create a notification for the doctor about the confirmed appointment
        if appointment.doctor_id:
            notification = Notification()
            notification.user_id = appointment.doctor_id
            notification.type = "Appointment Confirmed"
            notification.message = f"Appointment with {current_user.username} on {appointment.appointment_date} has been confirmed."
            notification.response_type = "appointment_update"
            db.session.add(notification)
    
    db.session.commit()
    
    action_messages = {
        'confirm': 'Appointment confirmed successfully',
        'complete': 'Appointment marked as completed',
        'cancel': 'Appointment cancelled successfully'
    }
    
    return jsonify({'success': True, 'message': action_messages.get(action, f'Appointment {action} successful')})

@web.route('/doctor/<int:doctor_id>/appointments')
@login_required
def doctor_appointments(doctor_id):
    """Render the doctor appointments page."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get upcoming appointments (using Lead model)
        today = datetime.now().date()
        upcoming_appointments = Lead.query.filter(
            Lead.doctor_id == doctor.id,
            Lead.appointment_date >= today,
            Lead.status.in_(['pending', 'confirmed'])
        ).order_by(Lead.appointment_date).all()
        
        # Get past appointments
        past_appointments = Lead.query.filter(
            Lead.doctor_id == doctor.id,
            Lead.appointment_date < today
        ).order_by(Lead.appointment_date.desc()).all()
        
        return render_template('doctor_appointments.html', 
                               doctor=doctor, 
                               upcoming_appointments=upcoming_appointments, 
                               past_appointments=past_appointments)
    except Exception as e:
        logger.error(f"Error in doctor_appointments: {str(e)}")
        flash('An error occurred while loading appointments.', 'danger')
        return redirect(url_for('web.doctor_dashboard', doctor_id=doctor_id))
        
@web.route('/doctor/<int:doctor_id>/reviews')
@login_required
def doctor_reviews(doctor_id):
    """Render the doctor reviews page."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get reviews for this doctor
        reviews = Review.query.filter_by(doctor_id=doctor.id).order_by(Review.created_at.desc()).all()
        
        return render_template('doctor_reviews.html', doctor=doctor, reviews=reviews)
    except Exception as e:
        logger.error(f"Error in doctor_reviews: {str(e)}")
        flash('An error occurred while loading reviews.', 'danger')
        return redirect(url_for('web.doctor_dashboard', doctor_id=doctor_id))
        
@web.route('/review/<int:review_id>/reply', methods=['POST'])
@login_required
def reply_review(review_id):
    """Reply to a review as a doctor."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Create form for CSRF validation
    form = ReviewReplyForm()
    
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            if is_ajax:
                return jsonify({'success': False, 'message': 'Unauthorized access. Only doctors can reply to reviews.'}), 403
            flash('Unauthorized access. Only doctors can reply to reviews.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the review
        review = Review.query.get_or_404(review_id)
        
        # Get the doctor profile
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Doctor profile not found.'}), 404
            flash('Doctor profile not found.', 'danger')
            return redirect(url_for('web.index'))
        
        # Check if this review is for this doctor
        if review.doctor_id != doctor.id:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Unauthorized access. You can only reply to your own reviews.'}), 403
            flash('Unauthorized access. You can only reply to your own reviews.', 'danger')
            return redirect(url_for('web.index'))
        
        # Validate form data if this is a regular (non-AJAX) request
        if not is_ajax and not form.validate_on_submit():
            flash('Invalid form submission. Please try again.', 'danger')
            return redirect(url_for('web.doctor_reviews', doctor_id=doctor.id))
            
        # Get the reply text from the form
        reply_text = request.form.get('reply_text')
        
        if not reply_text or len(reply_text.strip()) == 0:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Reply text cannot be empty.'}), 400
            flash('Reply text cannot be empty.', 'danger')
            return redirect(url_for('web.doctor_reviews', doctor_id=doctor.id))
        
        # Create the review reply
        reply = ReviewReply()
        reply.review_id = review.id
        reply.doctor_id = doctor.id
        reply.reply_text = reply_text
        db.session.add(reply)
        
        # Add a notification for the user if available
        if review.user_id:
            notification = Notification()
            notification.user_id = review.user_id
            notification.type = "Review Reply"
            notification.message = f"Dr. {doctor.name} replied to your review."
            notification.response_type = "review_reply"
            db.session.add(notification)
        
        db.session.commit()
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': 'Reply added successfully.',
                'reply': {
                    'id': reply.id,
                    'text': reply.reply_text,
                    'created_at': reply.created_at.strftime('%B %d, %Y at %H:%M'),
                    'doctor_name': doctor.name
                }
            })
        
        flash('Reply added successfully.', 'success')
        return redirect(url_for('web.doctor_reviews', doctor_id=doctor.id))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in reply_review: {str(e)}")
        
        if is_ajax:
            return jsonify({'success': False, 'message': 'An error occurred while adding your reply.'}), 500
        
        flash('An error occurred while adding your reply.', 'danger')
        return redirect(url_for('web.doctor_reviews', doctor_id=doctor_id))

# API Routes
@api.route('/ai-search', methods=['POST'])
def ai_search():
    """Handle AI-powered search queries and return recommendations."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({'success': False, 'message': 'Query is required'}), 400
        
        # Create fingerprint for tracking
        from personalization_system import PersonalizationEngine
        user_agent = request.headers.get('User-Agent', '')
        ip_address = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', '')
        accept_language = request.headers.get('Accept-Language', '')
        
        fingerprint = PersonalizationEngine.create_browser_fingerprint(
            user_agent, ip_address, accept_language
        )
        
        # Track AI search interaction
        PersonalizationEngine.track_user_interaction(
            fingerprint,
            'search',
            'ai_assistant',
            None,
            {'query': query, 'source': 'ai_search'}
        )
        
        # Simple keyword matching for procedures and categories
        recommendations = {
            'procedures': [],
            'packages': [],
            'categories': [],
            'face_analysis_suggested': False
        }
        
        # Keywords that suggest face analysis
        face_keywords = ['face', 'facial', 'nose', 'eyes', 'skin', 'wrinkles', 'aging', 'cheeks', 'chin', 'forehead']
        recommendations['face_analysis_suggested'] = any(keyword in query.lower() for keyword in face_keywords)
        
        # Search procedures
        procedures = db.session.execute(text("""
            SELECT p.*, c.name as category_name 
            FROM procedures p 
            JOIN categories c ON p.category_id = c.id
            WHERE LOWER(p.procedure_name) LIKE :query 
               OR LOWER(p.description) LIKE :query
               OR LOWER(c.name) LIKE :query
            LIMIT 5
        """), {'query': f'%{query.lower()}%'}).fetchall()
        
        for proc in procedures:
            # Track procedure search interaction to build user preferences
            PersonalizationEngine.track_user_interaction(
                fingerprint,
                'search',
                'procedure',
                proc.id,
                {'query': query, 'procedure_name': proc.procedure_name, 'source': 'search_results'}
            )
            
            recommendations['procedures'].append({
                'id': proc.id,
                'name': proc.procedure_name,
                'category': proc.category_name,
                'description': proc.description[:200] if proc.description else '',
                'min_cost': proc.min_cost,
                'max_cost': proc.max_cost
            })
        
        # Search packages
        packages = db.session.execute(text("""
            SELECT p.*, c.name as clinic_name, c.city as clinic_city
            FROM packages p 
            JOIN clinics c ON p.clinic_id = c.id
            WHERE (LOWER(p.name) LIKE :query 
                   OR LOWER(p.description) LIKE :query)
              AND p.is_active = true 
              AND c.is_approved = true
            LIMIT 3
        """), {'query': f'%{query.lower()}%'}).fetchall()
        
        for pkg in packages:
            recommendations['packages'].append({
                'id': pkg.id,
                'name': pkg.name,
                'clinic_name': pkg.clinic_name,
                'clinic_city': pkg.clinic_city,
                'base_price': pkg.base_price,
                'description': pkg.description[:200] if pkg.description else ''
            })
        
        # Search categories
        categories = db.session.execute(text("""
            SELECT * FROM categories 
            WHERE LOWER(name) LIKE :query 
               OR LOWER(description) LIKE :query
            LIMIT 3
        """), {'query': f'%{query.lower()}%'}).fetchall()
        
        for cat in categories:
            # Track category search interaction to build user preferences
            PersonalizationEngine.track_user_interaction(
                fingerprint,
                'search',
                'category',
                cat.id,
                {'query': query, 'category_name': cat.name, 'source': 'search_results'}
            )
            
            recommendations['categories'].append({
                'id': cat.id,
                'name': cat.name,
                'description': cat.description[:150] if cat.description else ''
            })
        
        return jsonify({
            'success': True,
            'query': query,
            'recommendations': recommendations
        })
        
    except Exception as e:
        logger.error(f"Error in AI search: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@api.route('/body-parts', methods=['GET'])
def get_body_parts():
    """Get all body parts."""
    try:
        body_parts = BodyPart.query.all()
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': bp.id,
                    'name': bp.name,
                    'description': bp.description,
                    'icon_url': bp.icon_url
                } for bp in body_parts
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting body parts: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching body parts'
        }), 500

@api.route('/body-parts/<int:body_part_id>', methods=['GET'])
def get_body_part(body_part_id):
    """Get a specific body part by ID."""
    try:
        body_part = BodyPart.query.get(body_part_id)
        if not body_part:
            return jsonify({
                'success': False,
                'message': 'Body part not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': {
                'id': body_part.id,
                'name': body_part.name,
                'description': body_part.description,
                'icon_url': body_part.icon_url
            }
        }), 200
    except Exception as e:
        logger.error(f"Error getting body part: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching the body part'
        }), 500

@api.route('/categories', methods=['GET'])
def get_categories():
    """Get all categories, optionally filtered by body part."""
    try:
        body_part_id = request.args.get('body_part_id', type=int)
        
        if body_part_id:
            categories = Category.query.filter_by(body_part_id=body_part_id).all()
        else:
            categories = Category.query.all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description,
                    'body_part_id': category.body_part_id,
                    'popularity_score': category.popularity_score
                } for category in categories
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting categories: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching categories'
        }), 500

@api.route('/procedures', methods=['GET'])
def get_procedures():
    """Get all procedures, optionally filtered by category."""
    try:
        category_id = request.args.get('category_id', type=int)
        
        if category_id:
            procedures = Procedure.query.filter_by(category_id=category_id).all()
        else:
            procedures = Procedure.query.all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': procedure.id,
                    'procedure_name': procedure.procedure_name,
                    'short_description': procedure.short_description,
                    'min_cost': procedure.min_cost,
                    'max_cost': procedure.max_cost,
                    'category_id': procedure.category_id,
                    'avg_rating': procedure.avg_rating,
                    'review_count': procedure.review_count
                } for procedure in procedures
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting procedures: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching procedures'
        }), 500

@api.route('/procedures/<int:procedure_id>', methods=['GET'])
def get_procedure(procedure_id):
    """Get a specific procedure by ID."""
    try:
        procedure = Procedure.query.get(procedure_id)
        if not procedure:
            return jsonify({
                'success': False,
                'message': 'Procedure not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': {
                'id': procedure.id,
                'procedure_name': procedure.procedure_name,
                'short_description': procedure.short_description,
                'overview': procedure.overview,
                'procedure_details': procedure.procedure_details,
                'ideal_candidates': procedure.ideal_candidates,
                'recovery_process': procedure.recovery_process,
                'recovery_time': procedure.recovery_time,
                'results_duration': procedure.results_duration,
                'min_cost': procedure.min_cost,
                'max_cost': procedure.max_cost,
                'benefits': procedure.benefits,
                'benefits_detailed': procedure.benefits_detailed,
                'risks': procedure.risks,
                'procedure_types': procedure.procedure_types,
                'alternative_procedures': procedure.alternative_procedures,
                'category_id': procedure.category_id,
                'avg_rating': procedure.avg_rating,
                'review_count': procedure.review_count,
                'category': {
                    'id': procedure.category.id,
                    'name': procedure.category.name
                } if procedure.category else None
            }
        }), 200
    except Exception as e:
        logger.error(f"Error getting procedure: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching the procedure'
        }), 500
        
@api.route('/procedures/<int:procedure_id>/recommendations', methods=['GET'])
def get_procedure_recommendations(procedure_id):
    """Get procedure recommendations based on category similarity."""
    try:
        procedure = Procedure.query.get(procedure_id)
        if not procedure:
            return jsonify({
                'success': False,
                'message': 'Procedure not found'
            }), 404
        
        # Get number of recommendations to return
        limit = request.args.get('limit', default=3, type=int)
        
        # Get recommendations based on same category
        recommended_procedures = []
        if procedure.category:
            recommended_procedures = Procedure.query.filter(
                Procedure.category_id == procedure.category_id,
                Procedure.id != procedure.id
            ).limit(limit).all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': p.id,
                    'procedure_name': p.procedure_name,
                    'short_description': p.short_description,
                    'body_part': getattr(p, 'body_part', ''),
                    'tags': getattr(p, 'tags', ''),
                    'category': {
                        'id': p.category.id,
                        'name': p.category.name
                    } if p.category else None,
                    'min_cost': p.min_cost,
                    'max_cost': p.max_cost,
                    'avg_rating': getattr(p, 'avg_rating', None),
                    'review_count': getattr(p, 'review_count', 0),
                    'body_area': getattr(p, 'body_area', ''),
                    'category_type': getattr(p, 'category_type', '')
                } for p in recommended_procedures
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting procedure recommendations: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching procedure recommendations'
        }), 500

@api.route('/doctors', methods=['GET'])
def get_doctors():
    """Get all doctors, optionally filtered by category or procedure."""
    try:
        category_id = request.args.get('category_id', type=int)
        procedure_id = request.args.get('procedure_id', type=int)
        
        if category_id:
            doctors = Doctor.query.join(DoctorCategory).filter(DoctorCategory.category_id == category_id).all()
        elif procedure_id:
            doctors = Doctor.query.join(DoctorProcedure).filter(DoctorProcedure.procedure_id == procedure_id).all()
        else:
            doctors = Doctor.query.all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': doctor.id,
                    'name': doctor.name,
                    'specialty': doctor.specialty,
                    'experience': doctor.experience,
                    'city': doctor.city,
                    'state': doctor.state,
                    'hospital': doctor.hospital,
                    'consultation_fee': doctor.consultation_fee,
                    'is_verified': doctor.is_verified,
                    'rating': doctor.rating,
                    'review_count': doctor.review_count
                } for doctor in doctors
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting doctors: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching doctors'
        }), 500

@api.route('/doctors/<int:doctor_id>', methods=['GET'])
def get_doctor(doctor_id):
    """Get a specific doctor by ID."""
    try:
        doctor = Doctor.query.get(doctor_id)
        if not doctor:
            return jsonify({
                'success': False,
                'message': 'Doctor not found'
            }), 404
        
        doctor_categories = DoctorCategory.query.filter_by(doctor_id=doctor_id).all()
        doctor_procedures = DoctorProcedure.query.filter_by(doctor_id=doctor_id).all()
        doctor_photos = DoctorPhoto.query.filter_by(doctor_id=doctor_id).all()
        
        return jsonify({
            'success': True,
            'data': {
                'id': doctor.id,
                'name': doctor.name,
                'specialty': doctor.specialty,
                'experience': doctor.experience,
                'city': doctor.city,
                'state': doctor.state,
                'hospital': doctor.hospital,
                'consultation_fee': doctor.consultation_fee,
                'is_verified': doctor.is_verified,
                'rating': doctor.rating,
                'review_count': doctor.review_count,
                'bio': doctor.bio,
                'certifications': doctor.certifications,
                'video_url': doctor.video_url,
                'success_stories': doctor.success_stories,
                'education': doctor.education,
                'categories': [
                    {
                        'id': dc.category.id,
                        'name': dc.category.name
                    } for dc in doctor_categories if dc.category
                ],
                'procedures': [
                    {
                        'id': dp.procedure.id,
                        'name': dp.procedure.procedure_name
                    } for dp in doctor_procedures if dp.procedure
                ],
                'photos': [
                    {
                        'id': photo.id,
                        'photo_url': photo.photo_url,
                        'description': photo.description
                    } for photo in doctor_photos
                ]
            }
        }), 200
    except Exception as e:
        logger.error(f"Error getting doctor: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching the doctor'
        }), 500

@api.route('/community', methods=['GET'])
def get_community_threads():
    """Get community threads, optionally filtered by category or procedure."""
    try:
        category_id = request.args.get('category_id', type=int)
        procedure_id = request.args.get('procedure_id', type=int)
        
        if category_id:
            threads = Community.query.filter_by(category_id=category_id).order_by(Community.created_at.desc()).all()
        elif procedure_id:
            threads = Community.query.filter_by(procedure_id=procedure_id).order_by(Community.created_at.desc()).all()
        else:
            threads = Community.query.order_by(Community.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': thread.id,
                    'title': thread.title,
                    'content': thread.content,
                    'is_anonymous': thread.is_anonymous,
                    'created_at': thread.created_at.isoformat() if thread.created_at else None,
                    'view_count': thread.view_count,
                    'reply_count': thread.reply_count,
                    'featured': thread.featured,
                    'tags': thread.tags,
                    'user': {
                        'id': thread.user.id,
                        'name': thread.user.name if not thread.is_anonymous else 'Anonymous'
                    } if thread.user else None,
                    'category': {
                        'id': thread.category.id,
                        'name': thread.category.name
                    } if thread.category else None,
                    'procedure': {
                        'id': thread.procedure.id,
                        'name': thread.procedure.procedure_name
                    } if thread.procedure else None
                } for thread in threads
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting community threads: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching community threads'
        }), 500

@api.route('/community/posts', methods=['GET'])
def get_community_posts():
    """Get community posts with sorting and pagination for the modern community page."""
    try:
        # Get parameters
        sort = request.args.get('sort', 'hot')
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Build base query - only get top-level posts (not replies)
        base_query = Community.query.filter(Community.parent_id.is_(None))
        
        # Apply sorting
        if sort == 'hot':
            # Sort by combination of upvotes and recency
            posts = base_query.order_by(
                (Community.upvotes + Community.view_count).desc(),
                Community.created_at.desc()
            ).limit(limit).offset((page - 1) * limit).all()
        elif sort == 'new':
            posts = base_query.order_by(Community.created_at.desc()).limit(limit).offset((page - 1) * limit).all()
        elif sort == 'top':
            posts = base_query.order_by(Community.upvotes.desc()).limit(limit).offset((page - 1) * limit).all()
        elif sort == 'imported':
            posts = base_query.filter(Community.source_type == 'reddit').order_by(Community.created_at.desc()).limit(limit).offset((page - 1) * limit).all()
        elif sort == 'professional':
            posts = base_query.filter(Community.is_professional_verified == True).order_by(Community.created_at.desc()).limit(limit).offset((page - 1) * limit).all()
        else:
            posts = base_query.order_by(Community.created_at.desc()).limit(limit).offset((page - 1) * limit).all()
        
        # Get reply count for each post
        for post in posts:
            post.reply_count = db.session.query(Community).filter(Community.parent_id == post.id).count()
        
        return jsonify({
            'success': True,
            'posts': [
                {
                    'id': post.id,
                    'title': post.title,
                    'content': post.content,
                    'is_anonymous': post.is_anonymous,
                    'created_at': post.created_at.isoformat() if post.created_at else None,
                    'view_count': post.view_count or 0,
                    'upvotes': post.upvotes or 0,
                    'reply_count': post.reply_count or 0,
                    'featured': post.featured,
                    'tags': post.tags,
                    'source_type': getattr(post, 'source_type', None),
                    'source_url': getattr(post, 'source_url', None),
                    'is_professional_verified': getattr(post, 'is_professional_verified', False),
                    'user': {
                        'id': post.user.id,
                        'username': post.user.username if not post.is_anonymous else 'Anonymous',
                        'name': post.user.name if not post.is_anonymous else 'Anonymous'
                    } if post.user else {'id': 0, 'username': 'Anonymous', 'name': 'Anonymous'},
                    'category': {
                        'id': post.category.id,
                        'name': post.category.name
                    } if post.category else None,
                    'procedure': {
                        'id': post.procedure.id,
                        'name': post.procedure.procedure_name
                    } if post.procedure else None
                } for post in posts
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting community posts: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching community posts'
        }), 500

@api.route('/community/<int:thread_id>/replies', methods=['GET'])
def get_community_replies(thread_id):
    """Get replies for a specific community thread."""
    try:
        thread = Community.query.get(thread_id)
        if not thread:
            return jsonify({
                'success': False,
                'message': 'Community thread not found'
            }), 404
        
        replies = CommunityReply.query.filter_by(thread_id=thread_id).order_by(CommunityReply.created_at.asc()).all()
        
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': reply.id,
                    'content': reply.content,
                    'is_anonymous': reply.is_anonymous,
                    'is_doctor_response': reply.is_doctor_response,
                    'created_at': reply.created_at.isoformat() if reply.created_at else None,
                    'upvotes': reply.upvotes,
                    'user': {
                        'id': reply.user.id,
                        'name': reply.user.username if not reply.is_anonymous else 'Anonymous',
                        'is_doctor': reply.user.role == 'doctor' if reply.user else False
                    } if reply.user else None
                } for reply in replies
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting community replies: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching community replies'
        }), 500

# Web Routes
# GlowUp demo route removed

@web.route('/health')
def health_check():
    """Simple health check endpoint that returns 200 quickly."""
    return jsonify({"status": "healthy", "service": "antidote"}), 200

@web.route('/')
def index():
    """Optimized homepage with single database query for faster loading."""
    try:
        # Quick health check parameter - if requested, return simple response
        if request.args.get('health') == 'true':
            return jsonify({"status": "healthy", "service": "antidote"}), 200
        
        # Import the critical performance optimizer
        from critical_performance_fix import get_cached_homepage_data, get_cached_packages_data
        
        # Get all homepage data with single optimized query (cached for 5 minutes)
        homepage_data = get_cached_homepage_data()
        procedure_categories = homepage_data.get('categories', [])
        popular_procedures = homepage_data.get('procedures', [])
        recent_threads = homepage_data.get('threads', [])
        top_doctors = homepage_data.get('doctors', [])
        
        # Get packages data with optimized query
        packages_data = get_cached_packages_data()
        affordable_packages = packages_data.get('affordable', [])
        high_review_packages = packages_data.get('high_review', [])
        
        # Get clinics with 1000+ reviews (using a quick additional query)
        try:
            verified_clinics = db.session.execute(text("""
                SELECT c.id, c.name, c.city, c.state, c.google_rating, c.google_review_count, c.description, c.slug,
                       (SELECT COUNT(*) FROM packages WHERE clinic_id = c.id AND is_active = true) as package_count
                FROM clinics c 
                WHERE c.is_approved = true AND c.google_review_count >= 1000
                ORDER BY c.google_review_count DESC, c.google_rating DESC
                LIMIT 20
            """)).fetchall()
            verified_clinics = [dict(row._mapping) for row in verified_clinics] if verified_clinics else []
        except Exception as e:
            logger.error(f"Error loading clinics data: {str(e)}")
            verified_clinics = []
        
        # Set safe defaults for other data
        popular_body_parts = []
        all_procedures = popular_procedures  # Use same data to avoid extra query
        
        # Quick personalization (minimal overhead)
        fingerprint = None
        try:
            from personalization_system import PersonalizationEngine
            user_agent = request.headers.get('User-Agent', '')
            ip_address = request.remote_addr or ''
            fingerprint = PersonalizationEngine.create_browser_fingerprint(user_agent, ip_address, '')
        except:
            fingerprint = None
        
        # Get hero banner data for instant loading (server-side preload)
        hero_banner_data = None
        try:
            from banner_cache import banner_cache
            hero_banner_data = banner_cache.get_hero_banner_data()
        except Exception as e:
            logger.error(f"Error preloading hero banner: {str(e)}")
            hero_banner_data = None
        
        # Render with optimized data including packages, clinics, and preloaded banner
        return render_template(
            'index.html',
            popular_body_parts=popular_body_parts,
            popular_procedures=popular_procedures,
            top_doctors=top_doctors,
            recent_threads=recent_threads,
            procedure_categories=procedure_categories,
            all_procedures=all_procedures,
            featured_packages=[],
            affordable_packages=affordable_packages,
            high_review_packages=high_review_packages,
            verified_clinics=verified_clinics,
            recent_activity=[],
            ai_recommendations=None,
            is_returning_user=False,
            user_summary={},
            fingerprint=fingerprint,
            hero_banner_data=hero_banner_data  # Preloaded banner data for instant loading
        )
    
    except Exception as e:
        logger.error(f"Error in optimized homepage: {str(e)}")
        # Fallback to safe empty data
        return render_template('index.html', 
            popular_body_parts=[],
            popular_procedures=[],
            top_doctors=[],
            recent_threads=[],
            procedure_categories=[],
            all_procedures=[],
            featured_packages=[],
            affordable_packages=[],
            high_review_packages=[],
            verified_clinics=[],
            recent_activity=[],
            ai_recommendations=None,
            is_returning_user=False,
            user_summary={},
            fingerprint=None
        )

@web.route('/test-performance')
def test_performance():
    """Test route that uses the regular homepage with optimized CSS bundles."""
    # Simply redirect to homepage with optimization flag
    return redirect(url_for('web.index', optimized='true'))

@web.route('/modern')
def modern_index():
    """Render the ultra-modern home page design."""
    # Default empty values
    popular_body_parts = []
    popular_procedures = []
    procedure_categories = []
    recent_threads = []
    top_doctors = []
    
    # Try to get body parts
    try:
        popular_body_parts = BodyPart.query.limit(4).all()
    except Exception as e:
        logger.error(f"Error querying body parts: {str(e)}")
    
    # Try to get procedures
    try:
        popular_procedures = Procedure.query.order_by(Procedure.popularity_score.desc()).limit(6).all()
    except Exception as e:
        logger.error(f"Error querying procedures: {str(e)}")
    
    # Try to get categories
    try:
        procedure_categories = Category.query.limit(6).all()
        if procedure_categories is None:
            procedure_categories = []
        # Ensure we always have a list, never None
        if not isinstance(procedure_categories, list):
            procedure_categories = list(procedure_categories) if procedure_categories else []
    except Exception as e:
        logger.error(f"Error querying categories: {str(e)}")
        procedure_categories = []
    
    # Try to get threads
    try:
        recent_threads = Thread.query.order_by(Thread.created_at.desc()).limit(3).all()
    except Exception as e:
        logger.error(f"Error querying threads: {str(e)}")
    
    # Try to get doctors - sorted by experience (most experienced first)
    try:
        top_doctors = Doctor.query.order_by(Doctor.experience.desc().nulls_last()).limit(9).all()
    except Exception as e:
        logger.error(f"Error querying doctors: {str(e)}")
    
    # Log what we're displaying
    logger.info(f"Modern index page showing: {len(popular_procedures)} procedures, {len(recent_threads)} threads, {len(top_doctors)} doctors, {len(procedure_categories)} categories")
    
    try:
        return render_template(
            'ultra-index.html',
            procedures=popular_procedures,
            doctors=top_doctors,
            threads=recent_threads,
            body_parts=popular_body_parts,
            procedure_categories=procedure_categories
        )
    except Exception as e:
        logger.error(f"Error rendering modern index page: {str(e)}")
        return render_template('ultra-index.html', 
            error=str(e),
            procedures=[],
            doctors=[],
            threads=[],
            body_parts=[],
            procedure_categories=[]
        )

@web.route('/body-parts')
def body_parts():
    """Render the body parts page."""
    try:
        body_parts = BodyPart.query.all()
        return render_template('body_parts.html', body_parts=body_parts)
    except Exception as e:
        logger.error(f"Error rendering body parts page: {str(e)}")
        return render_template('body_parts.html', error=str(e))

@web.route('/categories')
def categories():
    """Render the categories page, optionally filtered by body part."""
    try:
        body_part_id = request.args.get('body_part_id', type=int)
        
        if body_part_id:
            body_part = BodyPart.query.get(body_part_id)
            categories = Category.query.filter_by(body_part_id=body_part_id).all()
            return render_template('categories.html', categories=categories, body_part=body_part)
        else:
            categories = Category.query.all()
            return render_template('categories.html', categories=categories)
    except Exception as e:
        logger.error(f"Error rendering categories page: {str(e)}")
        return render_template('categories.html', error=str(e))

@web.route('/autocomplete')
def autocomplete():
    """
    Provide autocomplete suggestions for the search bar based on the active tab.
    
    Returns JSON data with procedure, doctor, thread, or package suggestions that match the query.
    
    Query parameters:
    - q: Search query (required)
    - type: Search type ('doctors', 'procedures', 'discussions', 'packages', or blank for all)
    """
    try:
        query = request.args.get('q', '')
        search_type = request.args.get('type', '')
        
        # Only process if query is at least 2 characters
        if len(query) < 2:
            return jsonify([])
        
        suggestions = []
        
        # Search for procedures
        if not search_type or search_type in ['doctors', 'procedures']:
            procedure_limit = 8 if search_type == 'procedures' else 3
            
            procedures = Procedure.query.filter(
                Procedure.procedure_name.ilike(f"%{query}%")
            ).order_by(
                # Prioritize exact matches, then alphabetical
                db.case((Procedure.procedure_name.ilike(f"{query}"), 0), else_=1),
                Procedure.procedure_name
            ).limit(procedure_limit).all()
            
            # Add procedures to suggestions
            for procedure in procedures:
                category_name = procedure.category.name if procedure.category else "Procedure"
                procedure_type = "Surgical" if procedure.procedure_types and "surgical" in procedure.procedure_types.lower() else "Non-Surgical"
                
                suggestions.append({
                    'id': procedure.id,
                    'text': procedure.procedure_name,
                    'display': f"{procedure.procedure_name} [Procedure]",
                    'category': 'Procedure',
                    'url': url_for('web.procedure_detail', procedure_id=procedure.id),
                    'type': procedure_type,
                    'body_part': procedure.body_part
                })
        
        # Search for doctors (only if in doctors tab or no specific tab)
        if not search_type or search_type == 'doctors':
            doctor_limit = 5 if search_type == 'doctors' else 2
            
            doctors = Doctor.query.filter(
                (Doctor.name.ilike(f"%{query}%")) |
                (Doctor.specialty.ilike(f"%{query}%"))
            ).order_by(
                # Prioritize exact matches in name, then specialty
                db.case((Doctor.name.ilike(f"{query}"), 0), else_=1),
                Doctor.name
            ).limit(doctor_limit).all()
            
            # Add doctors to suggestions
            for doctor in doctors:
                location = f"{doctor.city}{', ' + doctor.state if doctor.state else ''}"
                display_text = f"Dr. {doctor.name} – {doctor.specialty}"
                if location:
                    display_text += f", {location}"
                    
                suggestions.append({
                    'id': doctor.id,
                    'text': f"Dr. {doctor.name}",
                    'display': f"{display_text} [Doctor]",
                    'category': 'Doctor',
                    'url': url_for('web.doctor_detail', doctor_id=doctor.id),
                    'specialty': doctor.specialty,
                    'location': location
                })
        
        # Search for community threads (only if in discussions tab or no specific tab)
        if not search_type or search_type == 'discussions':
            thread_limit = 8 if search_type == 'discussions' else 2
            
            # Search in both Thread and Community models for comprehensive results
            threads = Thread.query.filter(
                Thread.title.ilike(f"%{query}%") | 
                Thread.content.ilike(f"%{query}%")
            ).order_by(
                # Prioritize exact matches, then newest
                db.case((Thread.title.ilike(f"{query}"), 0), else_=1),
                Thread.created_at.desc()
            ).limit(thread_limit).all()
            
            # Add threads to suggestions with enhanced information
            for thread in threads:
                # Get a brief content preview (first 100 characters)
                content_preview = thread.content[:100] + "..." if thread.content and len(thread.content) > 100 else thread.content
                
                # Count replies for this thread
                try:
                    # Use direct SQL count for thread replies
                    reply_count = db.session.execute(text(f"SELECT COUNT(*) FROM replies WHERE thread_id = {thread.id}")).scalar() or 0
                except Exception as e:
                    logger.error(f"Error counting replies: {str(e)}")
                    reply_count = 0
                
                suggestions.append({
                    'id': thread.id,
                    'text': thread.title,
                    'display': f"{thread.title} [Community Thread]",
                    'category': 'Thread',
                    'url': url_for('web.community_thread_detail', thread_id=thread.id),
                    'date': thread.created_at.strftime('%b %d, %Y') if thread.created_at else '',
                    'content_preview': content_preview,
                    'reply_count': reply_count,
                    'is_enhanced': True
                })
            
            # Also search in Community model if needed
            if thread_limit > len(threads):
                remaining_limit = thread_limit - len(threads)
                
                community_threads = Community.query.filter(
                    Community.title.ilike(f"%{query}%") | 
                    Community.content.ilike(f"%{query}%")
                ).order_by(
                    db.case((Community.title.ilike(f"{query}"), 0), else_=1),
                    Community.created_at.desc()
                ).limit(remaining_limit).all()
                
                for thread in community_threads:
                    # Check if we already have this thread (avoid duplicates)
                    if not any(s.get('id') == thread.id and s.get('category') == 'Thread' for s in suggestions):
                        # Get a brief content preview (first 100 characters)
                        content_preview = thread.content[:100] + "..." if thread.content and len(thread.content) > 100 else thread.content
                        
                        # Count replies for this thread
                        try:
                            # Use direct SQL count for community replies
                            reply_count = db.session.execute(text(f"SELECT COUNT(*) FROM community WHERE parent_id = {thread.id}")).scalar() or 0
                        except Exception as e:
                            logger.error(f"Error counting community replies: {str(e)}")
                            reply_count = 0
                        
                        suggestions.append({
                            'id': thread.id,
                            'text': thread.title,
                            'display': f"{thread.title} [Community Thread]",
                            'category': 'Thread',
                            'url': url_for('web.community_thread_detail', thread_id=thread.id),
                            'date': thread.created_at.strftime('%b %d, %Y') if thread.created_at else '',
                            'content_preview': content_preview,
                            'reply_count': reply_count,
                            'is_enhanced': True
                        })
        
        # Search for packages (only if in packages tab or no specific tab)
        if not search_type or search_type == 'packages':
            try:
                from models import Package, Clinic
                package_limit = 8 if search_type == 'packages' else 3
                
                # Search for packages
                packages = db.session.query(Package).join(Clinic).filter(
                    Package.is_active == True,
                    Clinic.is_approved == True,
                    db.or_(
                        Package.title.ilike(f"%{query}%"),
                        Package.description.ilike(f"%{query}%"),
                        Package.category.ilike(f"%{query}%")
                    )
                ).order_by(
                    # Prioritize exact matches in title, then alphabetical
                    db.case((Package.title.ilike(f"{query}"), 0), else_=1),
                    Package.title
                ).limit(package_limit).all()
                
                # Add packages to suggestions
                for package in packages:
                    clinic_name = package.clinic.name if package.clinic else "Unknown Clinic"
                    clinic_city = package.clinic.city if package.clinic else ""
                    
                    # Format price display
                    price_actual = getattr(package, 'price_actual', None)
                    price_discounted = getattr(package, 'price_discounted', None)
                    
                    if price_discounted and price_actual and price_discounted < price_actual:
                        price_display = f"₹{price_discounted:,.0f}"
                    elif price_actual:
                        price_display = f"₹{price_actual:,.0f}"
                    else:
                        price_display = "Contact for price"
                    
                    suggestions.append({
                        'id': package.id,
                        'text': package.title,
                        'display': f"{package.title} - {clinic_name} [Package]",
                        'category': 'Package',
                        'url': url_for('enhanced_package.package_detail', package_id=package.id),
                        'clinic_name': clinic_name,
                        'clinic_city': clinic_city,
                        'price': price_display,
                        'package_category': getattr(package, 'category', None) or 'General'
                    })
            except Exception as e:
                logger.error(f"Error searching packages in autocomplete: {str(e)}")
        
        # Sort suggestions by relevance within their category
        if search_type == 'doctors':
            # For doctors tab, prioritize procedures (which users will search for)
            suggestions.sort(key=lambda x: (
                0 if x['category'] == 'Procedure' else 1,
                0 if x['text'].lower() == query.lower() else 1
            ))
        elif search_type == 'procedures':
            # For procedures tab, only show procedures
            pass  # Already filtered above
        elif search_type == 'discussions':
            # For discussions tab, only show threads
            pass  # Already filtered above
        elif search_type == 'packages':
            # For packages tab, only show packages
            pass  # Already filtered above
        else:
            # Default sorting for combined results
            suggestions.sort(key=lambda x: (
                0 if x['text'].lower() == query.lower() else 1,  # Exact matches first
                # Then prioritize by category
                0 if x['category'] == 'Procedure' else (1 if x['category'] == 'Doctor' else 2)
            ))
        
        # Limit to 8 suggestions total
        suggestions = suggestions[:8]
        
        logger.info(f"Autocomplete for '{query}' (type: {search_type}) found: {len(suggestions)} suggestions")
        
        return jsonify(suggestions)
        
    except Exception as e:
        logger.error(f"Error in autocomplete: {str(e)}")
        return jsonify([])



@web.route('/search')
def search():
    """
    Global search functionality for procedures, doctors, and community threads.
    
    Query parameters:
    - q: Search query (required)
    - type: Type of search (doctors, procedures, threads)
    - location: City/location for doctor search
    """
    try:
        query = request.args.get('q')
        search_type = request.args.get('type')
        location = request.args.get('location')
        
        if not query:
            flash('Please enter a search term', 'warning')
            return redirect(url_for('web.index'))
        
        # Default to searching all types if not specified
        if search_type not in ['doctors', 'procedures', 'threads', 'packages']:
            search_type = None
            
        # Initialize results containers
        procedures = []
        doctors = []
        threads = []
        packages = []
        
        # Search for procedures if requested or searching all
        if not search_type or search_type == 'procedures':
            procedures = Procedure.query.filter(
                Procedure.procedure_name.ilike(f"%{query}%") | 
                Procedure.short_description.ilike(f"%{query}%") |
                Procedure.overview.ilike(f"%{query}%") |
                Procedure.procedure_details.ilike(f"%{query}%") |
                Procedure.body_part.ilike(f"%{query}%")
            ).limit(20).all()
        
        # Search for doctors if requested or searching all
        if not search_type or search_type == 'doctors':
            # For doctor searches with procedure names like "Rhinoplasty", we need to handle it differently
            # We'll first check if the query matches any procedure name
            procedure = Procedure.query.filter(
                Procedure.procedure_name.ilike(f"%{query}%")
            ).first()
            
            if procedure and search_type == 'doctors':
                # If it's a procedure, get all doctors (since they are all plastic surgeons)
                # and only filter by location if provided
                if location and location.strip():
                    doctors = Doctor.query.filter(
                        Doctor.city.ilike(f"%{location.strip()}%")
                    ).limit(20).all()
                else:
                    doctors = Doctor.query.limit(20).all()
            else:
                # If not a procedure name or searching all types, use regular search
                # Start with the base query
                doctor_query = Doctor.query.filter(
                    Doctor.name.ilike(f"%{query}%") | 
                    Doctor.specialty.ilike(f"%{query}%") |
                    Doctor.bio.ilike(f"%{query}%")
                )
                
                # Add location filter if provided
                if location and location.strip():
                    doctor_query = doctor_query.filter(Doctor.city.ilike(f"%{location.strip()}%"))
                
                # Get the results
                doctors = doctor_query.limit(20).all()
                
                # If no results, try to find all doctors who perform that procedure
                if search_type == 'doctors' and not doctors:
                    # Try to find procedure by name again (for safety)
                    if not procedure:
                        procedure = Procedure.query.filter(
                            Procedure.procedure_name.ilike(f"%{query}%")
                        ).first()
                    
                    if procedure:
                        # Find doctors filtered by location if provided
                        if location and location.strip():
                            doctors = Doctor.query.filter(
                                Doctor.city.ilike(f"%{location.strip()}%")
                            ).limit(20).all()
                        else:
                            doctors = Doctor.query.limit(20).all()
        
        # Search for community threads if requested or searching all
        if not search_type or search_type == 'threads':
            # First search the Thread model
            threads = Thread.query.filter(
                Thread.title.ilike(f"%{query}%") | 
                Thread.content.ilike(f"%{query}%") |
                Thread.keywords.cast(db.String).ilike(f"%{query}%")
            ).limit(10).all()
            
            # If we don't have enough threads or specifically searching for threads, also search Community model
            if len(threads) < 10 or search_type == 'threads':
                # Also search in Community model for more discussion threads
                community_threads = Community.query.filter(
                    Community.title.ilike(f"%{query}%") | 
                    Community.content.ilike(f"%{query}%") |
                    Community.tags.cast(db.String).ilike(f"%{query}%")
                ).filter(
                    Community.parent_id.is_(None)  # Only get top-level threads, not replies
                ).limit(20 - len(threads)).all()
                
                # Add community threads to the results
                # Add reply count for each thread for proper display
                for thread in community_threads:
                    try:
                        # Calculate reply count for each community thread
                        reply_count = db.session.query(Community).filter(
                            Community.parent_id == thread.id
                        ).count()
                        
                        # Set the reply_count attribute dynamically
                        thread.reply_count = reply_count
                    except Exception as e:
                        logger.error(f"Error counting replies for thread {thread.id}: {str(e)}")
                        thread.reply_count = 0
                
                threads.extend(community_threads)
        
        # Handle specific search types - redirect to their respective main pages with search parameters
        if search_type == 'packages':
            # Redirect to the enhanced packages page with search parameters
            from urllib.parse import urlencode
            params = {
                'search': query,
                'location': location or '',
                'category': '',
                'min_price': '',
                'max_price': '',
                'sort': 'newest'
            }
            return redirect(url_for('enhanced_package.package_directory') + '?' + urlencode(params))
        
        elif search_type == 'doctors':
            # Redirect to doctors page with search parameters
            from urllib.parse import urlencode
            params = {
                'search': query,
                'location': location or '',
                'specialty': '',
                'rating': '',
                'sort': 'rating'
            }
            return redirect(url_for('web.doctors') + '?' + urlencode(params))
        
        elif search_type == 'procedures':
            # Redirect to procedures page with search parameters
            from urllib.parse import urlencode
            params = {
                'search': query,
                'category': '',
                'body_part': '',
                'sort': 'popular'
            }
            return redirect(url_for('web.procedures') + '?' + urlencode(params))
        
        elif search_type == 'threads':
            # Redirect to community page with search parameters
            from urllib.parse import urlencode
            params = {
                'search': query,
                'category': '',
                'sort': 'latest'
            }
            return redirect(url_for('web.community') + '?' + urlencode(params))
        
        # Search for packages if searching all types (not specific packages search)
        if not search_type:
            try:
                from models import Package, Clinic
                # Build the package search query
                package_query = db.session.query(Package).join(Clinic).filter(
                    Package.is_active == True,
                    Clinic.is_approved == True,
                    db.or_(
                        Package.title.ilike(f"%{query}%"),
                        Package.description.ilike(f"%{query}%"),
                        Package.category.ilike(f"%{query}%")
                    )
                )
                
                # Add location filter if provided
                if location and location.strip():
                    package_query = package_query.filter(
                        Clinic.city.ilike(f"%{location.strip()}%")
                    )
                
                packages = package_query.limit(20).all()
                
                # Add clinic information to each package
                for package in packages:
                    if not hasattr(package, 'clinic'):
                        package.clinic = Clinic.query.get(package.clinic_id)
                
            except Exception as e:
                logger.error(f"Error searching packages: {str(e)}")
                packages = []
        else:
            packages = []
        
        # Search for clinics if searching all types (not specific clinic search)
        if not search_type:
            try:
                from models import Clinic
                # Build the clinic search query
                clinic_query = Clinic.query.filter(
                    Clinic.is_approved == True,
                    db.or_(
                        Clinic.name.ilike(f"%{query}%"),
                        Clinic.description.ilike(f"%{query}%"),
                        Clinic.area.ilike(f"%{query}%"),
                        Clinic.city.ilike(f"%{query}%")
                    )
                )
                
                # Add location filter if provided
                if location and location.strip():
                    clinic_query = clinic_query.filter(
                        Clinic.city.ilike(f"%{location.strip()}%")
                    )
                
                clinics = clinic_query.limit(20).all()
                
            except Exception as e:
                logger.error(f"Error searching clinics: {str(e)}")
                clinics = []
        else:
            clinics = []
        
        # Log search results
        logger.info(f"Search for '{query}' found: {len(procedures)} procedures, {len(doctors)} doctors, {len(threads)} threads, {len(packages)} packages, {len(clinics)} clinics")
        
        # Ensure all variables are properly defined
        query = query or ""
        location = location or ""
        search_type = search_type or ""
        procedures = procedures if 'procedures' in locals() else []
        doctors = doctors if 'doctors' in locals() else []
        threads = threads if 'threads' in locals() else []
        packages = packages if 'packages' in locals() else []
        clinics = clinics if 'clinics' in locals() else []
        
        return render_template(
            'search_results.html', 
            query=query,
            location=location,
            search_type=search_type,
            procedures=procedures, 
            doctors=doctors, 
            threads=threads,
            packages=packages,
            clinics=clinics
        )
    except Exception as e:
        logger.error(f"Error performing search: {str(e)}")
        logger.error(f"Search query: '{query}', location: '{location}', type: '{search_type}'")
        # Instead of redirecting to index, still render the search results template but with an error message
        flash(f"An error occurred while searching. Please try again.", 'warning')
        return render_template(
            'search_results.html', 
            query=query,
            location=location,
            search_type=search_type,
            procedures=[], 
            doctors=[], 
            threads=[],
            packages=[],
            clinics=[]
        )

@web.route('/procedures')
def procedures():
    """Render the procedures page, optionally filtered by category, search, and body part."""
    try:
        category_id = request.args.get('category_id', type=int)
        search_query = request.args.get('search', '').strip()
        body_part = request.args.get('body_part', '').strip()
        sort_by = request.args.get('sort', 'popular')
        
        # Pagination parameters for "Show More" functionality
        limit = 20  # Show 20 procedures initially
        
        # Base query
        base_query = Procedure.query
        title = "All Procedures"
        
        # Apply search filters
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    Procedure.procedure_name.ilike(f"%{search_query}%"),
                    Procedure.short_description.ilike(f"%{search_query}%"),
                    Procedure.overview.ilike(f"%{search_query}%"),
                    Procedure.body_part.ilike(f"%{search_query}%")
                )
            )
            title = f"Search results for '{search_query}'"
            
        if body_part:
            base_query = base_query.filter(Procedure.body_part.ilike(f"%{body_part}%"))
            if title == "All Procedures":
                title = f"Procedures for {body_part}"
            else:
                title += f" for {body_part}"
        
        if category_id:
            category = Category.query.get(category_id)
            if category:
                base_query = base_query.filter_by(category_id=category_id)
                title = f"Procedures in {category.name}"
                # Apply sorting and limit for category view too
                if sort_by == 'name':
                    procedures = base_query.order_by(Procedure.procedure_name.asc()).limit(limit).all()
                elif sort_by == 'popular':
                    procedures = base_query.order_by(Procedure.id.desc()).limit(limit).all()
                else:
                    procedures = base_query.limit(limit).all()
                
                # Get total count for show more functionality
                total_count = base_query.count()
                
                return render_template('procedures.html', 
                                     procedures=procedures, 
                                     category=category, 
                                     title=title,
                                     total_count=total_count,
                                     showing_count=len(procedures),
                                     has_more=total_count > limit)
        
        # Apply sorting and limit
        if sort_by == 'name':
            base_query = base_query.order_by(Procedure.procedure_name.asc())
        elif sort_by == 'popular':
            # Sort by a popularity metric - you can adjust this based on your data
            base_query = base_query.order_by(Procedure.id.desc())  # Most recent as proxy for popular
        
        # Get total count before applying limit
        total_count = base_query.count()
        
        # Apply limit for initial load
        procedures = base_query.limit(limit).all()
            
        return render_template('procedures.html', 
                             procedures=procedures, 
                             title=title,
                             total_count=total_count,
                             showing_count=len(procedures),
                             has_more=total_count > limit)
    except Exception as e:
        logger.error(f"Error rendering procedures page: {str(e)}")
        return render_template('procedures.html', error=str(e))



@web.route('/community')
def community():
    """Render the community interface with search support."""
    try:
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', '').strip()
        sort_by = request.args.get('sort', 'latest')
        
        # Base query for threads
        base_query = Community.query.filter(Community.parent_id.is_(None))  # Only top-level threads
        
        # Apply search filters
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    Community.title.ilike(f"%{search_query}%"),
                    Community.content.ilike(f"%{search_query}%"),
                    Community.tags.cast(db.String).ilike(f"%{search_query}%")
                )
            )
            
        if category_filter:
            try:
                category_id = int(category_filter)
                base_query = base_query.filter(Community.category_id == category_id)
            except ValueError:
                # If not an ID, try to find category by name
                category = Category.query.filter(Category.name.ilike(f"%{category_filter}%")).first()
                if category:
                    base_query = base_query.filter(Community.category_id == category.id)
        
        # Apply sorting
        if sort_by == 'latest':
            threads = base_query.order_by(Community.created_at.desc()).limit(50).all()
        elif sort_by == 'popular':
            threads = base_query.order_by(Community.upvotes.desc()).limit(50).all()
        elif sort_by == 'oldest':
            threads = base_query.order_by(Community.created_at.asc()).limit(50).all()
        else:
            threads = base_query.order_by(Community.created_at.desc()).limit(50).all()
        
        # Add reply count for each thread
        for thread in threads:
            try:
                reply_count = db.session.query(Community).filter(
                    Community.parent_id == thread.id
                ).count()
                thread.reply_count = reply_count
            except Exception as e:
                logger.error(f"Error counting replies for thread {thread.id}: {str(e)}")
                thread.reply_count = 0
        
        # Get categories for filter dropdown
        categories = Category.query.all()
        
        return render_template('community_modern.html', 
                             threads=threads, 
                             categories=categories,
                             search_query=search_query,
                             category_filter=category_filter,
                             sort_by=sort_by)
    except Exception as e:
        logger.error(f"Error rendering community page: {str(e)}")
        return render_template('community_modern.html', threads=[], categories=[])

@web.route('/community/legacy')
def community_legacy():
    """Enhanced community page with all posts (legacy version)."""
    try:
        # Get all community posts with user data
        threads = db.session.query(Community).join(User, Community.user_id == User.id).order_by(Community.created_at.desc()).all()
        
        # Get categories and procedures for filters
        categories = Category.query.order_by(Category.name).all()
        procedures = Procedure.query.order_by(Procedure.procedure_name).limit(50).all()
        
        # Get current user
        current_user = None
        if 'user_id' in session:
            current_user = User.query.get(session['user_id'])
        
        # Get user saves and follows if logged in
        user_saves = set()
        user_follows = set()
        if current_user:
            # Note: These tables may not exist yet, so we'll use empty sets for now
            user_saves = set()
            user_follows = set()
        
        logger.info(f"Community page loaded with {len(threads)} threads")
        
        return render_template('community_enhanced/index.html',
                             threads=threads,
                             pagination=None,
                             categories=categories,
                             procedures=procedures,
                             current_sort='newest',
                             current_category=None,
                             search_query='',
                             filter_type='all',
                             user_saves=user_saves,
                             user_follows=user_follows,
                             trending_tags=[],
                             current_user=current_user)
    except Exception as e:
        logger.error(f"Error loading community page: {e}")
        # Fallback to simple template
        return render_template('community_enhanced/index.html',
                             threads=[],
                             pagination=None,
                             categories=[],
                             procedures=[],
                             current_sort='newest',
                             current_category=None,
                             search_query='',
                             filter_type='all',
                             user_saves=set(),
                             user_follows=set(),
                             trending_tags=[],
                             current_user=None)

@web.route('/community/post/<int:thread_id>')
def community_post_redirect(thread_id):
    """Redirect old post URLs to thread URLs for compatibility."""
    return redirect(url_for('web.community_thread_detail', thread_id=thread_id))

@web.route('/community/thread/<int:thread_id>')
def community_thread_detail(thread_id):
    """Render the detailed community thread page with nested replies."""
    try:
        # Get the thread
        thread = Community.query.get_or_404(thread_id)
        
        # Safely handle user data
        if thread.user_id:
            thread.user = User.query.get(thread.user_id)
        else:
            thread.user = None
        
        # Get category and procedure if they exist
        if thread.category_id:
            thread.category = Category.query.get(thread.category_id)
        if thread.procedure_id:
            thread.procedure = Procedure.query.get(thread.procedure_id)
        
        # Create media directory if it doesn't exist
        media_dir = os.path.join(os.getcwd(), 'static', 'media')
        if not os.path.exists(media_dir):
            os.makedirs(media_dir, exist_ok=True)
            logger.info(f"Created media directory at {media_dir}")
        
        # Increment view count
        thread.view_count += 1
        
        # Update reply count with an accurate value
        thread.reply_count = count_all_replies(thread.id)
        db.session.commit()
        
        # Get sort parameter (default: oldest first for thread details)
        sort = request.args.get('sort', 'oldest')
        
        # Log for debugging
        logger.debug(f"Displaying thread {thread_id} with sort order: {sort}")
        
        # Get all replies for this thread from the community table
        replies = Community.query.filter_by(parent_id=thread_id).all()
        logger.debug(f"Found {len(replies)} total replies for thread {thread_id}")
        
        # Process replies and attach user data
        top_level_replies = []
        
        # For each reply, safely attach its user data
        for reply in replies:
            # Attach user data safely
            if reply.user_id:
                reply.user = User.query.get(reply.user_id)
            else:
                reply.user = None
            
            # Since we're using parent_id=thread_id, all these are top-level replies
            top_level_replies.append(reply)
        
        logger.debug(f"Found {len(top_level_replies)} top-level replies for thread {thread_id}")
        
        # Sort replies based on sort parameter
        if sort == 'latest':
            top_level_replies.sort(key=lambda x: x.created_at, reverse=True)
        elif sort == 'oldest':
            top_level_replies.sort(key=lambda x: x.created_at)
        elif sort == 'popular':
            # Sort by upvotes if available, otherwise by creation date
            top_level_replies.sort(key=lambda x: (x.upvotes or 0), reverse=True)
        
        # Get related threads (same category or procedure)
        related_threads = []
        if thread.category_id:
            related_threads = Community.query.filter(
                Community.category_id == thread.category_id,
                Community.id != thread.id,
                Community.parent_id.is_(None)  # Only top-level threads
            ).order_by(Community.created_at.desc()).limit(5).all()
        elif thread.procedure_id:
            related_threads = Community.query.filter(
                Community.procedure_id == thread.procedure_id,
                Community.id != thread.id,
                Community.parent_id.is_(None)  # Only top-level threads
            ).order_by(Community.created_at.desc()).limit(5).all()
        
        # Add user data to related threads
        for related in related_threads:
            if related.user_id:
                related.user = User.query.get(related.user_id)
            else:
                related.user = None
        
        # Get all categories for the dropdown
        categories = Category.query.all()
        
        # Get all procedures for the dropdown
        procedures = Procedure.query.all()
        
        return render_template(
            'community_thread_detail.html',
            thread=thread,
            top_level_replies=top_level_replies,
            all_replies=replies,
            related_threads=related_threads,
            categories=categories,
            procedures=procedures,
            sort=sort,
            media_api_url=url_for('api_routes.serve_media', url='').rstrip('/')
        )
    except Exception as e:
        logger.error(f"Error rendering community thread detail page: {str(e)}")
        return render_template(
            'community_thread_detail.html', 
            error=str(e),
            thread=None,
            top_level_replies=[],
            all_replies=[],
            related_threads=[],
            categories=[],
            procedures=[],
            sort='oldest',
            media_api_url=url_for('api_routes.serve_media', url='').rstrip('/')
        )

@web.route('/doctors/detail/<int:doctor_id>')
def doctor_detail(doctor_id):
    """Render the detailed doctor profile page."""
    try:
        logger.info('Accessing doctor_detail for id: %s', doctor_id)
        doctor = Doctor.query.get_or_404(doctor_id)
        logger.info('Doctor found: %s', doctor.name)
        logger.info('User authenticated: %s', current_user.is_authenticated)
        if current_user.is_authenticated:
            logger.info('Current user: %s (id: %s)', current_user.email, current_user.id)
        
        # Get ALL categories (since all doctors can handle all procedures)
        all_categories = Category.query.join(BodyPart).all()
        
        # Add procedure count to each category for display
        for category in all_categories:
            category.procedure_count = Procedure.query.filter_by(category_id=category.id).count()
        
        # Get ALL procedures for booking form (since all doctors can handle all procedures)
        all_procedures = Procedure.query.order_by(Procedure.procedure_name).all()
        
        # Keep doctor_procedures for backward compatibility
        doctor_procedures = DoctorProcedure.query.filter_by(doctor_id=doctor.id).all()
        
        # Get doctor's specific categories (for About tab)
        doctor_categories = DoctorCategory.query.filter_by(doctor_id=doctor.id).all()
        
        # Get doctor's photos from both DoctorPhoto table and package galleries
        doctor_photos = DoctorPhoto.query.filter_by(doctor_id=doctor.id).all()
        
        # Get gallery photos from packages where this doctor is featured
        package_gallery_photos = []
        try:
            package_gallery_result = db.session.execute(text("""
                SELECT pdg.title, pdg.description, pdg.before_image_url, pdg.after_image_url,
                       pdg.created_at, p.title as package_title
                FROM package_doctor_gallery pdg
                JOIN packages p ON pdg.package_id = p.id
                WHERE pdg.doctor_id = :doctor_id AND p.is_active = true
                ORDER BY pdg.created_at DESC
            """), {'doctor_id': doctor_id}).fetchall()
            
            for row in package_gallery_result:
                # Add complete before/after result as one entry
                package_gallery_photos.append({
                    'title': row[0] or 'Treatment Results',
                    'description': row[1] or '',
                    'before_image_url': row[2],
                    'after_image_url': row[3],
                    'created_at': row[4],
                    'package_title': row[5],
                    'type': 'package_result'
                })
        except Exception as e:
            logger.error(f"Error fetching package gallery photos: {e}")
            package_gallery_photos = []
        
        # Combine both photo sources
        all_doctor_photos = list(doctor_photos) + package_gallery_photos
        
        # Get doctor's reviews
        reviews = Review.query.filter_by(doctor_id=doctor.id).order_by(Review.created_at.desc()).all()
        
        # Calculate rating breakdown (percentage of each star rating)
        rating_breakdown = {}
        if reviews:
            total_reviews = len(reviews)
            for i in range(1, 6):
                count = sum(1 for r in reviews if round(r.rating) == i)
                rating_breakdown[i] = round((count / total_reviews) * 100)
        
        # Get similar doctors (same specialty, excluding current doctor)
        similar_doctors = Doctor.query.filter(
            Doctor.specialty == doctor.specialty,
            Doctor.id != doctor.id
        ).limit(3).all()
        
        return render_template(
            'doctor_detail.html',
            doctor=doctor,
            doctor_procedures=doctor_procedures,
            doctor_categories=doctor_categories,
            all_categories=all_categories,
            all_procedures=all_procedures,
            doctor_photos=all_doctor_photos,
            reviews=reviews,
            rating_breakdown=rating_breakdown,
            similar_doctors=similar_doctors
        )
    except Exception as e:
        logger.error(f"Error rendering doctor detail page: {str(e)}")
        return render_template(
            'doctor_detail.html',
            error=str(e),
            doctor=None,
            doctor_procedures=[],
            doctor_categories=[],
            all_categories=[],
            doctor_photos=[],
            reviews=[],
            rating_breakdown={}
            # Default doctor object not needed as we set doctor=None above
        )

@web.route('/procedures/detail/<int:procedure_id>')
@web.route('/procedure/<int:procedure_id>')
def procedure_detail(procedure_id):
    """Render the detailed procedure page."""
    try:
        procedure = Procedure.query.get_or_404(procedure_id)
        
        # Get reviews for this procedure
        procedure_reviews = Review.query.filter_by(procedure_id=procedure.id).order_by(Review.created_at.desc()).all()
        print(f"Procedure ID: {procedure.id}, Reviews found: {len(procedure_reviews)}")
        logger.info(f"Found {len(procedure_reviews)} reviews for procedure {procedure.procedure_name}")
        logger.info(f"Procedure review_count in database: {procedure.review_count}")
        
        # Calculate rating breakdown (percentage of each star rating)
        procedure_rating_breakdown = {}
        if procedure_reviews:
            total_reviews = len(procedure_reviews)
            for i in range(1, 6):
                count = sum(1 for r in procedure_reviews if round(r.rating) == i)
                procedure_rating_breakdown[i] = round((count / total_reviews) * 100)
        
        # Get doctors who perform this procedure
        procedure_doctors = Doctor.query.join(DoctorProcedure).filter(
            DoctorProcedure.procedure_id == procedure.id
        ).all()
        print(f"Procedure ID: {procedure.id}, Doctors found: {len(procedure_doctors)}")
        logger.info(f"Found {len(procedure_doctors)} doctors performing {procedure.procedure_name}")
        
        # Debug: Print each doctor found
        for doc in procedure_doctors:
            print(f"  - Doctor: {doc.name} (ID: {doc.id})")
            logger.info(f"  - Doctor: {doc.name} (ID: {doc.id})")
        
        # Additional debug to check what's being passed to the template
        print(f"procedure_doctors list: {procedure_doctors}, type: {type(procedure_doctors)}")
        logger.info(f"procedure_doctors list type: {type(procedure_doctors)}, length: {len(procedure_doctors)}")
        
        # Get community threads related to this procedure
        community_threads = Community.query.filter_by(procedure_id=procedure.id).order_by(Community.created_at.desc()).limit(5).all()
        
        # Get similar procedures based on category (fallback method)
        similar_procedures = []
        if procedure.category:
            similar_procedures = Procedure.query.filter(
                Procedure.category_id == procedure.category_id,
                Procedure.id != procedure.id
            ).limit(3).all()
        
        # Get recommended procedures (using similar procedures based on category)
        recommended_procedures = similar_procedures
        
        # Get education modules related to this procedure
        education_modules = []
        try:
            # Import models from education_routes to avoid circular imports
            from education_routes import EducationModule
            education_modules = EducationModule.query.filter_by(procedure_id=procedure.id).order_by(EducationModule.level).all()
            logger.debug(f"Found {len(education_modules)} education modules for {procedure.procedure_name}")
        except Exception as e:
            logger.error(f"Error getting education modules: {str(e)}")
        
        return render_template(
            'procedure_detail_vertical.html',
            procedure=procedure,
            procedure_reviews=procedure_reviews,
            procedure_rating_breakdown=procedure_rating_breakdown,
            procedure_doctors=procedure_doctors,
            community_threads=community_threads,
            similar_procedures=similar_procedures,
            recommended_procedures=recommended_procedures,
            education_modules=education_modules
        )
    except Exception as e:
        logger.error(f"Error rendering procedure detail page: {str(e)}")
        return render_template(
            'procedure_detail_vertical.html',
            error=str(e),
            procedure=Procedure(
                id=procedure_id, 
                procedure_name="Procedure not found", 
                short_description="", 
                min_cost=0, 
                max_cost=0,
                recovery_time="",
                results_duration="",
                risks="",
                procedure_types="",
                overview="",
                procedure_details="",
                ideal_candidates="",
                created_at=datetime.now()
            ),
            procedure_reviews=[],
            procedure_rating_breakdown={},
            procedure_doctors=[],
            community_threads=[],
            similar_procedures=[],
            recommended_procedures=[],
            education_modules=[]
        )

@web.route('/doctors')
def doctors():
    """Render the doctors page, optionally filtered by category, procedure, search, and location."""
    try:
        category_id = request.args.get('category_id', type=int)
        procedure_id = request.args.get('procedure_id', type=int)
        sort_by = request.args.get('sort_by', 'experience_desc')  # Default sort by experience
        search_query = request.args.get('search', '').strip()
        location = request.args.get('location', '').strip()
        specialty = request.args.get('specialty', '').strip()
        rating_filter = request.args.get('rating', '')
        
        title = "All Doctors"
        subtitle = None
        
        # Base query
        base_query = Doctor.query
        
        # Apply search filters
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    Doctor.name.ilike(f"%{search_query}%"),
                    Doctor.specialty.ilike(f"%{search_query}%"),
                    Doctor.bio.ilike(f"%{search_query}%")
                )
            )
            title = f"Search results for '{search_query}'"
            
        if location:
            base_query = base_query.filter(Doctor.city.ilike(f"%{location}%"))
            if title == "All Doctors":
                title = f"Doctors in {location}"
            else:
                title += f" in {location}"
                
        if specialty:
            base_query = base_query.filter(Doctor.specialty.ilike(f"%{specialty}%"))
            if title == "All Doctors":
                title = f"Doctors specializing in {specialty}"
            else:
                title += f" specializing in {specialty}"
                
        if rating_filter:
            try:
                min_rating = float(rating_filter)
                base_query = base_query.filter(Doctor.rating >= min_rating)
            except ValueError:
                pass
        
        if category_id:
            category = Category.query.get(category_id)
            if category:
                base_query = base_query.join(DoctorCategory).filter(DoctorCategory.category_id == category_id)
                title = f"Doctors specializing in {category.name}"
                subtitle = category.description
        elif procedure_id:
            procedure = Procedure.query.get(procedure_id)
            if procedure:
                base_query = base_query.join(DoctorProcedure).filter(DoctorProcedure.procedure_id == procedure_id)
                title = f"Doctors performing {procedure.procedure_name}"
                subtitle = procedure.short_description
        
        # Pagination parameters for "Show More" functionality
        limit = 20  # Show 20 doctors initially
        
        # Apply sorting based on the sort_by parameter and get total count
        if sort_by == 'experience_desc':
            base_query = base_query.order_by(Doctor.experience.desc().nulls_last())
            title += " - Sorted by Experience (Most First)"
        elif sort_by == 'experience_asc':
            base_query = base_query.order_by(Doctor.experience.asc().nulls_last())
            title += " - Sorted by Experience (Least First)"
        elif sort_by == 'rating_desc':
            base_query = base_query.order_by(Doctor.rating.desc().nulls_last())
            title += " - Sorted by Rating (Highest First)"
        elif sort_by == 'fee_asc':
            base_query = base_query.order_by(Doctor.consultation_fee.asc().nulls_last())
            title += " - Sorted by Fee (Lowest First)"
        elif sort_by == 'fee_desc':
            base_query = base_query.order_by(Doctor.consultation_fee.desc().nulls_last())
            title += " - Sorted by Fee (Highest First)"
        elif sort_by == 'name_asc':
            base_query = base_query.order_by(Doctor.name.asc())
            title += " - Sorted by Name (A-Z)"
        else:
            # Default: sort by experience descending
            base_query = base_query.order_by(Doctor.experience.desc().nulls_last())
        
        # Get total count before applying limit
        total_count = base_query.count()
        
        # Apply limit for initial load
        doctors = base_query.limit(limit).all()
        
        return render_template('doctors.html', 
                             doctors=doctors, 
                             title=title, 
                             subtitle=subtitle,
                             current_sort=sort_by,
                             total_count=total_count,
                             showing_count=len(doctors),
                             has_more=total_count > limit)
    except Exception as e:
        logger.error(f"Error rendering doctors page: {str(e)}")
        return render_template('doctors.html', error=str(e))

@web.route('/dashboard/user/<int:user_id>')
@login_required
def user_dashboard(user_id):
    """Render the user dashboard."""
    try:
        # Debug information about the current user and session
        from flask import session
        logger.info(f"Session user_id: {session.get('user_id')}")
        logger.info(f"Session _user_id: {session.get('_user_id')}")
        logger.info(f"Current user authenticated: {current_user.is_authenticated}")
        logger.info(f"Current user ID: {current_user.id}")
        logger.info(f"Requested dashboard for user_id: {user_id}")
        
        # If logged-in user is trying to access someone else's dashboard, redirect to their own
        if current_user.is_authenticated and current_user.id != user_id:
            logger.info(f"User {current_user.id} attempted to access dashboard for user {user_id}, redirecting")
            return redirect(url_for('web.user_dashboard', user_id=current_user.id))
            
        user = User.query.get_or_404(user_id)
        
        # Get saved items (if any)
        saved_items = []
        
        # First, get favorites from the Favorite model
        favorites = Favorite.query.filter_by(user_id=user.id).all()
        logger.info(f"Found {len(favorites)} favorites for user {user.id} ({user.name or user.username or user.email})")
        for favorite in favorites:
            if favorite.procedure_id and favorite.procedure:
                saved_items.append({
                    'id': favorite.procedure.id,
                    'name': favorite.procedure.procedure_name,
                    'type': 'Procedure',
                    'favorite_id': favorite.id,
                    'url': url_for('web.procedure_detail', procedure_id=favorite.procedure.id)
                })
            elif favorite.doctor_id and favorite.doctor:
                saved_items.append({
                    'id': favorite.doctor.id,
                    'name': f"Dr. {favorite.doctor.name}",
                    'type': 'Doctor',
                    'favorite_id': favorite.id,
                    'url': url_for('web.doctor_detail', doctor_id=favorite.doctor.id)
                })
        
        # Then, also check the legacy saved_items JSON field if it exists
        if hasattr(user, 'saved_items') and user.saved_items:
            try:
                saved_data = json.loads(user.saved_items) if isinstance(user.saved_items, str) else user.saved_items
                
                # Process saved procedures
                if 'procedures' in saved_data:
                    for proc_id in saved_data['procedures']:
                        # Skip if already added from Favorites
                        if any(item['id'] == proc_id and item['type'] == 'Procedure' for item in saved_items):
                            continue
                            
                        procedure = Procedure.query.get(proc_id)
                        if procedure:
                            saved_items.append({
                                'id': procedure.id,
                                'name': procedure.procedure_name,
                                'type': 'Procedure',
                                'url': url_for('web.procedure_detail', procedure_id=procedure.id)
                            })
                
                # Process saved doctors
                if 'doctors' in saved_data:
                    for doc_id in saved_data['doctors']:
                        # Skip if already added from Favorites
                        if any(item['id'] == doc_id and item['type'] == 'Doctor' for item in saved_items):
                            continue
                            
                        doctor = Doctor.query.get(doc_id)
                        if doctor:
                            saved_items.append({
                                'id': doctor.id,
                                'name': f"Dr. {doctor.name}",
                                'type': 'Doctor',
                                'url': url_for('web.doctor_detail', doctor_id=doctor.id)
                            })
                
                # Process saved threads
                if 'threads' in saved_data:
                    for thread_id in saved_data['threads']:
                        thread = Community.query.get(thread_id)
                        if thread:
                            saved_items.append({
                                'id': thread.id,
                                'name': thread.title,
                                'type': 'Discussion',
                                'url': url_for('web.community_thread_detail', thread_id=thread.id)
                            })
                            
                logger.debug(f"Processed {len(saved_items)} saved items for user {user.id}")
            except Exception as e:
                logger.error(f"Error processing saved items: {str(e)}")
        
        # Get user's appointments (leads)
        appointments = Lead.query.filter_by(user_id=user.id).all()
        
        # Get user's reviews
        reviews = Review.query.filter_by(user_id=user.id).all()
        logger.info(f"Found {len(reviews)} reviews for user {user.id} ({user.name or user.username or user.email})")
        
        # Get user's community threads
        try:
            community_threads = Community.query.filter_by(user_id=user.id).all()
            logger.info(f"Found {len(community_threads)} community threads for user {user.id}")
            
            # Get user's community replies too
            community_replies = CommunityReply.query.filter_by(user_id=user.id).all()
            logger.info(f"Found {len(community_replies)} community replies for user {user.id}")
        except Exception as e:
            logger.error(f"Error retrieving community content: {str(e)}")
            community_threads = []
            community_replies = []
        
        # Get user's notifications
        notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
        
        # Get user preferences
        preferences = UserPreference.query.filter_by(user_id=user.id).first()
        
        # Get all body parts for preference selection
        body_parts = BodyPart.query.all()
        
        return render_template(
            'dashboard_user.html',
            user=user,
            saved_items=saved_items,
            appointments=appointments,
            reviews=reviews,
            community_threads=community_threads,
            community_replies=community_replies,
            notifications=notifications,
            preferences=preferences,
            body_parts=body_parts
        )
    except Exception as e:
        logger.error(f"Error rendering user dashboard: {str(e)}")
        # Provide default empty values to avoid template errors
        return render_template(
            'dashboard_user.html', 
            error=str(e),
            user=User(id=user_id, name="User not found", email="", phone_number="", created_at=datetime.now(), role="user"),
            saved_items=[],
            appointments=[],
            reviews=[],
            community_threads=[],
            community_replies=[],
            notifications=[],
            preferences=None,
            body_parts=[]
        )

@web.route('/dashboard/doctor/<int:doctor_id>/manage-appointments')
@login_required
def doctor_manage_appointments(doctor_id):
    """Display appointments for a doctor."""
    from datetime import date
    
    if current_user.role != 'doctor':
        flash('Unauthorized access. Only doctors can access this dashboard.', 'danger')
        return redirect(url_for('web.index'))
    
    doctor = Doctor.query.get_or_404(doctor_id)
    if doctor.user_id != current_user.id:
        flash('Unauthorized access. You can only view your own dashboard.', 'danger')
        return redirect(url_for('web.index'))
    
    today = date.today()
    upcoming_appointments = Appointment.query.filter_by(doctor_id=doctor.id).filter(Appointment.appointment_date >= today).order_by(Appointment.appointment_date.asc()).all()
    past_appointments = Appointment.query.filter_by(doctor_id=doctor.id).filter(Appointment.appointment_date < today).order_by(Appointment.appointment_date.desc()).all()
    
    return render_template('doctor_appointments.html', 
                          doctor=doctor, 
                          upcoming_appointments=upcoming_appointments, 
                          past_appointments=past_appointments)

@web.route('/appointment/doctor-action/<string:action>/<int:id>', methods=['POST'])
@login_required
def doctor_appointment_action(action, id):
    """Take action on an appointment (confirm, complete, cancel)."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if current_user.role != 'doctor':
        if is_ajax:
            return jsonify({'success': False, 'message': 'Unauthorized access. Only doctors can update appointments.'}), 403
        flash('Unauthorized access. Only doctors can update appointments.', 'danger')
        return redirect(url_for('web.index'))
    
    appointment = Appointment.query.get_or_404(id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    if not doctor or appointment.doctor_id != doctor.id:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Unauthorized access. You can only update your own appointments.'}), 403
        flash('Unauthorized access. You can only update your own appointments.', 'danger')
        return redirect(url_for('web.index'))
    
    if action == 'confirm':
        appointment.status = 'confirmed'
        msg = 'Appointment confirmed.'
    elif action == 'complete':
        appointment.status = 'completed'
        msg = 'Appointment marked as completed.'
    elif action == 'cancel':
        appointment.status = 'cancelled'
        msg = 'Appointment cancelled.'
    else:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Invalid action.'}), 400
        flash('Invalid action.', 'danger')
        return redirect(url_for('web.doctor_manage_appointments', doctor_id=doctor.id))
    
    # Save changes
    try:
        db.session.commit()
        
        # Create notification for the patient
        notification = Notification(
            user_id=appointment.user_id,
            message=f"Your appointment for {appointment.procedure_name} has been {appointment.status}.",
            type='appointment_update'
        )
        db.session.add(notification)
        db.session.commit()
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': msg,
                'appointment_id': id,
                'status': appointment.status
            })
        
        flash(msg, 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating appointment: {str(e)}")
        
        if is_ajax:
            return jsonify({'success': False, 'message': 'An error occurred. Please try again.'}), 500
        
        flash('An error occurred. Please try again.', 'danger')
    
    return redirect(url_for('web.doctor_manage_appointments', doctor_id=doctor.id))

@web.route('/dashboard/doctor/<int:doctor_id>')
@login_required
def doctor_dashboard(doctor_id):
    """Render the doctor dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Use joins to reduce number of queries
        logger.info(f"Loading dashboard data for doctor ID {doctor.id}")
        
        # Get doctor's procedures - limit to essential data
        doctor_procedures = DoctorProcedure.query.filter_by(doctor_id=doctor.id).all()
        
        # Get only active leads
        leads = Lead.query.filter_by(doctor_id=doctor.id).filter(
            Lead.status.in_(['new', 'contacted', 'pending'])
        ).all()
        
        # Get doctor's upcoming appointments (pending or confirmed leads with appointment_date)
        upcoming_appointments = Lead.query.filter(
            Lead.doctor_id == doctor.id,
            Lead.appointment_date >= func.now(),
            Lead.status.in_(['pending', 'confirmed'])
        ).order_by(Lead.appointment_date).limit(10).all()
        
        # Get doctor's past appointments - limit to recent ones
        past_appointments = Lead.query.filter(
            Lead.doctor_id == doctor.id,
            Lead.appointment_date < func.now()
        ).order_by(Lead.appointment_date.desc()).limit(10).all()
        
        # Get doctor's reviews - limit to recent ones
        reviews = Review.query.filter_by(doctor_id=doctor.id).order_by(Review.created_at.desc()).limit(10).all()
        
        # Calculate rating breakdown (percentage of each star rating)
        rating_breakdown = {}
        if reviews:
            total_reviews = len(reviews)
            for i in range(1, 6):
                count = sum(1 for r in reviews if round(r.rating) == i)
                rating_breakdown[i] = round((count / total_reviews) * 100)
        
        # Get doctor's photos
        doctor_photos = DoctorPhoto.query.filter_by(doctor_id=doctor.id).all()
        
        # Get threads related to doctor's specialty or recent threads - optimized query
        try:
            # Initialize specialty_threads
            specialty_threads = []
            
            # Only get category IDs once
            if hasattr(doctor, 'doctor_categories') and doctor.doctor_categories:
                # Extract the category IDs
                category_ids = []
                for dc in doctor.doctor_categories:
                    if hasattr(dc, 'category') and hasattr(dc.category, 'id'):
                        category_ids.append(dc.category.id)
                
                # If we have category IDs, run the query
                if category_ids:
                    # Simplified query with direct category ID filtering
                    specialty_threads = Community.query.filter(
                        Community.category_id.in_(category_ids)
                    ).order_by(Community.created_at.desc()).limit(5).all()
                    
                    logger.info(f"Found {len(specialty_threads)} specialty-specific threads for doctor dashboard")
            
            # If we still don't have threads, get recent ones
            if not specialty_threads:
                # Get all recent community threads with a single query
                specialty_threads = Community.query.order_by(
                    Community.created_at.desc()
                ).limit(5).all()
                
                logger.info(f"Using {len(specialty_threads)} recent threads for doctor dashboard")
                
        except Exception as e:
            logger.error(f"Error fetching threads for doctor dashboard: {str(e)}")
            specialty_threads = []
        
        # Create activities list for activity feed
        activities = []
        
        # Add recent leads to activities
        for lead in leads[:5]:
            activities.append({
                'type': 'lead',
                'description': f"New lead from {lead.user.username if lead.user else 'Anonymous'} for consultation",
                'time': lead.created_at
            })
        
        # Add recent appointments to activities
        for appt in upcoming_appointments[:5]:
            activities.append({
                'type': 'appointment',
                'description': f"Upcoming appointment with {appt.user.username if appt.user else 'Anonymous'} on {appt.appointment_date.strftime('%b %d')}",
                'time': appt.created_at
            })
        
        # Add recent reviews to activities
        for review in reviews[:5]:
            activities.append({
                'type': 'review',
                'description': f"New {review.rating}-star review from {review.user.username}",
                'time': review.created_at
            })
        
        # Sort activities by time (most recent first)
        activities.sort(key=lambda x: x['time'], reverse=True)
        
        # Create form for review replies
        form = ReviewReplyForm()
        
        return render_template(
            'dashboard_doctor.html',
            doctor=doctor,
            doctor_procedures=doctor_procedures,
            leads=leads,
            upcoming_appointments=upcoming_appointments,
            past_appointments=past_appointments,
            reviews=reviews,
            rating_breakdown=rating_breakdown,
            doctor_photos=doctor_photos,
            specialty_threads=specialty_threads,
            activities=activities[:10],  # Limit to 10 most recent activities
            form=form  # Pass the form to the template for CSRF protection
        )
    except Exception as e:
        logger.error(f"Error rendering doctor dashboard: {str(e)}")
        # Provide default empty values to avoid template errors
        form = ReviewReplyForm()  # Create form for CSRF protection
        return render_template(
            'dashboard_doctor.html',
            error=str(e),
            doctor=Doctor(id=doctor_id, name="Doctor not found", specialty="", experience=0, city="", created_at=datetime.now(), rating=0.0),
            doctor_procedures=[],
            leads=[],
            upcoming_appointments=[],
            past_appointments=[],
            reviews=[],
            rating_breakdown={},
            doctor_photos=[],
            specialty_threads=[],
            activities=[],
            form=form  # Pass the form to the template
        )

@web.route('/dashboard/community/create', methods=['GET', 'POST'])
def create_thread():
    """Create a new community thread."""
    try:
        logger.debug(f"Create thread page accessed")
        
        # Handle form submission
        if request.method == 'POST':
            title = request.form['title']
            content = request.form.get('content', '')
            category_name = request.form.get('category', '')
            is_anonymous = request.form.get('is_anonymous') == 'on'
            
            # Find category by name
            category_id = None
            if category_name:
                category = Category.query.filter_by(name=category_name).first()
                if category:
                    category_id = category.id
                elif category_name in ["Facial Surgery", "Non-Surgical Treatments"]:
                    # Find similar category
                    category = Category.query.filter(Category.name.ilike(f"%{category_name}%")).first()
                    if category:
                        category_id = category.id
            
            # Get the currently logged in user's ID (using 1 for testing if not available)
            user_id = 1  # Default user for testing - would normally use current_user.id
            
            # Create new thread with user information
            new_thread = Community(
                title=title,
                content=content,
                user_id=user_id,
                category_id=category_id,
                created_at=datetime.utcnow(),
                is_anonymous=is_anonymous
            )
            
            # Handle image upload
            if 'image' in request.files and request.files['image'].filename:
                file = request.files['image']
                # Create a safe filename
                filename = secure_filename(file.filename)
                # Make sure the path exists first
                os.makedirs('static/media', exist_ok=True)
                # Save the image
                file_path = os.path.join('static/media', filename)
                file.save(file_path)
                # Update photo_url to reference the saved file
                new_thread.photo_url = filename
                logger.debug(f"Image saved: {filename}")
            
            db.session.add(new_thread)
            db.session.commit()
            
            logger.debug(f"Thread created successfully with ID: {new_thread.id}")
            return redirect(url_for('web.community_dashboard'))
            
        # Get all categories for the form dropdown
        categories = Category.query.all()
        
        return render_template('create_thread.html', categories=categories)
    except Exception as e:
        logger.error(f"Error creating thread: {str(e)}")
        return render_template('create_thread.html', error=str(e), categories=[])

@web.route('/dashboard/community/edit/<int:thread_id>', methods=['GET', 'POST'])
def edit_thread(thread_id):
    """Edit a community thread."""
    try:
        logger.debug(f"Editing thread {thread_id}")
        thread = Community.query.get_or_404(thread_id)
        
        if request.method == 'POST':
            thread.title = request.form['title']
            thread.content = request.form.get('content', thread.content)
            thread.is_anonymous = request.form.get('is_anonymous') == 'on'
            
            # Handle the category as a string instead of an ID
            category_name = request.form['category']
            logger.debug(f"Updating thread category to: {category_name}")
            
            # Find the category by name
            category = Category.query.filter_by(name=category_name).first()
            if category:
                thread.category_id = category.id
            else:
                # For testing purposes - create or find a category with this name
                logger.debug(f"Category not found, searching for similar categories")
                # This branch is just for temporary compatibility
                if category_name == "Facial Surgery" or category_name == "Non-Surgical Treatments":
                    category = Category.query.filter(Category.name.ilike(f"%{category_name}%")).first()
                    if category:
                        thread.category_id = category.id
            
            # Handle image upload
            if 'image' in request.files and request.files['image'].filename:
                file = request.files['image']
                # Create a safe filename
                filename = secure_filename(file.filename)
                # Make sure the path exists first
                os.makedirs('static/media', exist_ok=True)
                # Save the image
                file_path = os.path.join('static/media', filename)
                file.save(file_path)
                # Update photo_url to reference the saved file
                thread.photo_url = filename
                logger.debug(f"Image updated: {filename}")
            
            thread.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.debug(f"Thread {thread_id} updated successfully")
            return redirect(url_for('web.community_dashboard'))
            
        # Get all categories for the form dropdown
        categories = Category.query.all()
        return render_template('edit_thread.html', thread=thread, categories=categories)
    except Exception as e:
        logger.error(f"Error editing thread: {str(e)}")
        # Get all categories for the form dropdown even on error
        categories = Category.query.all()
        return render_template('edit_thread.html', error=str(e), thread=None, categories=categories)

# Doctor dashboard section routes
@web.route('/dashboard/doctor/<int:doctor_id>/leads')
@login_required
def doctor_leads(doctor_id):
    """Render the doctor leads dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get doctor's leads
        leads = Lead.query.filter_by(doctor_id=doctor.id).order_by(Lead.created_at.desc()).all()
        
        return render_template('doctor_leads.html', doctor=doctor, leads=leads)
    except Exception as e:
        logger.error(f"Error rendering doctor leads: {str(e)}")
        return render_template('doctor_leads.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              leads=[])

@web.route('/dashboard/doctor/<int:doctor_id>/procedures')
@login_required
def doctor_procedures(doctor_id):
    """Render the doctor procedures dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get doctor's procedures
        doctor_procedures = DoctorProcedure.query.filter_by(doctor_id=doctor.id).all()
        
        # Get all available procedures for adding new ones
        all_procedures = Procedure.query.all()
        
        return render_template('doctor_procedures.html', 
                              doctor=doctor, 
                              doctor_procedures=doctor_procedures,
                              all_procedures=all_procedures)
    except Exception as e:
        logger.error(f"Error rendering doctor procedures: {str(e)}")
        return render_template('doctor_procedures.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              doctor_procedures=[],
                              all_procedures=[])

@web.route('/dashboard/doctor/<int:doctor_id>/availability')
@login_required
def doctor_availability(doctor_id):
    """Render the doctor availability dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get doctor's availability slots
        availability = DoctorAvailability.query.filter_by(doctor_id=doctor.id).all()
        
        # Get special dates (time off, extended hours)
        # In a real application, we would have a dedicated model for this
        # For now, we'll create dummy data for the template
        special_dates = {
            'time_off': [],
            'extended_hours': []
        }
        
        return render_template('doctor_availability.html', 
                              doctor=doctor, 
                              availability=availability,
                              special_dates=special_dates)
    except Exception as e:
        logger.error(f"Error rendering doctor availability: {str(e)}")
        return render_template('doctor_availability.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              availability=[],
                              special_dates=None)

@web.route('/dashboard/doctor/<int:doctor_id>/availability/update', methods=['POST'])
@login_required
def update_availability(doctor_id):
    """Update doctor's availability schedule."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can update availability.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own availability.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get existing availability to update or remove
        existing_availability = {a.day_of_week: a for a in DoctorAvailability.query.filter_by(doctor_id=doctor.id).all()}
        
        # Process each day of the week
        days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        for day in days:
            day_title = day.capitalize()
            is_available = request.form.get(f'{day}_available') == 'on'
            
            if is_available:
                # Get time values
                start_time_str = request.form.get(f'{day}_start_time')
                end_time_str = request.form.get(f'{day}_end_time')
                
                if start_time_str and end_time_str:
                    # Convert time strings to time objects
                    try:
                        start_time = datetime.strptime(start_time_str, '%H:%M').time()
                        end_time = datetime.strptime(end_time_str, '%H:%M').time()
                        
                        # Update or create availability record
                        if day_title in existing_availability:
                            # Update existing
                            availability = existing_availability[day_title]
                            availability.start_time = start_time
                            availability.end_time = end_time
                        else:
                            # Create new
                            availability = DoctorAvailability(
                                doctor_id=doctor.id,
                                day_of_week=day_title,
                                start_time=start_time,
                                end_time=end_time
                            )
                            db.session.add(availability)
                    except ValueError:
                        flash(f'Invalid time format for {day_title}', 'warning')
            elif day_title in existing_availability:
                # Remove availability for this day
                db.session.delete(existing_availability[day_title])
        
        # Update appointment settings
        appointment_duration = request.form.get('appointment_duration', type=int)
        buffer_time = request.form.get('buffer_time', type=int)
        allow_online_meetings = request.form.get('allow_online_meetings') == 'on'
        
        # In a real application, we would have these fields in the Doctor model
        # For now, we'll just log them
        logger.info(f"Setting appointment_duration={appointment_duration} for doctor {doctor.id}")
        logger.info(f"Setting buffer_time={buffer_time} for doctor {doctor.id}")
        logger.info(f"Setting allow_online_meetings={allow_online_meetings} for doctor {doctor.id}")
        
        # Save all changes
        db.session.commit()
        
        flash('Your availability has been updated successfully.', 'success')
        return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
    except Exception as e:
        logger.error(f"Error updating availability: {str(e)}")
        flash(f'Error updating availability: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_availability', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/availability/special-date/add', methods=['POST'])
@login_required
def add_special_date(doctor_id):
    """Add a special date (time off or extended hours) to doctor's schedule."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can update availability.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own availability.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get form data
        date_type = request.form.get('date_type')
        date_str = request.form.get('date')
        
        if not date_str:
            flash('Date is required.', 'danger')
            return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
        # In a real application, we would have a DoctorSpecialDate model
        # For now, we'll just log the data
        if date_type == 'time_off':
            reason = request.form.get('reason', 'Time off')
            logger.info(f"Adding time off on {date_str} with reason '{reason}' for doctor {doctor.id}")
            flash(f'Time off added for {date_str}.', 'success')
        else:  # extended_hours
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time')
            logger.info(f"Adding extended hours on {date_str} from {start_time} to {end_time} for doctor {doctor.id}")
            flash(f'Special working hours added for {date_str}.', 'success')
        
        return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
    except Exception as e:
        logger.error(f"Error adding special date: {str(e)}")
        flash(f'Error adding special date: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_availability', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/availability/special-date/delete', methods=['POST'])
@login_required
def delete_special_date(doctor_id):
    """Delete a special date from doctor's schedule."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can update availability.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own availability.', 'danger')
            return redirect(url_for('web.index'))
        
        date_id = request.form.get('date_id')
        if not date_id:
            flash('Invalid request. Missing date ID.', 'danger')
            return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
        # In a real application, we would delete the DoctorSpecialDate record
        # For now, we'll just log it
        logger.info(f"Deleting special date with ID {date_id} for doctor {doctor.id}")
        flash('Special date has been deleted.', 'success')
        
        return redirect(url_for('web.doctor_availability', doctor_id=doctor.id))
        
    except Exception as e:
        logger.error(f"Error deleting special date: {str(e)}")
        flash(f'Error deleting special date: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_availability', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/gallery')
@login_required
def doctor_gallery(doctor_id):
    """Render the doctor gallery dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get doctor's photos
        doctor_photos = DoctorPhoto.query.filter_by(doctor_id=doctor.id).all()
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        procedure_id = request.args.get('procedure_id', type=int)
        
        # In a real application, we would paginate and filter by procedure
        # For now, we'll set some default pagination values
        page_count = max(1, len(doctor_photos) // 6)  # 6 photos per page
        current_page = min(page, page_count)
        
        # If filtering by procedure, we would filter the photos here
        
        return render_template('doctor_gallery.html', 
                              doctor=doctor, 
                              doctor_photos=doctor_photos,
                              page_count=page_count,
                              current_page=current_page)
    except Exception as e:
        logger.error(f"Error rendering doctor gallery: {str(e)}")
        return render_template('doctor_gallery.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              doctor_photos=[],
                              page_count=1,
                              current_page=1)

@web.route('/dashboard/doctor/<int:doctor_id>/gallery/upload', methods=['POST'])
@login_required
def upload_photo(doctor_id):
    """Upload photos to the doctor's gallery."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can upload photos.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own gallery.', 'danger')
            return redirect(url_for('web.index'))
        
        # Check if patient consent is given
        if not request.form.get('patient_consent'):
            flash('You must confirm patient consent to share these photos.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Get form data
        photo_type = request.form.get('photo_type')
        procedure_id = request.form.get('procedure_id')
        description = request.form.get('description')
        
        # Check if files were submitted
        if 'photos' not in request.files:
            flash('No files were uploaded.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        files = request.files.getlist('photos')
        if not files or files[0].filename == '':
            flash('No files were selected.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Count how many photos were uploaded successfully
        success_count = 0
        
        # Process each file
        for file in files:
            if file and file.filename:
                # Check if the file is an allowed image type
                if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    # Create a safe filename
                    filename = secure_filename(file.filename)
                    
                    # Make sure the upload directory exists
                    os.makedirs('static/uploads/doctors', exist_ok=True)
                    
                    # Generate a unique filename to avoid collisions
                    unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                    file_path = os.path.join('static/uploads/doctors', unique_filename)
                    
                    # Save the file
                    file.save(file_path)
                    
                    # Create the doctor photo record
                    doctor_photo = DoctorPhoto(
                        doctor_id=doctor.id,
                        photo_url=f"/static/uploads/doctors/{unique_filename}",
                        description=description
                    )
                    
                    # If a procedure was selected, link it
                    if procedure_id:
                        doctor_photo.procedure_id = procedure_id
                    
                    db.session.add(doctor_photo)
                    success_count += 1
                else:
                    flash(f'File {file.filename} is not an allowed image type.', 'warning')
        
        if success_count > 0:
            db.session.commit()
            flash(f'Successfully uploaded {success_count} photo(s).', 'success')
        else:
            flash('No photos were uploaded. Please check that your files are valid images.', 'danger')
        
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
    
    except Exception as e:
        logger.error(f"Error uploading photos: {str(e)}")
        flash(f'Error uploading photos: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/gallery/edit', methods=['POST'])
@login_required
def edit_photo(doctor_id):
    """Edit a photo in the doctor's gallery."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can edit photos.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own gallery.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the photo ID and details
        photo_id = request.form.get('photo_id', type=int)
        if not photo_id:
            flash('Photo ID is required.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Find the photo
        photo = DoctorPhoto.query.get_or_404(photo_id)
        
        # Verify that this photo belongs to the doctor
        if photo.doctor_id != doctor.id:
            flash('You can only edit your own photos.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Update the photo details
        description = request.form.get('description')
        procedure_id = request.form.get('procedure_id')
        
        photo.description = description
        if procedure_id:
            photo.procedure_id = procedure_id
        
        db.session.commit()
        flash('Photo details updated successfully.', 'success')
        
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
    
    except Exception as e:
        logger.error(f"Error editing photo: {str(e)}")
        flash(f'Error editing photo: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/gallery/delete', methods=['POST'])
@login_required
def delete_photo(doctor_id):
    """Delete a photo from the doctor's gallery."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can delete photos.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own gallery.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the photo ID
        photo_id = request.form.get('photo_id', type=int)
        if not photo_id:
            flash('Photo ID is required.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Find the photo
        photo = DoctorPhoto.query.get_or_404(photo_id)
        
        # Verify that this photo belongs to the doctor
        if photo.doctor_id != doctor.id:
            flash('You can only delete your own photos.', 'danger')
            return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
        
        # Delete the file if it exists
        if photo.photo_url and photo.photo_url.startswith('/static/'):
            file_path = os.path.join('.', photo.photo_url.lstrip('/'))
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete the database record
        db.session.delete(photo)
        db.session.commit()
        
        flash('Photo deleted successfully.', 'success')
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor.id))
    
    except Exception as e:
        logger.error(f"Error deleting photo: {str(e)}")
        flash(f'Error deleting photo: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_gallery', doctor_id=doctor_id))

@web.route('/dashboard/doctor/<int:doctor_id>/community')
@login_required
def doctor_community(doctor_id):
    """Render the doctor community dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get doctor's specialty categories
        specialty_categories = [dc.category for dc in doctor.doctor_categories if dc.category]
        
        # Get threads related to doctor's specialty
        specialty_threads = Community.query.filter(
            Community.category_id.in_([c.id for c in specialty_categories]) if specialty_categories else False
        ).order_by(Community.created_at.desc()).limit(10).all()
        
        return render_template('doctor_community.html', 
                              doctor=doctor, 
                              specialty_threads=specialty_threads,
                              specialty_categories=specialty_categories)
    except Exception as e:
        logger.error(f"Error rendering doctor community: {str(e)}")
        return render_template('doctor_community.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              specialty_threads=[],
                              specialty_categories=[])

@web.route('/doctor/<int:doctor_id>/procedure/add', methods=['POST'])
@login_required
def add_doctor_procedure(doctor_id):
    """Add a procedure to a doctor's profile."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can add procedures.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own profile.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the procedure ID from the form
        procedure_id = request.form.get('procedure_id', type=int)
        if not procedure_id:
            flash('No procedure selected.', 'danger')
            return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
        # Check if the procedure exists
        procedure = Procedure.query.get(procedure_id)
        if not procedure:
            flash('Selected procedure does not exist.', 'danger')
            return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
        # Check if the doctor already has this procedure
        existing = DoctorProcedure.query.filter_by(doctor_id=doctor.id, procedure_id=procedure.id).first()
        if existing:
            flash('You already have this procedure added to your profile.', 'warning')
            return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
        # Create the doctor-procedure association
        doctor_procedure = DoctorProcedure(
            doctor_id=doctor.id,
            procedure_id=procedure.id
        )
        
        # Add any custom details from the form
        custom_price = request.form.get('custom_price', type=int)
        if custom_price and custom_price > 0:
            # In a real implementation, we would store this in the doctor_procedure table
            # For now, we'll just acknowledge it
            logger.info(f"Custom price of {custom_price} set for doctor {doctor.id}, procedure {procedure.id}")
        
        experience_years = request.form.get('experience_years', type=int)
        if experience_years is not None:
            # Similarly, in a real implementation, we would store this
            logger.info(f"Experience of {experience_years} years set for doctor {doctor.id}, procedure {procedure.id}")
        
        special_notes = request.form.get('special_notes')
        if special_notes:
            # Similarly, in a real implementation, we would store this
            logger.info(f"Special notes added for doctor {doctor.id}, procedure {procedure.id}")
        
        is_featured = request.form.get('is_featured') == 'on'
        # Similarly, in a real implementation, we would store this
        logger.info(f"Featured status set to {is_featured} for doctor {doctor.id}, procedure {procedure.id}")
        
        db.session.add(doctor_procedure)
        db.session.commit()
        
        flash(f'Added {procedure.procedure_name} to your procedures.', 'success')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
    except Exception as e:
        logger.error(f"Error adding doctor procedure: {str(e)}")
        flash(f'Error adding procedure: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor_id))

@web.route('/doctor/<int:doctor_id>/procedure/<int:procedure_id>/remove', methods=['POST'])
@login_required
def remove_doctor_procedure(doctor_id, procedure_id):
    """Remove a procedure from a doctor's profile."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can remove procedures.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own profile.', 'danger')
            return redirect(url_for('web.index'))
        
        # Find the doctor-procedure association
        doctor_procedure = DoctorProcedure.query.filter_by(doctor_id=doctor.id, procedure_id=procedure_id).first()
        if not doctor_procedure:
            flash('This procedure is not on your profile.', 'warning')
            return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
        # Get the procedure name for the success message
        procedure_name = Procedure.query.get(procedure_id).procedure_name if Procedure.query.get(procedure_id) else "Unknown procedure"
        
        # Delete the association
        db.session.delete(doctor_procedure)
        db.session.commit()
        
        flash(f'Removed {procedure_name} from your procedures.', 'success')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
    except Exception as e:
        logger.error(f"Error removing doctor procedure: {str(e)}")
        flash(f'Error removing procedure: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor_id))

@web.route('/doctor/<int:doctor_id>/procedure/<int:procedure_id>/update', methods=['POST'])
@login_required
def update_doctor_procedure(doctor_id, procedure_id):
    """Update a doctor's procedure details."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can update procedures.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only update your own profile.', 'danger')
            return redirect(url_for('web.index'))
        
        # Find the doctor-procedure association
        doctor_procedure = DoctorProcedure.query.filter_by(doctor_id=doctor.id, procedure_id=procedure_id).first()
        if not doctor_procedure:
            flash('This procedure is not on your profile.', 'warning')
            return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
        # Update with form data
        # In a real implementation, we would have additional fields in the DoctorProcedure model
        # For now, we'll just log the updates
        
        custom_price = request.form.get('custom_price', type=int)
        if custom_price and custom_price > 0:
            logger.info(f"Updated custom price to {custom_price} for doctor {doctor.id}, procedure {procedure_id}")
        
        experience_years = request.form.get('experience_years', type=int)
        if experience_years is not None:
            logger.info(f"Updated experience to {experience_years} years for doctor {doctor.id}, procedure {procedure_id}")
        
        special_notes = request.form.get('special_notes')
        if special_notes:
            logger.info(f"Updated special notes for doctor {doctor.id}, procedure {procedure_id}")
        
        is_featured = request.form.get('is_featured') == 'on'
        logger.info(f"Updated featured status to {is_featured} for doctor {doctor.id}, procedure {procedure_id}")
        
        # Here we would update the fields if they existed in the model
        # Since they don't yet, we'll just send the success message
        
        db.session.commit()
        
        flash('Procedure details updated successfully!', 'success')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor.id))
        
    except Exception as e:
        logger.error(f"Error updating doctor procedure: {str(e)}")
        flash(f'Error updating procedure: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_procedures', doctor_id=doctor_id))

# Admin Category Image Management Routes
@web.route('/admin/category-images')
@login_required
@admin_required
def admin_category_images():
    """Admin category image management page."""
    try:
        # Force fresh data from database
        db.session.expire_all()
        categories = Category.query.join(BodyPart).order_by(BodyPart.name, Category.name).all()
        
        # Debug: Log categories with images
        categories_with_images = [c for c in categories if c.image_url]
        logger.info(f"Categories with images: {len(categories_with_images)}")
        
        return render_template('admin/category_images.html', categories=categories)
    except Exception as e:
        logger.error(f"Error loading category images page: {str(e)}")
        flash('Error loading categories', 'error')
        return redirect(url_for('admin_credit.credit_dashboard'))

@web.route('/admin/category/<int:category_id>/upload-image', methods=['POST'])
@login_required
@admin_required
def upload_category_image(category_id):
    """Upload image for a category."""
    try:
        category = Category.query.get_or_404(category_id)
        
        if 'image' not in request.files:
            flash('No image file selected', 'error')
            return redirect(url_for('web.admin_category_images'))
        
        file = request.files['image']
        if file.filename == '':
            flash('No image file selected', 'error')
            return redirect(url_for('web.admin_category_images'))
        
        # Check file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'svg'}
        if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            flash('Invalid file type. Please upload PNG, JPG, or SVG files only.', 'error')
            return redirect(url_for('web.admin_category_images'))
        
        # Check file size (5MB limit)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 5 * 1024 * 1024:  # 5MB
            flash('File too large. Please upload files under 5MB.', 'error')
            return redirect(url_for('web.admin_category_images'))
        
        # Create uploads directory if it doesn't exist
        upload_folder = os.path.join('static', 'uploads', 'categories')
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate secure filename
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        # Save file
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        
        # Update category with image URL
        image_url = f'/static/uploads/categories/{filename}'
        
        # Update category with image URL using ORM
        category.image_url = image_url
        db.session.commit()
        
        logger.info(f"Updated category {category.name} (ID: {category_id}) with image: {image_url}")
        flash(f'Image uploaded successfully for {category.name}!', 'success')
        
    except Exception as e:
        logger.error(f"Error uploading category image: {str(e)}")
        flash('Error uploading image. Please try again.', 'error')
    
    return redirect(url_for('web.admin_category_images'))

@web.route('/admin/category/<int:category_id>/remove-image')
@login_required
@admin_required
def remove_category_image(category_id):
    """Remove image from a category."""
    try:
        category = Category.query.get_or_404(category_id)
        
        if category.image_url:
            # Try to delete the file from filesystem
            try:
                if category.image_url.startswith('/static/'):
                    file_path = category.image_url[1:]  # Remove leading slash
                    if os.path.exists(file_path):
                        os.remove(file_path)
            except Exception as e:
                logger.warning(f"Could not delete file {category.image_url}: {str(e)}")
            
            # Remove image URL from database
            category.image_url = None
            db.session.commit()
            
            flash(f'Image removed successfully from {category.name}!', 'success')
        else:
            flash(f'{category.name} has no image to remove.', 'warning')
            
    except Exception as e:
        logger.error(f"Error removing category image: {str(e)}")
        flash('Error removing image. Please try again.', 'error')
    
    return redirect(url_for('web.admin_category_images'))

@web.route('/admin/upload-procedure-image', methods=['POST'])
@login_required
@admin_required
def upload_procedure_image():
    """Upload image for a popular procedure."""
    try:
        procedure_id = request.form.get('procedure_id')
        image_file = request.files.get('image')
        
        if not procedure_id or not image_file:
            flash('Please select a procedure and image file.', 'error')
            return redirect(url_for('admin_credit.credit_dashboard') + '#procedures')
        
        procedure = Procedure.query.get_or_404(procedure_id)
        
        # Validate file type
        allowed_extensions = {'jpg', 'jpeg', 'png', 'webp'}
        if not ('.' in image_file.filename and 
                image_file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            flash('Only JPG, PNG and WebP images are allowed.', 'error')
            return redirect(url_for('admin_credit.credit_dashboard') + '#procedures')
        
        # Create procedures upload directory
        upload_dir = 'static/uploads/procedures'
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_extension = image_file.filename.rsplit('.', 1)[1].lower()
        filename = f"{timestamp}_{secure_filename(procedure.procedure_name.lower().replace(' ', '_'))}.{file_extension}"
        
        # Save file
        file_path = os.path.join(upload_dir, filename)
        image_file.save(file_path)
        
        # Update procedure with image URL
        image_url = f'/static/uploads/procedures/{filename}'
        procedure.image_url = image_url
        db.session.commit()
        
        logger.info(f"Updated procedure {procedure.procedure_name} (ID: {procedure_id}) with image: {image_url}")
        flash(f'Image uploaded successfully for {procedure.procedure_name}!', 'success')
        
    except Exception as e:
        logger.error(f"Error uploading procedure image: {str(e)}")
        flash('Error uploading image. Please try again.', 'error')
    
    return redirect(url_for('admin_credit.credit_dashboard') + '#procedures')

@web.route('/lead/<int:lead_id>/details')
@login_required
def lead_details(lead_id):
    """Get lead details in JSON format for AJAX requests."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            return jsonify({'success': False, 'message': 'Unauthorized access. Only doctors can access this.'}), 403
        
        # Get the lead
        lead = Lead.query.get_or_404(lead_id)
        
        # Get the doctor associated with the current user
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            return jsonify({'success': False, 'message': 'Doctor profile not found.'}), 404
        
        # Check if this lead belongs to this doctor
        if lead.doctor_id != doctor.id:
            return jsonify({'success': False, 'message': 'Unauthorized access. You can only view your own leads.'}), 403
        
        # Log for debugging
        logger.info(f"Getting lead details via API - ID: {lead_id}, Doctor ID: {doctor.id}, Patient: {lead.patient_name}")
        
        # Return JSON data for the lead
        return jsonify({
            'success': True,
            'lead': {
                'id': lead.id,
                'patient_name': lead.patient_name,
                'email': lead.email,
                'mobile_number': lead.mobile_number,
                'city': lead.city,
                'procedure_name': lead.procedure_name,
                'preferred_date': lead.preferred_date.strftime('%d %b %Y') if lead.preferred_date else None,
                'status': lead.status,
                'message': lead.message,
                'created_at': lead.created_at.strftime('%d %b %Y, %H:%M') if lead.created_at else None,
                'appointment_date': lead.appointment_date.strftime('%d %b %Y, %H:%M') if lead.appointment_date else None
            }
        })
    except Exception as e:
        logger.error(f"Error getting lead details: {str(e)}")
        return jsonify({'success': False, 'message': f'Error getting lead details: {str(e)}'}), 500

@web.route('/lead/<int:lead_id>/view')
@login_required
def view_lead(lead_id):
    """View details of a patient lead."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can access this.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the lead
        lead = Lead.query.get_or_404(lead_id)
        
        # Get the doctor associated with the current user
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            flash('Doctor profile not found.', 'danger')
            return redirect(url_for('web.index'))
        
        # Check if this lead belongs to this doctor
        if lead.doctor_id != doctor.id:
            flash('Unauthorized access. You can only view your own leads.', 'danger')
            return redirect(url_for('web.index'))
        
        # Log for debugging
        logger.info(f"Viewing lead ID: {lead_id}, Doctor ID: {doctor.id}, Patient: {lead.patient_name}")
        
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            return jsonify({
                'success': True,
                'lead': {
                    'id': lead.id,
                    'patient_name': lead.patient_name,
                    'email': lead.email,
                    'mobile_number': lead.mobile_number,
                    'city': lead.city,
                    'procedure_name': lead.procedure_name,
                    'preferred_date': lead.preferred_date.strftime('%d %b %Y') if lead.preferred_date else None,
                    'status': lead.status,
                    'message': lead.message,
                    'created_at': lead.created_at.strftime('%d %b %Y, %H:%M') if lead.created_at else None,
                    'appointment_date': lead.appointment_date.strftime('%d %b %Y, %H:%M') if lead.appointment_date else None
                }
            })
        
        # Regular HTML response
        return render_template('view_lead.html', lead=lead, doctor=doctor)
    except Exception as e:
        logger.error(f"Error viewing lead: {str(e)}")
        flash(f'Error viewing lead: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_leads', doctor_id=doctor.id if 'doctor' in locals() else 1))

@web.route('/lead/<int:lead_id>/contact', methods=['GET', 'POST'])
@login_required
def contact_lead(lead_id):
    """Contact a patient lead."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can access this.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the lead
        lead = Lead.query.get_or_404(lead_id)
        
        # Get the doctor associated with the current user
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            flash('Doctor profile not found.', 'danger')
            return redirect(url_for('web.index'))
        
        # Check if this lead belongs to this doctor
        if lead.doctor_id != doctor.id:
            flash('Unauthorized access. You can only contact your own leads.', 'danger')
            return redirect(url_for('web.index'))
        
        # Update lead status to 'contacted' if it's 'pending'
        if lead.status == 'pending':
            lead.status = 'contacted'
            db.session.commit()
            flash('Lead status updated to contacted.', 'success')
        
        # Check if it's a POST request (sending the message)
        if request.method == 'POST':
            # Get form data
            contact_method = request.form.get('contact_method', 'email')
            subject = request.form.get('subject', f'Regarding your {lead.procedure_name} inquiry')
            message = request.form.get('message', '')
            update_status = request.form.get('update_status') == 'contacted'
            
            # In a real implementation, this would send an email or SMS
            # For now, just return success message
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            
            if update_status and lead.status == 'pending':
                lead.status = 'contacted'
                db.session.commit()
            
            if is_ajax:
                return jsonify({
                    'success': True,
                    'message': 'Message sent successfully to the patient.',
                    'lead': {
                        'id': lead.id,
                        'status': lead.status
                    }
                })
            
            flash('Message sent successfully to the patient.', 'success')
            return redirect(url_for('web.view_lead', lead_id=lead.id))
        
        # For GET requests, show the contact form
        return render_template('contact_lead.html', lead=lead, doctor=doctor)
    except Exception as e:
        logger.error(f"Error contacting lead: {str(e)}")
        flash(f'Error contacting lead: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_leads', doctor_id=doctor.id if 'doctor' in locals() else 1))

@web.route('/lead/<int:lead_id>/update_status', methods=['GET', 'POST'])
@login_required
def update_lead_status(lead_id):
    """Update a patient lead status."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            if is_ajax:
                return jsonify({'success': False, 'message': 'Unauthorized access. Only doctors can access this.'}), 403
            flash('Unauthorized access. Only doctors can access this.', 'danger')
            return redirect(url_for('web.index'))
        
        # Get the lead
        lead = Lead.query.get_or_404(lead_id)
        
        # Get the doctor associated with this lead
        doctor = Doctor.query.get_or_404(lead.doctor_id)
        
        # Check if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Unauthorized access. You can only update your own leads.'}), 403
            flash('Unauthorized access. You can only update your own leads.', 'danger')
            return redirect(url_for('web.index'))
        
        # For GET requests, show the update form
        if request.method == 'GET':
            if is_ajax:
                return jsonify({
                    'success': True,
                    'lead': {
                        'id': lead.id,
                        'patient_name': lead.patient_name,
                        'procedure_name': lead.procedure_name,
                        'status': lead.status,
                        'appointment_date': lead.appointment_date.isoformat() if lead.appointment_date else None,
                        'preferred_date': lead.preferred_date.isoformat() if lead.preferred_date else None
                    }
                })
            return render_template('update_lead_status.html', lead=lead, doctor=doctor)
        
        # For POST requests, process the form submission
        # Get the new status from the form
        new_status = request.form.get('status')
        if not new_status or new_status not in ['pending', 'contacted', 'scheduled', 'completed', 'rejected']:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Invalid status. Please select a valid status.'}), 400
            flash('Invalid status. Please select a valid status.', 'danger')
            return redirect(url_for('web.doctor_leads', doctor_id=doctor.id))
        
        # Update the lead status
        lead.status = new_status
        
        # If the status is 'scheduled', update appointment_date if provided
        if new_status == 'scheduled':
            appointment_date_str = request.form.get('appointment_date')
            if appointment_date_str:
                try:
                    # Parse datetime from the form input
                    appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%dT%H:%M')
                    lead.appointment_date = appointment_date
                except ValueError:
                    if is_ajax:
                        return jsonify({'success': False, 'message': 'Invalid appointment date format.'}), 400
                    flash('Invalid appointment date format. Please use the date picker.', 'warning')
                    # Use preferred_date if available, or set to tomorrow
                    if lead.preferred_date:
                        lead.appointment_date = lead.preferred_date
                    else:
                        lead.appointment_date = datetime.now() + timedelta(days=1)
            elif not lead.appointment_date:
                # If no appointment date is provided and none exists, set a default
                if lead.preferred_date:
                    lead.appointment_date = lead.preferred_date
                else:
                    lead.appointment_date = datetime.now() + timedelta(days=1)
        
        db.session.commit()
        
        if is_ajax:
            return jsonify({
                'success': True,
                'message': f'Lead status updated to {new_status}.',
                'lead': {
                    'id': lead.id,
                    'status': lead.status,
                    'appointment_date': lead.appointment_date.isoformat() if lead.appointment_date else None
                }
            })
        
        flash(f'Lead status updated to {new_status}.', 'success')
        return redirect(url_for('web.doctor_leads', doctor_id=doctor.id))
    except Exception as e:
        logger.error(f"Error updating lead status: {str(e)}")
        flash(f'Error updating lead status: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_leads', doctor_id=lead.doctor_id if 'lead' in locals() and lead.doctor_id else 1))

@web.route('/dashboard/doctor/<int:doctor_id>/verification')
@login_required
def doctor_verification(doctor_id):
    """Render the doctor verification dashboard."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can view this dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only view your own dashboard.', 'danger')
            return redirect(url_for('web.index'))
        
        # In a real application, we would have a VerificationEvent model
        # to track the verification timeline
        verification_events = []
        
        return render_template('doctor_verification.html', 
                              doctor=doctor,
                              verification_events=verification_events)
    except Exception as e:
        logger.error(f"Error rendering doctor verification: {str(e)}")
        return render_template('doctor_verification.html', 
                              error=str(e),
                              doctor=doctor if 'doctor' in locals() else None,
                              verification_events=[])

@web.route('/dashboard/doctor/<int:doctor_id>/verification/submit', methods=['POST'])
@login_required
def submit_verification(doctor_id):
    """Submit verification documents for review."""
    try:
        # Check if the user is a doctor
        if current_user.role != 'doctor':
            flash('Unauthorized access. Only doctors can submit verification.', 'danger')
            return redirect(url_for('web.index'))
        
        doctor = Doctor.query.get_or_404(doctor_id)
        
        # Verify if the current user is the doctor owner
        if doctor.user_id != current_user.id:
            flash('Unauthorized access. You can only submit verification for your own profile.', 'danger')
            return redirect(url_for('web.index'))
        
        # Check required form fields
        if not request.form.get('medical_license_number'):
            flash('Medical license number is required.', 'danger')
            return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        if not request.form.get('aadhaar_number'):
            flash('Aadhaar number is required.', 'danger')
            return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        if not request.form.get('qualification'):
            flash('Qualification is required.', 'danger')
            return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        if not request.form.get('practice_location'):
            flash('Practice location is required.', 'danger')
            return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        if not request.form.get('specialty'):
            flash('Specialty is required.', 'danger')
            return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        # Process form data
        medical_license_number = request.form.get('medical_license_number')
        aadhaar_number = request.form.get('aadhaar_number')
        qualification = request.form.get('qualification')
        practice_location = request.form.get('practice_location')
        specialty = request.form.get('specialty')
        
        # Get certifications as a list
        certifications = request.form.getlist('certifications[]')
        
        # Process credentials file if uploaded
        credentials_url = None
        if 'credentials' in request.files:
            credentials_file = request.files['credentials']
            if credentials_file.filename:
                # Check if it's an allowed file type
                allowed_extensions = {'.pdf', '.jpg', '.jpeg', '.png'}
                if any(credentials_file.filename.lower().endswith(ext) for ext in allowed_extensions):
                    # Create a safe filename
                    filename = secure_filename(credentials_file.filename)
                    
                    # Make sure the upload directory exists
                    os.makedirs('static/uploads/credentials', exist_ok=True)
                    
                    # Generate a unique filename to avoid collisions
                    unique_filename = f"{doctor.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                    file_path = os.path.join('static/uploads/credentials', unique_filename)
                    
                    # Save the file
                    credentials_file.save(file_path)
                    credentials_url = f"/static/uploads/credentials/{unique_filename}"
                else:
                    flash('Credentials must be in PDF, JPG, or PNG format.', 'danger')
                    return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
        # Update doctor record with verification information
        doctor.medical_license_number = medical_license_number
        doctor.aadhaar_number = aadhaar_number
        doctor.qualification = qualification
        doctor.practice_location = practice_location
        doctor.specialty = specialty
        doctor.certifications = certifications
        
        if credentials_url:
            doctor.credentials_url = credentials_url
        
        # Set verification status to pending and record the date
        doctor.verification_status = 'pending'
        doctor.verification_date = datetime.now()
        
        # Save changes
        db.session.commit()
        
        # In a real application, we would also create a VerificationEvent
        # to track this submission in the timeline
        
        # Send notification to admin (in a real application)
        # send_email(
        #     subject="New Doctor Verification Request",
        #     recipients=["admin@antidote.com"],
        #     template=render_template('emails/new_verification_request.html', doctor=doctor)
        # )
        
        flash('Your verification documents have been submitted and are pending review.', 'success')
        return redirect(url_for('web.doctor_verification', doctor_id=doctor.id))
        
    except Exception as e:
        logger.error(f"Error submitting verification: {str(e)}")
        flash(f'Error submitting verification: {str(e)}', 'danger')
        return redirect(url_for('web.doctor_verification', doctor_id=doctor_id))

@web.route('/admin/doctor-verification-requests')
@login_required
@admin_required
def admin_doctor_verification_requests():
    """Admin view of all doctor verification requests."""
    try:
        # Get all pending verification requests
        pending_verifications = Doctor.query.filter_by(verification_status='pending').all()
        
        # Get all approved and rejected verifications from the last 30 days
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_verifications = Doctor.query.filter(
            Doctor.verification_status.in_(['approved', 'rejected']),
            Doctor.verification_date >= thirty_days_ago
        ).all()
        
        return render_template('admin/verification_requests.html',
                              pending_verifications=pending_verifications,
                              recent_verifications=recent_verifications)
    except Exception as e:
        logger.error(f"Error rendering admin verifications: {str(e)}")
        return render_template('admin/verification_requests.html',
                              error=str(e),
                              pending_verifications=[],
                              recent_verifications=[])

@web.route('/admin/doctor/<int:doctor_id>/verification/approve', methods=['POST'])
@login_required
@admin_required
def approve_doctor_verification(doctor_id):
    """Approve a doctor's verification request."""
    try:
        doctor = Doctor.query.get_or_404(doctor_id)
        
        if doctor.verification_status != 'pending':
            flash('This doctor is not pending verification.', 'danger')
            return redirect(url_for('web.admin_doctor_verification_requests'))
        
        # Approve the doctor
        doctor.verification_status = 'approved'
        doctor.verification_date = datetime.now()
        doctor.verification_notes = request.form.get('notes', 'Verification approved')
        
        db.session.commit()
        
        # In a real application, we would also create a VerificationEvent
        # to track this approval in the timeline
        
        # Send notification to the doctor (in a real application)
        # send_email(
        #     subject="Verification Approved",
        #     recipients=[doctor.user.email],
        #     template=render_template('emails/verification_approved.html', doctor=doctor)
        # )
        
        flash(f'Doctor {doctor.name} has been approved.', 'success')
        return redirect(url_for('web.admin_doctor_verification_requests'))
        
    except Exception as e:
        logger.error(f"Error approving doctor: {str(e)}")
        flash(f'Error approving doctor: {str(e)}', 'danger')
        return redirect(url_for('web.admin_doctor_verification_requests'))

@web.route('/admin/doctor/<int:doctor_id>/verification/reject', methods=['POST'])
@login_required
@admin_required
def reject_doctor_verification(doctor_id):
    """Reject a doctor's verification request."""
    try:
        doctor = Doctor.query.get_or_404(doctor_id)
        
        if doctor.verification_status != 'pending':
            flash('This doctor is not pending verification.', 'danger')
            return redirect(url_for('web.admin_doctor_verification_requests'))
        
        # Get rejection reason
        reason = request.form.get('reason')
        if not reason:
            flash('Rejection reason is required.', 'danger')
            return redirect(url_for('web.admin_doctor_verification_requests'))
        
        # Reject the doctor
        doctor.verification_status = 'rejected'
        doctor.verification_date = datetime.now()
        doctor.verification_notes = reason
        
        db.session.commit()
        
        # In a real application, we would also create a VerificationEvent
        # to track this rejection in the timeline
        
        # Send notification to the doctor (in a real application)
        # send_email(
        #     subject="Verification Rejected",
        #     recipients=[doctor.user.email],
        #     template=render_template('emails/verification_rejected.html', doctor=doctor, reason=reason)
        # )
        
        flash(f'Doctor {doctor.name} has been rejected.', 'success')
        return redirect(url_for('web.admin_doctor_verification_requests'))
        
    except Exception as e:
        logger.error(f"Error rejecting doctor: {str(e)}")
        flash(f'Error rejecting doctor: {str(e)}', 'danger')
        return redirect(url_for('web.admin_doctor_verification_requests'))

@web.route('/clinic/<int:clinic_id>')
def clinic_profile_direct(clinic_id):
    """Direct clinic profile route for viewing clinic details with Google Reviews."""
    try:
        # Get clinic by ID using ORM to properly access all fields
        from models import Clinic
        clinic = Clinic.query.filter_by(id=clinic_id, is_approved=True).first()
        
        if not clinic:
            flash('Clinic not found or not approved.', 'error')
            return redirect(url_for('web.index'))
        
        # Update view count
        clinic.view_count = (clinic.view_count or 0) + 1
        db.session.commit()
        
        return render_template('clinic_profile.html', clinic=clinic)
                             
    except Exception as e:
        logger.error(f"Error loading clinic profile {clinic_id}: {e}")
        flash('Clinic not found.', 'error')
        return redirect(url_for('web.index'))

@web.route('/dashboard/community')
def community_dashboard():
    """Render the community dashboard with analytics."""
    try:
        logger.info("Entering community_dashboard route")
        # Current time for display
        now = datetime.now()
        logger.info("Set current time: %s", now)
        
        # Get the 10 most recent threads
        logger.info("Fetching recent threads")
        threads = Community.query.order_by(Community.created_at.desc()).limit(10).all()
        logger.info("Found %d recent threads", len(threads))
        
        # Get stats for the dashboard
        thread_count = Community.query.count()
        reply_count = CommunityReply.query.count()
        logger.info("Thread count: %d, Reply count: %d", thread_count, reply_count)
        
        # Calculate activity statistics
        thirty_days_ago = now - timedelta(days=30)
        recent_threads = Community.query.filter(Community.created_at >= thirty_days_ago).count()
        logger.info("Recent threads (last 30 days): %d", recent_threads)
        recent_replies = CommunityReply.query.filter(CommunityReply.created_at >= thirty_days_ago).count()
        
        # Add user data to threads
        for thread in threads:
            if thread.user_id:
                thread.user = User.query.get(thread.user_id)
            else:
                thread.user = None
                
            # Get category and procedure if they exist
            if thread.category_id:
                thread.category = Category.query.get(thread.category_id)
            if thread.procedure_id:
                thread.procedure = Procedure.query.get(thread.procedure_id)
        
        # Get analytics data - trending topics and body part distribution
        # First check if we have Thread data
        has_thread_data = Thread.query.count() > 0
        
        if has_thread_data:
            # Get trending topics
            all_keywords = []
            threads_with_keywords = Thread.query.filter(Thread.keywords.isnot(None)).all()
            
            for thread in threads_with_keywords:
                if thread.keywords:
                    all_keywords.extend(thread.keywords)
            
            # Count keyword frequency
            keyword_counts = {}
            for keyword in all_keywords:
                if keyword in keyword_counts:
                    keyword_counts[keyword] += 1
                else:
                    keyword_counts[keyword] = 1
            
            # Sort keywords by frequency
            sorted_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Format trending topics for the template and Chart.js (top 3)
            formatted_trending_topics = [{'topic': topic, 'count': count} for topic, count in sorted_keywords[:3]] if sorted_keywords else []
            
            # Get body part distribution
            body_parts = {}
            for thread in Thread.query.all():
                if thread.procedure_id:
                    procedure = Procedure.query.get(thread.procedure_id)
                    if procedure and procedure.body_part:
                        if procedure.body_part in body_parts:
                            body_parts[procedure.body_part] += 1
                        else:
                            body_parts[procedure.body_part] = 1
            
            # Sort by count descending and format for Chart.js
            sorted_body_parts = sorted(body_parts.items(), key=lambda x: x[1], reverse=True)
            formatted_body_part_distribution = [{'body_part': body_part, 'count': count} for body_part, count in sorted_body_parts]
            
            # Get all categories for filtering
            categories = Category.query.all()
            
            # Get all unique body parts
            all_body_parts = sorted(list(set([p.body_part for p in Procedure.query.filter(
                Procedure.body_part.isnot(None)).all() if p.body_part])))
        else:
            # No Thread data, set empty values
            formatted_trending_topics = []
            formatted_body_part_distribution = []
            categories = []
            all_body_parts = []
        
        # Calculate avg engagement and active users
        avg_engagement = round(reply_count / thread_count, 1) if thread_count and thread_count > 0 else 0
        
        # Get unique users who have posted threads or replies in the last 30 days
        thread_user_ids = [t.user_id for t in Community.query.filter(Community.created_at >= thirty_days_ago).all() if t.user_id]
        reply_user_ids = [r.user_id for r in CommunityReply.query.filter(CommunityReply.created_at >= thirty_days_ago).all() if r.user_id]
        active_users = len(set(thread_user_ids + reply_user_ids))
        
        return render_template(
            'dashboard_community.html',
            threads=threads,
            thread_count=thread_count,
            reply_count=reply_count,
            recent_threads=recent_threads,
            recent_replies=recent_replies,
            trending_topics=formatted_trending_topics,
            body_part_distribution=formatted_body_part_distribution,
            categories=categories,
            all_body_parts=all_body_parts,
            avg_engagement=avg_engagement,
            active_users=active_users,
            now=now,
            last_updated=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        )
    except Exception as e:
        logger.error(f"Error rendering community dashboard: {str(e)}")
        # Add now for the timestamp in the template
        now = datetime.now()
        return render_template(
            'dashboard_community.html', 
            threads=[], 
            thread_count=0,
            reply_count=0,
            recent_threads=0,
            recent_replies=0,
            trending_topics=[],
            body_part_distribution=[],
            categories=[],
            all_body_parts=[],
            avg_engagement=0,
            active_users=0,
            now=now,
            error=str(e)
        )

@api.route('/community/trends', methods=['GET'])
def api_community_trends():
    """Return current community analytics data in JSON format for real-time updates."""
    try:
        # Get stats for the analytics dashboard
        thread_count = Thread.query.count()
        total_views = db.session.query(func.sum(Thread.view_count)).scalar() or 0
        total_replies = db.session.query(func.sum(Thread.reply_count)).scalar() or 0
        
        # Get top trending keywords
        # Extract all keywords from threads and count their frequency
        all_keywords = []
        threads_with_keywords = Thread.query.filter(Thread.keywords.isnot(None)).all()
        
        for thread in threads_with_keywords:
            if thread.keywords:
                all_keywords.extend(thread.keywords)
        
        # Count keyword frequency
        keyword_counts = {}
        for keyword in all_keywords:
            if keyword in keyword_counts:
                keyword_counts[keyword] += 1
            else:
                keyword_counts[keyword] = 1
        
        # Sort keywords by frequency
        sorted_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)
        trending_topics = sorted_keywords[:10] if sorted_keywords else []
        
        # Get body part distribution
        body_parts = {}
        for thread in Thread.query.all():
            if thread.procedure_id:
                procedure = Procedure.query.get(thread.procedure_id)
                if procedure and procedure.body_part:
                    if procedure.body_part in body_parts:
                        body_parts[procedure.body_part] += 1
                    else:
                        body_parts[procedure.body_part] = 1
        
        # Sort body parts by frequency
        sorted_body_parts = sorted(body_parts.items(), key=lambda x: x[1], reverse=True)
        body_part_distribution = sorted_body_parts if sorted_body_parts else []
        
        # Return the data as JSON for real-time updates
        return jsonify({
            'success': True,
            'data': {
                'stats': {
                    'thread_count': thread_count,
                    'total_views': total_views,
                    'total_replies': total_replies
                },
                'trending_topics': [
                    {'topic': topic, 'count': count} for topic, count in trending_topics[:3]
                ],
                'trending_topics_full': [
                    {'topic': topic, 'count': count} for topic, count in trending_topics
                ],
                'body_part_distribution': [
                    {'body_part': body_part, 'count': count} for body_part, count in body_part_distribution
                ],
                'last_updated': datetime.utcnow().isoformat()
            }
        }), 200
    except Exception as e:
        logger.error(f"Error getting community trends data: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching community trends data'
        }), 500

@web.route('/community/new', methods=['GET', 'POST'])
@login_required
def create_community_thread():
    """Create a new community thread."""
    try:
        if request.method == 'POST':
            # Extract form data
            title = request.form.get('title')
            content = request.form.get('content')
            procedure_id = request.form.get('procedure_id')
            
            # Validate required fields
            if not title or not content:
                flash('Title and content are required.', 'danger')
                return redirect(url_for('web.create_community_thread'))
            
            # Create new thread
            new_thread = Thread(
                title=title,
                content=content,
                user_id=session['user_id'],
                procedure_id=procedure_id if procedure_id else None,
                created_at=datetime.utcnow(),
                view_count=0,
                reply_count=0
            )
            
            # Extract keywords from title and content for analytics
            keywords = []
            
            # Simple keyword extraction from title (split by spaces and filter)
            title_words = [word.lower() for word in title.split() if len(word) > 3]
            keywords.extend(title_words)
            
            # Simple keyword extraction from content (split by spaces and filter)
            content_words = [word.lower() for word in content.split() if len(word) > 3]
            # Take top 5 most common words from content
            from collections import Counter
            word_counts = Counter(content_words)
            keywords.extend([word for word, _ in word_counts.most_common(5)])
            
            # Filter out duplicates and limit to 10 keywords
            new_thread.keywords = list(set(keywords))[:10]
            
            # Save to database
            db.session.add(new_thread)
            db.session.commit()
            
            flash('Thread created successfully!', 'success')
            return redirect(url_for('web.community_thread_detail', thread_id=new_thread.id))
        
        # GET request - render the form
        # Get all procedures for dropdown
        procedures = Procedure.query.all()
        
        return render_template(
            'new_thread.html',
            procedures=procedures
        )
    except Exception as e:
        logger.error(f"Error creating new thread: {str(e)}")
        flash('An error occurred while creating the thread.', 'danger')
        return redirect(url_for('web.community'))

@web.route('/community/analytics')
def community_analytics_dashboard():
    """Render the community analytics dashboard with insights from Thread model."""
    try:
        # Get the 5 most recent threads from the new Thread model
        threads = Thread.query.order_by(Thread.created_at.desc()).limit(5).all()
        
        # Get stats for the analytics dashboard
        thread_count = Thread.query.count()
        total_views = db.session.query(func.sum(Thread.view_count)).scalar() or 0
        total_replies = db.session.query(func.sum(Thread.reply_count)).scalar() or 0
        
        # Get top trending keywords
        # Extract all keywords from threads and count their frequency
        all_keywords = []
        threads_with_keywords = Thread.query.filter(Thread.keywords.isnot(None)).all()
        
        for thread in threads_with_keywords:
            if thread.keywords:
                all_keywords.extend(thread.keywords)
        
        # Count keyword frequency
        keyword_counts = {}
        for keyword in all_keywords:
            if keyword in keyword_counts:
                keyword_counts[keyword] += 1
            else:
                keyword_counts[keyword] = 1
        
        # Sort keywords by frequency
        sorted_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)
        trending_topics = sorted_keywords[:3] if sorted_keywords else []
        trending_topics_full = sorted_keywords[:10] if sorted_keywords else []
        
        # Get body part distribution
        body_parts = {}
        for thread in Thread.query.all():
            if thread.procedure_id:
                procedure = Procedure.query.get(thread.procedure_id)
                if procedure and procedure.body_part:
                    if procedure.body_part in body_parts:
                        body_parts[procedure.body_part] += 1
                    else:
                        body_parts[procedure.body_part] = 1
        
        # Sort body parts by frequency
        sorted_body_parts = sorted(body_parts.items(), key=lambda x: x[1], reverse=True)
        body_part_distribution = sorted_body_parts[:5] if sorted_body_parts else []
        
        # Add procedure and user data to threads
        for thread in threads:
            if thread.procedure_id:
                thread.procedure = Procedure.query.get(thread.procedure_id)
            else:
                thread.procedure = None
                
            if thread.user_id:
                thread.user = User.query.get(thread.user_id)
            else:
                thread.user = None
        
        # Get all categories for filter
        categories = Category.query.all()
        
        # Get all unique body parts for the body part filter
        all_body_parts = [body_part for body_part, _ in sorted_body_parts]
        
        # Add current time for the template
        now = datetime.now()
        # Calculate average engagement and active users
        avg_engagement = round(total_replies / thread_count, 1) if thread_count and thread_count > 0 else 0
        
        # Get unique users who have posted threads in the last 30 days
        thirty_days_ago = now - timedelta(days=30)
        thread_user_ids = [t.user_id for t in Thread.query.filter(Thread.created_at >= thirty_days_ago).all() if t.user_id]
        active_users = len(set(thread_user_ids))
        
        return render_template(
            'dashboard_community.html',
            threads=threads,
            thread_count=thread_count,
            total_views=total_views,
            total_replies=total_replies,
            trending_topics=trending_topics,
            trending_topics_full=trending_topics_full,
            body_part_distribution=body_part_distribution,
            categories=categories,
            all_body_parts=all_body_parts,
            avg_engagement=avg_engagement,
            active_users=active_users,
            now=now,
            last_updated=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        )
    except Exception as e:
        logger.error(f"Error rendering community analytics dashboard: {str(e)}")
        # Add now for the timestamp in the template
        now = datetime.now()
        return render_template(
            'dashboard_community.html', 
            threads=[],
            thread_count=0,
            total_views=0,
            total_replies=0,
            trending_topics=[],
            body_part_distribution=[],
            categories=[],
            all_body_parts=[],
            avg_engagement=0,
            active_users=0, 
            now=now,
            error=str(e)
        )

# Doctor verification routes
@web.route('/dashboard/doctor/verify', methods=['GET', 'POST'])
@login_required
@doctor_required
def doctor_verify():
    """Handle doctor verification submission."""
    try:
        logger.debug("Doctor verification page accessed")
        
        # Handle form submission
        if request.method == 'POST':
            # Get form data
            license_number = request.form['medical_license_number']
            qualification = request.form['qualification']
            practice_location = request.form['practice_location']
            aadhaar_number = request.form.get('aadhaar_number', '')
            
            # Validate MCI license format (example: MCI-12345-YYYY)
            if not (license_number.startswith('MCI-') and len(license_number.split('-')) == 3):
                flash('Invalid medical license number format. Format should be MCI-XXXXX-YYYY', 'danger')
                return redirect(url_for('web.doctor_verify'))
            
            # Get the user ID from session
            user_id = session.get('user_id', 1)  # Default user for testing
            
            # Check if user already has a doctor profile
            existing_doctor = Doctor.query.filter_by(user_id=user_id).first()
            
            if existing_doctor:
                # Update existing doctor profile
                existing_doctor.medical_license_number = license_number
                existing_doctor.qualification = qualification
                existing_doctor.practice_location = practice_location
                existing_doctor.verification_status = 'pending'
                existing_doctor.aadhaar_number = aadhaar_number
                
                # Handle credentials file upload
                if 'credentials' in request.files:
                    file = request.files['credentials']
                    if file and file.filename:
                        filename = secure_filename(f"{user_id}_{license_number}_{file.filename}")
                        file_path = os.path.join('static/doctor_credentials', filename)
                        os.makedirs('static/doctor_credentials', exist_ok=True)
                        file.save(file_path)
                        existing_doctor.credentials_url = filename
                
                db.session.commit()
                logger.debug(f"Doctor verification updated for user ID: {user_id}")
                flash('Your verification details have been updated and are pending review.', 'success')
            else:
                # Create new doctor profile
                user = User.query.get(user_id)
                if not user:
                    flash('User not found.', 'danger')
                    return redirect(url_for('web.index'))
                    
                # Create a new doctor profile
                new_doctor = Doctor(
                    user_id=user_id,
                    name=user.name,
                    specialty='',  # Will be filled in during approval
                    experience=0,  # Will be filled in during approval
                    city='',       # Will be filled in during approval
                    state='',      # Will be filled in during approval
                    hospital='',   # Will be filled in during approval
                    medical_license_number=license_number,
                    qualification=qualification,
                    practice_location=practice_location,
                    verification_status='pending',
                    aadhaar_number=aadhaar_number
                )
                
                # Handle credentials file upload
                if 'credentials' in request.files:
                    file = request.files['credentials']
                    if file and file.filename:
                        filename = secure_filename(f"{user_id}_{license_number}_{file.filename}")
                        file_path = os.path.join('static/doctor_credentials', filename)
                        os.makedirs('static/doctor_credentials', exist_ok=True)
                        file.save(file_path)
                        new_doctor.credentials_url = filename
                
                db.session.add(new_doctor)
                db.session.commit()
                logger.debug(f"New doctor verification submitted for user ID: {user_id}")
                flash('Your verification request has been submitted and is pending review.', 'success')
            
            # Redirect to doctor dashboard
            return redirect(url_for('web.doctor_dashboard', doctor_id=user_id))
        
        # Get the current user's doctor profile if it exists
        user_id = session.get('user_id', 1)  # Default user for testing
        doctor = Doctor.query.filter_by(user_id=user_id).first()
        
        return render_template('doctor_verification.html', doctor=doctor)
        
    except Exception as e:
        logger.error(f"Error in doctor verification: {str(e)}")
        flash('An error occurred while processing your request. Please try again.', 'danger')
        return redirect(url_for('web.index'))

@web.route('/dashboard/admin/doctor-verifications')
@login_required
@admin_required
def admin_dashboard_doctor_verifications():
    """Admin view of all doctor verification requests."""
    try:
        logger.debug("Admin doctor verifications page accessed")
        
        # Get query parameters for filtering
        status = request.args.get('status', 'pending')
        location = request.args.get('location', '')
        
        # Query doctors based on filters
        query = Doctor.query
        
        if status:
            query = query.filter(Doctor.verification_status == status)
        
        if location:
            query = query.filter(Doctor.practice_location.ilike(f'%{location}%'))
            
        doctors = query.all()
        
        return render_template('admin_doctor_verifications.html', doctors=doctors, status=status, location=location)
        
    except Exception as e:
        logger.error(f"Error in admin doctor verifications: {str(e)}")
        flash('An error occurred while fetching doctor verification requests.', 'danger')
        return redirect(url_for('admin_credit.credit_dashboard'))

@web.route('/api/doctor/<int:doctor_id>/approve', methods=['POST'])
@login_required
@admin_required
def api_approve_doctor(doctor_id):
    """Approve a doctor's verification request via API."""
    try:
        doctor = Doctor.query.get_or_404(doctor_id)
        doctor.verification_status = 'approved'
        doctor.is_verified = True
        db.session.commit()
        
        # Create notification for doctor
        user_id = doctor.user_id
        notification = Notification(
            user_id=user_id,
            message='Your doctor verification has been approved. You can now use all doctor features.',
            type='verification'
        )
        db.session.add(notification)
        db.session.commit()
        
        logger.debug(f"Doctor ID {doctor_id} has been approved")
        return jsonify({'status': 'success', 'message': 'Doctor has been approved'})
        
    except Exception as e:
        logger.error(f"Error approving doctor: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An error occurred while approving the doctor'})

@web.route('/api/doctor/<int:doctor_id>/reject', methods=['POST'])
@login_required
@admin_required
def api_reject_doctor(doctor_id):
    """Reject a doctor's verification request."""
    try:
        doctor = Doctor.query.get_or_404(doctor_id)
        reason = request.json.get('reason', 'Your verification request was rejected.')
        doctor.verification_status = 'rejected'
        db.session.commit()
        
        # Create notification for doctor
        user_id = doctor.user_id
        notification = Notification(
            user_id=user_id,
            message=f'Your doctor verification was rejected. Reason: {reason}',
            type='verification'
        )
        db.session.add(notification)
        db.session.commit()
        
        logger.debug(f"Doctor ID {doctor_id} has been rejected. Reason: {reason}")
        return jsonify({'status': 'success', 'message': 'Doctor has been rejected'})
        
    except Exception as e:
        logger.error(f"Error rejecting doctor: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An error occurred while rejecting the doctor'})

@web.route('/dashboard/procedures')
@login_required
@admin_required
def procedures_dashboard():
    """Admin dashboard for procedures."""
    try:
        # Get all procedures
        procedures = Procedure.query.all()
        
        # Get all body parts and categories for filters
        body_parts = BodyPart.query.all()
        categories = Category.query.all()
        
        return render_template(
            'dashboard_procedures.html',
            procedures=procedures,
            body_parts=body_parts,
            categories=categories
        )
    except Exception as e:
        logger.error(f"Error in procedures dashboard: {str(e)}")
        flash('An error occurred while loading the procedures dashboard.', 'danger')
        return redirect(url_for('admin_credit.credit_dashboard'))

@web.route('/admin/procedures/delete/<int:procedure_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_procedure(procedure_id):
    """Delete a procedure from the admin dashboard."""
    try:
        procedure = Procedure.query.get_or_404(procedure_id)
        logger.info(f"Deleting procedure: ID={procedure.id}, Name={procedure.procedure_name}")
        
        # Delete related records (reviews, leads, etc.) if necessary
        # This depends on the database relationships and constraints
        
        db.session.delete(procedure)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Procedure "{procedure.procedure_name}" deleted successfully'
        })
    except Exception as e:
        logger.error(f"Error deleting procedure {procedure_id}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error deleting procedure: {str(e)}'
        }), 500

@web.route('/admin/procedures/edit/<int:procedure_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_procedure(procedure_id):
    """Edit a procedure from the admin dashboard."""
    try:
        procedure = Procedure.query.get_or_404(procedure_id)
        
        if request.method == 'POST':
            # Update procedure details from form data
            procedure.procedure_name = request.form.get('procedure_name', procedure.procedure_name)
            procedure.description = request.form.get('description', procedure.description)
            
            # Parse numeric values with error handling
            try:
                if request.form.get('min_cost'):
                    procedure.min_cost = float(request.form.get('min_cost'))
                if request.form.get('max_cost'):
                    procedure.max_cost = float(request.form.get('max_cost'))
            except ValueError:
                flash('Invalid cost values provided', 'danger')
            
            # Handle category update
            category_id = request.form.get('category_id')
            if category_id and category_id.isdigit():
                procedure.category_id = int(category_id)
            
            # Handle body part update
            body_part_id = request.form.get('body_part_id')
            if body_part_id and body_part_id.isdigit():
                procedure.body_part_id = int(body_part_id)
            
            # Handle image upload
            if 'image' in request.files and request.files['image'].filename:
                file = request.files['image']
                filename = secure_filename(file.filename)
                os.makedirs('static/procedures', exist_ok=True)
                file_path = os.path.join('static/procedures', filename)
                file.save(file_path)
                procedure.image_url = filename
            
            procedure.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash(f'Procedure "{procedure.procedure_name}" updated successfully', 'success')
            return redirect(url_for('admin_credit.credit_dashboard'))
        
        # Get categories and body parts for the form
        categories = Category.query.all()
        body_parts = BodyPart.query.all()
        
        return render_template(
            'admin/edit_procedure.html', 
            procedure=procedure,
            categories=categories,
            body_parts=body_parts
        )
    except Exception as e:
        logger.error(f"Error editing procedure {procedure_id}: {str(e)}")
        flash(f'Error editing procedure: {str(e)}', 'danger')
        return redirect(url_for('admin_credit.credit_dashboard'))

# Admin dashboard route moved to admin_credit_system.py to avoid conflicts

@web.route('/admin/allocate-credits', methods=['POST'])
@login_required
@admin_required
def allocate_credits():
    """Allocate credits to a clinic manually."""
    try:
        clinic_id = request.form.get('clinic_id', type=int)
        credits = request.form.get('credits', type=int)
        description = request.form.get('description', '')
        
        if not clinic_id or not credits or credits <= 0:
            flash('Invalid clinic or credit amount', 'danger')
            return redirect(url_for('admin_credit.credit_dashboard'))
        
        # Update clinic balance
        db.session.execute(text("""
            UPDATE clinics 
            SET credit_balance = credit_balance + :credits,
                total_credits_purchased = total_credits_purchased + :credits
            WHERE id = :clinic_id
        """), {
            'credits': credits,
            'clinic_id': clinic_id
        })
        
        # Record transaction
        db.session.execute(text("""
            INSERT INTO credit_transactions 
            (clinic_id, amount, transaction_type, description, created_by, created_at)
            VALUES (:clinic_id, :amount, 'manual_allocation', :description, :admin_id, NOW())
        """), {
            'clinic_id': clinic_id,
            'amount': credits,
            'description': description or f'Manual credit allocation by admin',
            'admin_id': current_user.id
        })
        
        db.session.commit()
        
        # Get clinic name for success message
        clinic = db.session.execute(text("""
            SELECT name FROM clinics WHERE id = :clinic_id
        """), {'clinic_id': clinic_id}).fetchone()
        
        clinic_name = clinic[0] if clinic else f'Clinic #{clinic_id}'
        flash(f'Successfully allocated {credits} credits to {clinic_name}', 'success')
        
    except Exception as e:
        logger.error(f"Error allocating credits: {str(e)}")
        db.session.rollback()
        flash(f'Error allocating credits: {str(e)}', 'danger')
    
    return redirect(url_for('admin_credit.credit_dashboard'))

# Admin transaction history functionality consolidated into single implementation above

@web.route('/admin/lead-analytics')
@login_required
@admin_required
def admin_lead_analytics():
    """Comprehensive lead analytics dashboard."""
    
    try:
        from datetime import datetime, timedelta
        
        # Get filter parameters with safe defaults
        clinic_id = request.args.get('clinic_id')
        if clinic_id:
            try:
                clinic_id = int(clinic_id)
            except (ValueError, TypeError):
                clinic_id = None
                
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        days = request.args.get('days', '30')
        
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 30
        
        # Parse dates safely
        parsed_start_date = None
        parsed_end_date = None
        
        if start_date:
            try:
                parsed_start_date = datetime.strptime(start_date, '%Y-%m-%d')
            except (ValueError, TypeError):
                pass
                
        if end_date:
            try:
                parsed_end_date = datetime.strptime(end_date, '%Y-%m-%d')
            except (ValueError, TypeError):
                pass
        
        # Set default date range if no valid dates provided
        if not parsed_start_date and not parsed_end_date:
            parsed_end_date = datetime.now()
            parsed_start_date = parsed_end_date - timedelta(days=days)
        
        # Simple lead query to avoid complex joins causing issues
        base_query = """
            SELECT 
                l.*,
                COALESCE(c.name, 'Unknown Clinic') as clinic_name
            FROM leads l
            LEFT JOIN clinics c ON l.clinic_id = c.id
            WHERE l.created_at >= %s AND l.created_at <= %s
        """
        
        query_params = [parsed_start_date, parsed_end_date]
        
        if clinic_id:
            base_query += " AND l.clinic_id = %s"
            query_params.append(clinic_id)
            
        base_query += " ORDER BY l.created_at DESC LIMIT 500"
        
        # Execute with raw connection to avoid SQLAlchemy issues
        import psycopg2
        import os
        
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        cursor = conn.cursor()
        
        cursor.execute(base_query, query_params)
        raw_leads = cursor.fetchall()
        
        # Get column names
        column_names = [desc[0] for desc in cursor.description]
        
        # Convert to dictionaries and add calculated fields
        leads = []
        for row in raw_leads:
            lead_dict = dict(zip(column_names, row))
            
            # Add calculated fields that the template expects
            if lead_dict.get('converted_at') is not None:
                lead_dict['lead_stage'] = 'converted'
            elif lead_dict.get('contacted_at') is not None:
                lead_dict['lead_stage'] = 'contacted'
            else:
                lead_dict['lead_stage'] = 'pending'
                
            # Calculate hours to conversion if applicable
            if lead_dict.get('converted_at') is not None and lead_dict.get('created_at') is not None:
                try:
                    from datetime import datetime
                    converted_time = lead_dict['converted_at'] if isinstance(lead_dict['converted_at'], datetime) else lead_dict['converted_at']
                    created_time = lead_dict['created_at'] if isinstance(lead_dict['created_at'], datetime) else lead_dict['created_at']
                    time_diff = converted_time - created_time
                    lead_dict['hours_to_conversion'] = round(time_diff.total_seconds() / 3600, 2)
                except:
                    lead_dict['hours_to_conversion'] = None
            else:
                lead_dict['hours_to_conversion'] = None
                
            leads.append(lead_dict)
        
        # Get all clinics for filter dropdown
        cursor.execute("SELECT id, name FROM clinics WHERE is_approved = true ORDER BY name")
        clinic_rows = cursor.fetchall()
        clinics = [{'id': row[0], 'name': row[1]} for row in clinic_rows]
        
        cursor.close()
        conn.close()
        
        # Calculate analytics safely
        total_leads = len(leads)
        contacted_leads = 0
        converted_leads = 0
        total_revenue = 0
        total_credits_spent = 0
        
        for lead in leads:
            # Safe None checks
            if lead.get('contacted_at') is not None:
                contacted_leads += 1
            if lead.get('converted_at') is not None:
                converted_leads += 1
            if lead.get('conversion_value') is not None:
                total_revenue += float(lead['conversion_value'] or 0)
            if lead.get('credit_cost') is not None:
                total_credits_spent += int(lead['credit_cost'] or 0)
        
        # Calculate metrics with safe division
        contact_rate = (contacted_leads * 100.0 / total_leads) if total_leads > 0 else 0.0
        conversion_rate = (converted_leads * 100.0 / total_leads) if total_leads > 0 else 0.0
        roi = ((total_revenue - total_credits_spent) * 100.0 / total_credits_spent) if total_credits_spent > 0 else 0.0
        avg_lead_value = (total_revenue / converted_leads) if converted_leads > 0 else 0.0
        
        analytics = {
            'total_leads': total_leads,
            'contacted_leads': contacted_leads,
            'converted_leads': converted_leads,
            'total_revenue': round(total_revenue, 2),
            'total_credits_spent': total_credits_spent,
            'contact_rate': round(contact_rate, 2),
            'conversion_rate': round(conversion_rate, 2),
            'roi': round(roi, 2),
            'avg_lead_value': round(avg_lead_value, 2)
        }
        
        # Empty clinic metrics for now to avoid complex query issues
        clinic_metrics = []
        
        return render_template('admin/lead_analytics.html',
                              leads=leads,
                              clinic_metrics=clinic_metrics,
                              clinics=clinics,
                              analytics=analytics,
                              selected_clinic=clinic_id,
                              start_date=parsed_start_date.strftime('%Y-%m-%d') if parsed_start_date else '',
                              end_date=parsed_end_date.strftime('%Y-%m-%d') if parsed_end_date else '',
                              days=days)
                              
    except Exception as e:
        logger.error(f"Error loading lead analytics: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash('Error loading lead analytics dashboard', 'danger')
        return redirect(url_for('admin_credit.credit_dashboard'))

@web.route('/dashboard/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard with integrated credit management."""
    logger.info(f"Admin dashboard accessed by user: {current_user.email}")
    
    # Get comprehensive dashboard data
    try:
        # Get clinic statistics with credit balances
        clinics_result = db.session.execute(text("""
            SELECT c.*, 
                   COALESCE(SUM(CASE WHEN ct.amount > 0 THEN ct.amount ELSE ct.amount END), 0) as credit_balance,
                   COALESCE(SUM(CASE WHEN ct.amount > 0 THEN ct.amount ELSE 0 END), 0) as total_purchased,
                   COALESCE(SUM(CASE WHEN ct.amount < 0 THEN ABS(ct.amount) ELSE 0 END), 0) as total_used,
                   COUNT(DISTINCT l.id) as total_leads
            FROM clinics c
            LEFT JOIN credit_transactions ct ON c.id = ct.clinic_id
            LEFT JOIN leads l ON c.id = l.clinic_id
            GROUP BY c.id, c.name, c.email, c.phone_number, c.address, c.is_verified, c.created_at
            ORDER BY c.created_at DESC
        """))
        clinics = [dict(row._mapping) for row in clinics_result.fetchall()]
        
        # Get comprehensive system statistics
        total_users = db.session.execute(text("SELECT COUNT(*) as count FROM users")).scalar()
        total_procedures = db.session.execute(text("SELECT COUNT(*) as count FROM procedures")).scalar()
        
        stats_result = db.session.execute(text("""
            SELECT 
                COUNT(DISTINCT c.id) as total_clinics,
                COUNT(DISTINCT l.id) as total_leads,
                COALESCE(SUM(CASE WHEN ct.amount > 0 THEN ct.amount ELSE 0 END), 0) as total_credits,
                COUNT(DISTINCT CASE WHEN l.created_at >= NOW() - INTERVAL '7 days' THEN l.id END) as leads_this_week,
                COUNT(DISTINCT CASE WHEN c.is_verified = true THEN c.id END) as active_clinics
            FROM clinics c
            LEFT JOIN leads l ON c.id = l.clinic_id
            LEFT JOIN credit_transactions ct ON c.id = ct.clinic_id
        """))
        stats_row = stats_result.fetchone()
        stats = dict(stats_row._mapping) if stats_row else {}
        
        # Count low balance clinics
        low_balance_result = db.session.execute(text("""
            SELECT COUNT(DISTINCT c.id) as count
            FROM clinics c
            LEFT JOIN credit_transactions ct ON c.id = ct.clinic_id
            GROUP BY c.id
            HAVING COALESCE(SUM(CASE WHEN ct.transaction_type = 'credit' THEN ct.amount ELSE -ct.amount END), 0) <= 100
        """))
        low_balance_count = low_balance_result.scalar() or 0
        stats['low_balance_clinics'] = low_balance_count
        
        # Get recent transactions
        recent_transactions_result = db.session.execute(text("""
            SELECT ct.*, c.name as clinic_name
            FROM credit_transactions ct
            LEFT JOIN clinics c ON ct.clinic_id = c.id
            ORDER BY ct.created_at DESC
            LIMIT 10
        """))
        recent_transactions = [dict(row._mapping) for row in recent_transactions_result.fetchall()]
        
        # Lead analytics data
        lead_analytics = {
            'recent_leads': stats.get('leads_this_week', 0)
        }
        
    except Exception as e:
        logger.error(f"Error fetching admin dashboard data: {e}")
        clinics = []
        stats = {}
        recent_transactions = []
        total_users = 0
        total_procedures = 0
        lead_analytics = {'recent_leads': 0}
    
    return render_template('admin/dashboard.html', 
                         clinics=clinics, 
                         stats=stats,
                         recent_transactions=recent_transactions,
                         total_users=total_users,
                         total_clinics=stats.get('total_clinics', 0),
                         total_procedures=total_procedures,
                         total_leads=stats.get('total_leads', 0),
                         lead_analytics=lead_analytics)

@web.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Admin user management page."""
    users = User.query.order_by(User.id).all()
    return render_template('admin/users.html', users=users)

@web.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    """Edit a user from the admin panel."""
    try:
        user = User.query.get_or_404(user_id)
        
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')
        
        # Update user information
        user.username = username
        user.email = email
        user.role = role
        
        # Update password if provided
        if password and password.strip():
            user.password_hash = generate_password_hash(password)
        
        db.session.commit()
        
        flash(f'User "{username}" has been updated successfully.', 'success')
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {str(e)}")
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_users'))

@web.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete a user from the admin panel."""
    try:
        # Don't allow deleting self
        if user_id == current_user.id:
            flash('You cannot delete your own account.', 'danger')
            return redirect(url_for('web.admin_users'))
        
        user = User.query.get_or_404(user_id)
        
        # Store the username for the success message
        username = user.username
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User "{username}" has been deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_users'))

@web.route('/admin/clinic')
@login_required
@admin_required
def admin_clinic():
    """Admin clinic management page."""
    try:
        # Get all clinics with owner information
        clinics_result = db.session.execute(text("""
            SELECT c.*, u.name as owner_name, u.email as owner_email
            FROM clinics c
            LEFT JOIN users u ON c.owner_user_id = u.id
            ORDER BY c.created_at DESC
        """)).fetchall()
        
        clinics = [dict(row._mapping) for row in clinics_result]
        
        return render_template('admin/clinic_management.html', clinics=clinics)
    except Exception as e:
        logger.error(f"Error loading admin clinic management: {e}")
        flash('Error loading clinic management', 'error')
        return redirect(url_for('web.admin_dashboard'))

@web.route('/admin/clinic/<int:clinic_id>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_clinic(clinic_id):
    """Approve a clinic."""
    try:
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        # Update clinic approval status
        db.session.execute(text("""
            UPDATE clinics 
            SET is_approved = true, is_verified = true 
            WHERE id = :clinic_id
        """), {'clinic_id': clinic_id})
        
        db.session.commit()
        
        clinic_dict = dict(clinic_result._mapping)
        flash(f'Clinic "{clinic_dict["name"]}" has been approved successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Error approving clinic {clinic_id}: {e}")
        db.session.rollback()
        flash('Error approving clinic', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_clinic(clinic_id):
    """Reject a clinic application with reason."""
    try:
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        rejection_reason = request.form.get('reason', 'Application does not meet requirements')
        
        # Update clinic rejection status
        db.session.execute(text("""
            UPDATE clinics 
            SET is_approved = false, verification_notes = :reason 
            WHERE id = :clinic_id
        """), {'clinic_id': clinic_id, 'reason': rejection_reason})
        
        db.session.commit()
        
        clinic_dict = dict(clinic_result._mapping)
        flash(f'Clinic "{clinic_dict["name"]}" has been rejected.', 'warning')
        
    except Exception as e:
        logger.error(f"Error rejecting clinic {clinic_id}: {e}")
        db.session.rollback()
        flash('Error rejecting clinic', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/unapprove', methods=['POST'])
@login_required
@admin_required
def admin_unapprove_clinic(clinic_id):
    """Unapprove a clinic (remove from public view)."""
    try:
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        # Update clinic approval status
        db.session.execute(text("""
            UPDATE clinics 
            SET is_approved = false 
            WHERE id = :clinic_id
        """), {'clinic_id': clinic_id})
        
        db.session.commit()
        
        clinic_dict = dict(clinic_result._mapping)
        flash(f'Clinic "{clinic_dict["name"]}" has been unapproved and hidden from public view.', 'warning')
        
    except Exception as e:
        logger.error(f"Error unapproving clinic {clinic_id}: {e}")
        db.session.rollback()
        flash('Error unapproving clinic', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/verify', methods=['POST'])
@login_required
@admin_required
def admin_verify_clinic(clinic_id):
    """Verify a clinic (add verification badge)."""
    try:
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        # Update clinic verification status
        db.session.execute(text("""
            UPDATE clinics 
            SET is_verified = true, verification_date = :now 
            WHERE id = :clinic_id
        """), {'clinic_id': clinic_id, 'now': datetime.utcnow()})
        
        db.session.commit()
        
        clinic_dict = dict(clinic_result._mapping)
        flash(f'Clinic "{clinic_dict["name"]}" has been verified successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Error verifying clinic {clinic_id}: {e}")
        db.session.rollback()
        flash('Error verifying clinic', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/unverify', methods=['POST'])
@login_required
@admin_required
def admin_unverify_clinic(clinic_id):
    """Unverify a clinic (remove verification badge)."""
    try:
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        # Update clinic verification status
        db.session.execute(text("""
            UPDATE clinics 
            SET is_verified = false, verification_date = NULL 
            WHERE id = :clinic_id
        """), {'clinic_id': clinic_id})
        
        db.session.commit()
        
        clinic_dict = dict(clinic_result._mapping)
        flash(f'Clinic "{clinic_dict["name"]}" verification has been removed.', 'info')
        
    except Exception as e:
        logger.error(f"Error unverifying clinic {clinic_id}: {e}")
        db.session.rollback()
        flash('Error unverifying clinic', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/assign-owner', methods=['POST'])
@login_required
@admin_required
def admin_assign_clinic_owner(clinic_id):
    """Assign a clinic to a user (create user if doesn't exist)."""
    try:
        from werkzeug.security import generate_password_hash
        import secrets
        import string
        
        # Get form data
        user_email = request.form.get('user_email', '').strip().lower()
        user_name = request.form.get('user_name', '').strip()
        
        if not user_email:
            flash('User email is required', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        # Check if clinic exists
        clinic_result = db.session.execute(text("SELECT * FROM clinics WHERE id = :clinic_id"), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        clinic_dict = dict(clinic_result._mapping)
        
        # Check if user exists
        user_result = db.session.execute(text("SELECT * FROM users WHERE email = :email"), {'email': user_email}).fetchone()
        
        if user_result:
            # User exists, assign clinic to them
            user_dict = dict(user_result._mapping)
            user_id = user_dict['id']
            
            # Update clinic ownership
            db.session.execute(text("""
                UPDATE clinics 
                SET owner_user_id = :user_id, updated_at = :now
                WHERE id = :clinic_id
            """), {'user_id': user_id, 'clinic_id': clinic_id, 'now': datetime.utcnow()})
            
            flash(f'Clinic "{clinic_dict["name"]}" has been assigned to existing user {user_email}', 'success')
            
        else:
            # User doesn't exist, create new user
            # Generate random password
            password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            password_hash = generate_password_hash(password)
            
            # Create user
            db.session.execute(text("""
                INSERT INTO users (username, email, password_hash, name, role, is_verified, created_at, updated_at)
                VALUES (:username, :email, :password_hash, :name, :role, :is_verified, :created_at, :updated_at)
            """), {
                'username': user_email,
                'email': user_email,
                'password_hash': password_hash,
                'name': user_name or user_email.split('@')[0].title(),
                'role': 'clinic_owner',
                'is_verified': True,
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            })
            
            # Get the new user ID
            new_user_result = db.session.execute(text("SELECT * FROM users WHERE email = :email"), {'email': user_email}).fetchone()
            new_user_dict = dict(new_user_result._mapping)
            user_id = new_user_dict['id']
            
            # Update clinic ownership
            db.session.execute(text("""
                UPDATE clinics 
                SET owner_user_id = :user_id, updated_at = :now
                WHERE id = :clinic_id
            """), {'user_id': user_id, 'clinic_id': clinic_id, 'now': datetime.utcnow()})
            
            flash(f'New user created and clinic "{clinic_dict["name"]}" assigned to {user_email}. Temporary password: {password}', 'success')
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error assigning clinic owner {clinic_id}: {e}")
        db.session.rollback()
        flash('Error assigning clinic owner', 'error')
    
    return redirect(url_for('web.admin_clinic'))

@web.route('/admin/clinic/<int:clinic_id>/details')
@login_required
@admin_required
def view_clinic_details(clinic_id):
    """View detailed clinic information for admin review."""
    try:
        # Get comprehensive clinic information
        clinic_result = db.session.execute(text("""
            SELECT c.*, u.name as owner_name, u.email as owner_email, u.phone_number as owner_phone
            FROM clinics c
            LEFT JOIN users u ON c.owner_user_id = u.id
            WHERE c.id = :clinic_id
        """), {'clinic_id': clinic_id}).fetchone()
        
        if not clinic_result:
            flash('Clinic not found', 'error')
            return redirect(url_for('web.admin_clinic'))
        
        clinic = dict(clinic_result._mapping)
        
        # Get clinic's packages
        packages_result = db.session.execute(text("""
            SELECT p.*, COUNT(l.id) as lead_count
            FROM packages p
            LEFT JOIN leads l ON p.id = l.package_id
            WHERE p.clinic_id = :clinic_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        """), {'clinic_id': clinic_id}).fetchall()
        
        packages = [dict(row._mapping) for row in packages_result]
        
        # Get clinic's doctors
        doctors_result = db.session.execute(text("""
            SELECT d.* FROM doctors d
            WHERE d.clinic_id = :clinic_id
            ORDER BY d.created_at DESC
        """), {'clinic_id': clinic_id}).fetchall()
        
        doctors = [dict(row._mapping) for row in doctors_result]
        
        # Get clinic's leads
        leads_result = db.session.execute(text("""
            SELECT l.*, u.name as patient_name, u.phone_number as patient_phone,
                   p.title as package_name
            FROM leads l
            LEFT JOIN users u ON l.user_id = u.id
            LEFT JOIN packages p ON l.package_id = p.id
            WHERE l.clinic_id = :clinic_id
            ORDER BY l.created_at DESC
            LIMIT 10
        """), {'clinic_id': clinic_id}).fetchall()
        
        leads = [dict(row._mapping) for row in leads_result]
        
        return render_template('admin/clinic_details.html', 
                             clinic=clinic, 
                             packages=packages, 
                             doctors=doctors, 
                             leads=leads)
        
    except Exception as e:
        logger.error(f"Error loading clinic details {clinic_id}: {e}")
        flash('Error loading clinic details', 'error')
        return redirect(url_for('web.admin_clinic'))

@web.route('/admin/community-moderation')
@login_required
@admin_required
def admin_community_moderation():
    """Admin community moderation page."""
    # Get threads from the Thread model
    threads_model = Thread.query.join(User, Thread.user_id == User.id).add_columns(
        Thread.id, Thread.title, Thread.content, Thread.view_count, 
        Thread.created_at, User.username, User.email
    ).order_by(Thread.id.desc()).all()
    
    # Get threads from the Community model
    community_threads = Community.query.join(User, Community.user_id == User.id).add_columns(
        Community.id, Community.title, Community.content, Community.view_count, 
        Community.created_at, User.username, User.email
    ).order_by(Community.id.desc()).all()
    
    # Combine both sets of threads
    all_threads = threads_model + community_threads
    
    # Sort by creation date (descending)
    all_threads.sort(key=lambda t: t.created_at, reverse=True)
    
    return render_template('admin/community_moderation.html', threads=all_threads)

@web.route('/admin/community/thread/<int:thread_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_thread(thread_id):
    """Delete a thread from the admin panel."""
    try:
        # Try Thread model first
        thread = Thread.query.get(thread_id)
        
        if thread:
            # Get the thread title before deletion for the success message
            thread_title = thread.title
            
            # Delete all replies first
            db.session.query(CommunityReply).filter_by(thread_id=thread_id).delete()
            
            # Delete the thread
            db.session.delete(thread)
            db.session.commit()
            
            flash(f'Thread "{thread_title}" has been deleted successfully.', 'success')
        else:
            # Try Community model
            community_thread = Community.query.get_or_404(thread_id)
            thread_title = community_thread.title
            
            # Delete all replies
            db.session.query(CommunityReply).filter_by(thread_id=thread_id).delete()
            
            # Delete the thread
            db.session.delete(community_thread)
            db.session.commit()
            
            flash(f'Community thread "{thread_title}" has been deleted successfully.', 'success')
            
    except Exception as e:
        logger.error(f"Error deleting thread {thread_id}: {str(e)}")
        db.session.rollback()
        flash(f'Error deleting thread: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_community_moderation'))

@web.route('/admin/community/thread/<int:thread_id>/flag', methods=['POST'])
@login_required
@admin_required
def admin_flag_thread(thread_id):
    """Flag a thread from the admin panel."""
    try:
        # Try Thread model first
        thread = Thread.query.get(thread_id)
        
        if thread:
            # Set the thread to flagged status
            thread.is_flagged = True
            thread.flag_reason = request.form.get('reason')
            thread.flag_notes = request.form.get('notes')
            thread.flagged_by = current_user.id  # This maps to fk_thread_flagged_by column in database
            thread.flagged_at = datetime.utcnow()
            
            db.session.commit()
            
            flash(f'Thread "{thread.title}" has been flagged.', 'success')
        else:
            # Try Community model
            community_thread = Community.query.get_or_404(thread_id)
            
            # Set the community thread to flagged status 
            # Add these columns if they don't exist in the Community model
            community_thread.is_flagged = True
            if hasattr(community_thread, 'flag_reason'):
                community_thread.flag_reason = request.form.get('reason')
            if hasattr(community_thread, 'flag_notes'):
                community_thread.flag_notes = request.form.get('notes')
            if hasattr(community_thread, 'flagged_by'):
                community_thread.flagged_by = current_user.id
            if hasattr(community_thread, 'flagged_at'):
                community_thread.flagged_at = datetime.utcnow()
            
            db.session.commit()
            
            flash(f'Community thread "{community_thread.title}" has been flagged.', 'success')
            
    except Exception as e:
        logger.error(f"Error flagging thread {thread_id}: {str(e)}")
        db.session.rollback()
        flash(f'Error flagging thread: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_community_moderation'))

@web.route('/admin/procedures')
@login_required
@admin_required
def admin_procedures():
    """Admin procedures management page."""
    procedures = Procedure.query.order_by(Procedure.id).all()
    categories = Category.query.order_by(Category.name).all()
    body_parts = BodyPart.query.order_by(BodyPart.name).all()
    
    # Get featured procedures for image management
    try:
        featured_procedures = Procedure.query.filter(Procedure.is_featured == True).all()
    except Exception as e:
        logger.error(f"Error getting featured procedures: {str(e)}")
        featured_procedures = []
    
    return render_template('admin/procedures.html', 
                          procedures=procedures,
                          categories=categories,
                          body_parts=body_parts,
                          featured_procedures=featured_procedures)

@web.route('/admin/procedures/toggle-featured', methods=['POST'])
@login_required
@admin_required
def toggle_procedure_featured():
    """Toggle featured status for a procedure."""
    try:
        data = request.get_json()
        procedure_id = data.get('procedure_id')
        is_featured = data.get('is_featured')
        
        procedure = Procedure.query.get_or_404(procedure_id)
        procedure.is_featured = is_featured
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Procedure {"featured" if is_featured else "unfeatured"} successfully'
        })
        
    except Exception as e:
        logger.error(f"Error toggling featured status: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500



@web.route('/admin/procedures/add', methods=['POST'])
@login_required
@admin_required
def add_procedure():
    """Add a new procedure."""
    try:
        # Get form data
        procedure_name = request.form.get('procedure_name')
        short_description = request.form.get('short_description')
        overview = request.form.get('overview')
        procedure_details = request.form.get('procedure_details')
        ideal_candidates = request.form.get('ideal_candidates')
        recovery_process = request.form.get('recovery_process')
        risks = request.form.get('risks')
        benefits = request.form.get('benefits')
        category_id = request.form.get('category_id')
        body_part = request.form.get('body_part')
        min_cost = request.form.get('min_cost')
        max_cost = request.form.get('max_cost')
        
        # Create new procedure
        new_procedure = Procedure(
            procedure_name=procedure_name,
            short_description=short_description,
            overview=overview,
            procedure_details=procedure_details,
            ideal_candidates=ideal_candidates,
            recovery_process=recovery_process,
            risks=risks,
            benefits=benefits,
            category_id=category_id,
            body_part=body_part,
            min_cost=min_cost if min_cost else None,
            max_cost=max_cost if max_cost else None,
            created_at=datetime.utcnow()
        )
        
        # Handle thumbnail upload
        if 'thumbnail' in request.files:
            thumbnail = request.files['thumbnail']
            if thumbnail and thumbnail.filename:
                filename = secure_filename(thumbnail.filename)
                # Create upload directory if it doesn't exist
                upload_folder = os.path.join(os.getcwd(), 'static', 'uploads', 'procedures')
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save file
                file_path = os.path.join(upload_folder, filename)
                thumbnail.save(file_path)
                
                # Update procedure with thumbnail path
                new_procedure.thumbnail = os.path.join('uploads', 'procedures', filename)
        
        db.session.add(new_procedure)
        db.session.commit()
        
        flash(f'Procedure "{procedure_name}" has been added successfully.', 'success')
    except Exception as e:
        logger.error(f"Error adding procedure: {str(e)}")
        db.session.rollback()
        flash(f'Error adding procedure: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_procedures'))

@web.route('/admin/categories/add', methods=['POST'])
@login_required
@admin_required
def add_category():
    """Add a new category."""
    try:
        # Get form data
        name = request.form.get('name')
        display_name = request.form.get('display_name') or name
        description = request.form.get('description')
        body_part_id = request.form.get('body_part_id')
        
        # Create new category
        new_category = Category(
            name=name,
            display_name=display_name,
            description=description,
            body_part_id=body_part_id if body_part_id else None
        )
        
        db.session.add(new_category)
        db.session.commit()
        
        flash(f'Category "{name}" has been added successfully.', 'success')
    except Exception as e:
        logger.error(f"Error adding category: {str(e)}")
        db.session.rollback()
        flash(f'Error adding category: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_procedures'))

@web.route('/admin/body-parts/add', methods=['POST'])
@login_required
@admin_required
def add_body_part():
    """Add a new body part."""
    try:
        # Get form data
        name = request.form.get('name')
        display_name = request.form.get('display_name') or name
        description = request.form.get('description')
        
        # Create new body part
        new_body_part = BodyPart(
            name=name,
            display_name=display_name,
            description=description
        )
        
        db.session.add(new_body_part)
        db.session.commit()
        
        flash(f'Body part "{name}" has been added successfully.', 'success')
    except Exception as e:
        logger.error(f"Error adding body part: {str(e)}")
        db.session.rollback()
        flash(f'Error adding body part: {str(e)}', 'danger')
    
    return redirect(url_for('web.admin_procedures'))

@web.route('/sitemap.xml')
def sitemap_index():
    """Generate sitemap index for better SEO performance"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        # Create sitemap index
        sitemapindex = ET.Element('sitemapindex')
        sitemapindex.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Helper function to add sitemap
        def add_sitemap(loc, lastmod=today):
            sitemap = ET.SubElement(sitemapindex, 'sitemap')
            ET.SubElement(sitemap, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(sitemap, 'lastmod').text = lastmod
        
        # Add individual sitemaps
        add_sitemap('/sitemap-main.xml')
        add_sitemap('/sitemap-procedures.xml')
        add_sitemap('/sitemap-clinics.xml') 
        add_sitemap('/sitemap-doctors.xml')
        add_sitemap('/sitemap-categories.xml')
        add_sitemap('/sitemap-community.xml')
        add_sitemap('/sitemap-bodyparts.xml')
        add_sitemap('/sitemap-community.xml')
        add_sitemap('/sitemap-bodyparts.xml')
        
        # Generate XML with pretty formatting
        from xml.dom import minidom
        rough_string = ET.tostring(sitemapindex, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['X-Robots-Tag'] = 'index, follow, all'
        response.headers['Cache-Control'] = 'public, max-age=3600'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating sitemap index: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></sitemapindex>', 
                       mimetype='application/xml')

@web.route('/sitemap-main.xml')
def sitemap_main():
    """Main pages sitemap"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Main pages with high priority
        add_url('/', priority='1.0', changefreq='daily')
        add_url('/procedures', priority='0.9', changefreq='weekly')
        add_url('/doctors', priority='0.9', changefreq='weekly')
        add_url('/clinics', priority='0.9', changefreq='weekly')
        add_url('/packages', priority='0.8', changefreq='weekly')
        add_url('/community', priority='0.8', changefreq='daily')
        add_url('/search', priority='0.8', changefreq='weekly')
        add_url('/face-analysis', priority='0.7', changefreq='monthly')
        add_url('/ai-recommendation', priority='0.7', changefreq='weekly')
        
        # Generate XML with pretty formatting
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
        
    except Exception as e:
        logger.error(f"Error generating main sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-procedures.xml')
def sitemap_procedures():
    """Procedures sitemap (limited to prevent timeout)"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Limit procedures to prevent timeout (most popular first)
        procedures = Procedure.query.order_by(Procedure.id.desc()).limit(500).all()
        for procedure in procedures:
            add_url(f'/procedure/{procedure.id}', priority='0.8', changefreq='monthly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=7200'  # 2 hour cache
        return response
        
    except Exception as e:
        logger.error(f"Error generating procedures sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-clinics.xml')
def sitemap_clinics():
    """Clinics sitemap (limited to prevent timeout)"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Import model if not available
        from models import Clinic
        
        # Get all clinics (no is_verified field exists)
        clinics = Clinic.query.order_by(Clinic.id.desc()).limit(300).all()
        for clinic in clinics:
            add_url(f'/clinic/{clinic.id}', priority='0.8', changefreq='monthly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=7200'
        return response
        
    except Exception as e:
        logger.error(f"Error generating clinics sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-doctors.xml') 
def sitemap_doctors():
    """Doctors sitemap"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Import model if not available
        from models import Doctor
        
        # Get verified doctors only from doctors table
        doctors = Doctor.query.filter_by(is_verified=True).limit(106).all()
        for doctor in doctors:
            add_url(f'/doctor/{doctor.id}', priority='0.8', changefreq='monthly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=7200'
        return response
        
    except Exception as e:
        logger.error(f"Error generating doctors sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-categories.xml')
def sitemap_categories():
    """Categories and packages sitemap"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Import models if not available
        from models import Category
        
        # Add categories
        categories = Category.query.limit(50).all()
        for category in categories:
            add_url(f'/procedures?category={category.id}', priority='0.7', changefreq='monthly')
        
        # Import models if not available
        from models import Package
        
        # Add packages 
        packages = Package.query.filter_by(is_active=True).limit(100).all()
        for package in packages:
            add_url(f'/package/{package.id}', priority='0.7', changefreq='monthly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=7200'
        return response
        
    except Exception as e:
        logger.error(f"Error generating categories sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-community.xml')
def sitemap_community():
    """Community threads and discussions sitemap"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Import models if not available
        from models import Thread
        
        # Add community threads - high engagement content
        threads = Thread.query.order_by(Thread.created_at.desc()).limit(100).all()
        for thread in threads:
            thread_date = thread.created_at.strftime('%Y-%m-%d') if thread.created_at else today
            add_url(f'/community/thread/{thread.id}', lastmod=thread_date, priority='0.7', changefreq='weekly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=3600'  # 1 hour cache
        return response
        
    except Exception as e:
        logger.error(f"Error generating community sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/sitemap-bodyparts.xml')
def sitemap_bodyparts():
    """Body parts and location-based pages sitemap"""
    from flask import Response
    from datetime import datetime
    import xml.etree.ElementTree as ET
    
    try:
        urlset = ET.Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')
        
        base_url = 'https://antidote.fit'
        today = datetime.now().strftime('%Y-%m-%d')
        
        def add_url(loc, lastmod=today, changefreq='weekly', priority='0.5'):
            url = ET.SubElement(urlset, 'url')
            ET.SubElement(url, 'loc').text = f"{base_url}{loc}"
            ET.SubElement(url, 'lastmod').text = lastmod
            ET.SubElement(url, 'changefreq').text = changefreq
            ET.SubElement(url, 'priority').text = priority
        
        # Import models if not available
        from models import BodyPart
        
        # Add body parts - high SEO value for "face procedures", "body treatments"
        body_parts = BodyPart.query.all()
        for body_part in body_parts:
            add_url(f'/procedures/{body_part.name.lower()}', priority='0.8', changefreq='monthly')
        
        # Add major city pages for local SEO
        major_cities = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad', 'pune', 'kolkata', 'ahmedabad']
        for city in major_cities:
            add_url(f'/procedures/{city}', priority='0.8', changefreq='monthly')
            add_url(f'/clinics/{city}', priority='0.8', changefreq='monthly')
            add_url(f'/doctors/{city}', priority='0.8', changefreq='monthly')
        
        # Generate XML with proper formatting for browser readability
        from xml.dom import minidom
        rough_string = ET.tostring(urlset, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
        response = Response(xml_str, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=7200'  # 2 hour cache
        return response
        
    except Exception as e:
        logger.error(f"Error generating body parts sitemap: {e}")
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 
                       mimetype='application/xml')

@web.route('/opensearch.xml')
def opensearch_xml():
    """OpenSearch description for browser search integration"""
    from flask import Response
    
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
    <ShortName>Antidote Medical Search</ShortName>
    <Description>Search for medical procedures, doctors, and clinics on Antidote</Description>
    <Url type="text/html" method="get" template="https://antidote.fit/search?q={searchTerms}"/>
    <Image height="16" width="16" type="image/x-icon">https://antidote.fit/static/favicon-16x16.png</Image>
    <Image height="32" width="32" type="image/png">https://antidote.fit/static/favicon-32x32.png</Image>
</OpenSearchDescription>'''
    
    return Response(xml_content, mimetype='application/xml')

@web.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    """Admin analytics and reports page."""
    # Get user counts
    user_count = User.query.count()
    doctor_count = User.query.filter_by(role='doctor').count()
    
    # Get content counts
    procedure_count = Procedure.query.count()
    thread_count = Thread.query.count()
    review_count = Review.query.count()
    banner_count = Banner.query.count()
    banner_slide_count = BannerSlide.query.count()
    
    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_threads = Thread.query.order_by(Thread.created_at.desc()).limit(5).all()
    
    # Get banner impressions and clicks
    total_impressions = db.session.query(func.sum(BannerSlide.impression_count)).scalar() or 0
    total_clicks = db.session.query(func.sum(BannerSlide.click_count)).scalar() or 0
    ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
    
    return render_template(
        'admin/analytics.html',
        user_count=user_count,
        doctor_count=doctor_count,
        procedure_count=procedure_count,
        thread_count=thread_count,
        review_count=review_count,
        banner_count=banner_count,
        banner_slide_count=banner_slide_count,
        recent_users=recent_users,
        recent_threads=recent_threads,
        total_impressions=total_impressions,
        total_clicks=total_clicks,
        ctr=ctr
    )


# Media handling route
@api.route('/media/<path:url>', methods=['GET'])
def serve_media(url):
    """
    Serve media files from a designated directory or proxy external URLs.
    This provides a consistent interface for media regardless of storage location.
    """
    try:
        logger.debug(f"Media request received for: {url}")
        
        # Check if this is an internal or external URL
        parsed_url = urllib.parse.urlparse(url)
        
        if parsed_url.netloc:  # External URL (e.g., S3, CDN)
            # For security, we'll redirect rather than proxy
            logger.debug(f"Redirecting to external URL: {url}")
            return redirect(url)
        else:
            # Ensure the media directory exists
            media_dir = os.path.join(os.getcwd(), 'static', 'media')
            os.makedirs(media_dir, exist_ok=True)
            
            # Normalize the path to avoid ../ security issues
            safe_path = os.path.normpath(url).lstrip('/')
            
            # Build the file path
            file_path = os.path.join(media_dir, safe_path)
            
            # Check if file exists and serve it
            if os.path.exists(file_path) and os.path.isfile(file_path):
                logger.info(f"Serving media: {file_path}")
                return send_from_directory(media_dir, safe_path)
            
            # If not found, use placeholder
            logger.warning(f"Media not found, serving placeholder: {safe_path}")
            placeholder_path = os.path.join(media_dir, 'placeholder.jpg')
            
            # Create placeholder if it doesn't exist
            if not os.path.exists(placeholder_path):
                try:
                    with open(placeholder_path, 'w') as f:
                        f.write("This is a placeholder image file.")
                    logger.info(f"Created placeholder image at {placeholder_path}")
                except Exception as e:
                    logger.error(f"Failed to create placeholder: {str(e)}")
            
            # Return placeholder
            return send_from_directory(media_dir, 'placeholder.jpg')
    except Exception as e:
        logger.error(f"Media serving error: {str(e)}")
        return jsonify({'success': False, 'message': 'Media error'}), 500

# Lead submission for India launch
@web.route('/submit-lead', methods=['POST'])
def submit_lead():
    """
    Process lead submission for India launch.
    
    This route handles the lead submission form from both procedure and doctor detail pages.
    It supports guest submissions (not logged in) using mock authentication.
    """
    try:
        # Get form data
        patient_name = request.form.get('patient_name')
        mobile_number = request.form.get('mobile_number')
        city = request.form.get('city')
        procedure_name = request.form.get('procedure_name')
        preferred_date = request.form.get('preferred_date')
        message = request.form.get('message', '')
        consent = request.form.get('consent') == 'on'
        source = request.form.get('source', 'Unknown')  # Track where the lead came from
        
        # Get doctor information
        doctor_id = request.form.get('doctor_id')
        
        logger.info(f"Received lead submission: Patient={patient_name}, Procedure={procedure_name}, Source={source}")
        logger.debug(f"Lead details - Mobile: {mobile_number}, City: {city}, Date: {preferred_date}, Consent: {consent}")
        
        # Validate required fields
        missing_fields = []
        if not patient_name: missing_fields.append('Patient Name')
        if not mobile_number: missing_fields.append('Mobile Number')
        if not city: missing_fields.append('City')
        if not procedure_name: missing_fields.append('Procedure Name')
        if not preferred_date: missing_fields.append('Preferred Date')
        if not consent: missing_fields.append('Consent')
        
        if missing_fields:
            missing_fields_str = ', '.join(missing_fields)
            logger.warning(f"Missing required fields: {missing_fields_str}")
            flash('Please fill all required fields', 'danger')
            # Determine where to redirect based on whether it's from a doctor or procedure page
            if doctor_id:
                return redirect(url_for('web.doctor_detail', doctor_id=doctor_id))
            else:
                # Redirect to the procedure search page if procedure ID is not available
                return redirect(url_for('web.procedures'))
        
        # Validate mobile number format (10 digits)
        if not mobile_number.isdigit() or len(mobile_number) != 10:
            logger.warning(f"Invalid mobile number format: {mobile_number}")
            flash('Please enter a valid 10-digit mobile number', 'danger')
            if doctor_id:
                return redirect(url_for('web.doctor_detail', doctor_id=doctor_id))
            else:
                return redirect(url_for('web.procedures'))
                
        # Get user_id from current_user if authenticated
        user_id = current_user.id if current_user.is_authenticated else None
        
        # Create new lead
        new_lead = Lead(
            user_id=user_id,
            doctor_id=doctor_id if doctor_id else None,
            procedure_name=procedure_name,
            message=message,
            status='pending',
            created_at=datetime.utcnow(),
            patient_name=patient_name,
            mobile_number=mobile_number,
            city=city,
            preferred_date=datetime.strptime(preferred_date, '%Y-%m-%d'),
            consent_given=consent,
            source=source  # Track where the lead came from
        )
        
        db.session.add(new_lead)
        db.session.commit()
        
        # Send email notification to doctor if doctor_id is available
        if doctor_id:
            try:
                doctor = Doctor.query.get(doctor_id)
                
                if not doctor:
                    logger.warning(f"Doctor with ID {doctor_id} not found in database")
                    flash('Doctor not found, but your consultation request has been saved', 'warning')
                elif not doctor.user:
                    logger.warning(f"Doctor with ID {doctor_id} does not have an associated user account")
                elif not doctor.user.email:
                    logger.warning(f"Doctor with ID {doctor_id} (user ID: {doctor.user.id}) does not have an email address")
                else:
                    # Get doctor's user email
                    doctor_email = doctor.user.email
                    logger.info(f"Preparing email notification to Dr. {doctor.name} at {doctor_email}")
                    
                    # Create email template
                    email_template = f"""
                    <h2>New Lead Submission</h2>
                    <p>Dear Dr. {doctor.name},</p>
                    <p>A new patient consultation request has been submitted:</p>
                    <ul>
                        <li><strong>Patient Name:</strong> {patient_name}</li>
                        <li><strong>Mobile Number:</strong> {mobile_number}</li>
                        <li><strong>City:</strong> {city}</li>
                        <li><strong>Procedure:</strong> {procedure_name}</li>
                        <li><strong>Preferred Date:</strong> {preferred_date}</li>
                        <li><strong>Message:</strong> {message}</li>
                        <li><strong>Source:</strong> {source}</li>
                    </ul>
                    <p>Please log in to your Antidote dashboard to respond to this inquiry.</p>
                    <p>Best regards,<br>The Antidote Team</p>
                    """
                    
                    # Send the email
                    email_sent = send_email(
                        subject="New Patient Consultation Request", 
                        recipients=[doctor_email],
                        template=email_template
                    )
                    
                    if email_sent:
                        logger.info(f"Email notification sent to Dr. {doctor.name} at {doctor_email}")
                    else:
                        logger.warning(f"Failed to send email notification to Dr. {doctor.name}")
                        
                    # Create a notification in the database for the doctor as well
                    try:
                        notification = Notification(
                            user_id=doctor.user.id,
                            type='new_lead',
                            message=f'New consultation request from {patient_name} for {procedure_name}',
                            is_read=False,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(notification)
                        db.session.commit()
                        logger.info(f"In-app notification created for Dr. {doctor.name}")
                    except Exception as e:
                        logger.error(f"Error creating notification: {str(e)}")
            except Exception as e:
                logger.error(f"Error sending email notification: {str(e)}")
                # Continue with the flow even if email sending fails
        
        # Redirect to confirmation page
        return redirect(url_for('web.lead_confirmation', lead_id=new_lead.id))
        
    except Exception as e:
        logger.error(f"Error processing lead submission: {str(e)}")
        flash('An error occurred while processing your request. Please try again.', 'danger')
        return redirect(url_for('web.index'))

@web.route('/lead-confirmation/<int:lead_id>')
def lead_confirmation(lead_id):
    """
    Show confirmation page after successful lead submission.
    
    This page thanks the user and encourages them to create an account or login.
    It provides details about their submission and next steps.
    """
    try:
        logger.info(f"Loading lead confirmation page for lead ID: {lead_id}")
        lead = Lead.query.get(lead_id)
        
        if not lead:
            logger.warning(f"Lead with ID {lead_id} not found")
            flash('Lead not found', 'danger')
            return redirect(url_for('web.index'))
            
        logger.info(f"Found lead for patient: {lead.patient_name}, Procedure: {lead.procedure_name}")
        
        # Get doctor information if available
        doctor = None
        if lead.doctor_id:
            doctor = Doctor.query.get(lead.doctor_id)
            if doctor:
                logger.info(f"Lead linked to doctor: {doctor.name}")
            else:
                logger.warning(f"Doctor with ID {lead.doctor_id} not found")
        
        # Check if user is logged in
        is_logged_in = 'user_id' in session
        
        # Log analytics for lead confirmation view
        try:
            # You could add analytics tracking here
            logger.info(f"Lead confirmation viewed - ID: {lead_id}, Source: {lead.source}, Logged in: {is_logged_in}")
        except Exception as e:
            logger.error(f"Error logging lead confirmation analytics: {str(e)}")
            
        return render_template(
            'lead_confirmation.html', 
            lead=lead, 
            doctor=doctor,
            is_logged_in=is_logged_in
        )
        
    except Exception as e:
        logger.error(f"Error showing lead confirmation: {str(e)}")
        flash('An error occurred while accessing the confirmation page', 'danger')
        return redirect(url_for('web.index'))

# Helper function to count replies recursively
def count_all_replies(thread_id):
    """
    Count all replies for a thread, including nested replies.
    This provides a more accurate count than just counting top-level replies.
    
    Uses the unified community table structure where replies have parent_id = thread_id.
    """
    try:
        # Count all replies to this thread (entries with parent_id = thread_id)
        total = Community.query.filter_by(parent_id=thread_id).count()
        
        # Log for debugging
        logger.debug(f"Found {total} total replies for thread {thread_id} using recursive count")
        
        # Update the thread's reply_count if different
        thread = Community.query.get(thread_id)
        if thread and thread.reply_count != total:
            thread.reply_count = total
            db.session.commit()
            
        return total
    except Exception as e:
        logger.error(f"Error counting replies: {str(e)}")
        return 0

# Mock login route for testing
@web.route('/mock_login')
def mock_login():
    """
    Mock login route for testing purposes.
    Properly logs in user 339 (Ashok Advanced Aesthetics clinic) using Flask-Login.
    """
    from flask_login import login_user
    from models import User
    
    try:
        # Get user 339 from database
        user = db.session.get(User, 339)
        if user:
            login_user(user)
            flash('You are now logged in as Ashok Advanced Aesthetics clinic user', 'success')
            return redirect(url_for('web.clinic_dashboard'))
        else:
            flash('Test user not found', 'error')
            return redirect(url_for('web.index'))
    except Exception as e:
        logger.error(f"Error in mock login: {e}")
        flash('Login error occurred', 'error')
        return redirect(url_for('web.index'))

@web.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration."""
    # Redirect to dashboard if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))
        
    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Create new user with hashed password
            user = User(
                name=form.name.data,
                username=form.username.data,
                email=form.email.data,
                phone_number=form.phone_number.data,
                role='user',  # Default role
                created_at=datetime.utcnow()
            )
            user.set_password(form.password.data)
            
            # Add user to database
            db.session.add(user)
            db.session.commit()
            
            # Log in the user after registration
            login_user(user)
            flash('Your account has been created! You are now logged in.', 'success')
            
            # Redirect to home page
            return redirect(url_for('web.index'))
        except Exception as e:
            logger.error(f"Error during user registration: {str(e)}")
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('signup.html', title='Sign Up', form=form)

@web.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    # Redirect to dashboard if user is already logged in
    if current_user.is_authenticated:
        # Redirect doctors to their dashboard
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if doctor:
                return redirect(url_for('web.doctor_dashboard', doctor_id=doctor.id))
        # Other users go to index
        return redirect(url_for('web.index'))
        
    form = LoginForm()
    
    # Add debugging for form validation
    if request.method == 'POST':
        logger.info(f"Login attempt for email: {request.form.get('email')}")
        
        if not form.validate_on_submit():
            for field, errors in form.errors.items():
                for error in errors:
                    logger.error(f"Validation error in {field}: {error}")
                    flash(f"Error in {field}: {error}", 'danger')
    
    if form.validate_on_submit():
        # Look up user by email - use case-insensitive comparison
        email = form.email.data.lower().strip()
        logger.info(f"Looking up user with email: {email}")
        
        # Try case-insensitive search
        user = User.query.filter(func.lower(User.email) == func.lower(email)).first()
        
        if not user:
            logger.error(f"No user found with email: {email}")
            flash('Login failed. User not found with this email.', 'danger')
            return render_template('login.html', title='Log In', form=form)
        
        # Check if password is correct
        if user.check_password(form.password.data):
            # Update last login timestamp
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            
            # Log in the user
            login_user(user, remember=form.remember_me.data)
            logger.info(f"User {user.id} ({user.email}) logged in successfully")
            flash('You have been logged in successfully!', 'success')
            
            # Redirect to the page the user was trying to access, or to the appropriate dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
                
            # If no next page, redirect based on role
            logger.info(f"User role: {user.role}")
            if user.role == 'doctor':
                doctor = Doctor.query.filter_by(user_id=user.id).first()
                if doctor:
                    logger.info(f"Redirecting doctor to dashboard")
                    return redirect(url_for('web.doctor_dashboard', doctor_id=doctor.id))
            elif user.role == 'clinic_admin':
                logger.info(f"Redirecting clinic admin to dashboard")
                return redirect(url_for('clinic.clinic_dashboard'))
            
            # Default redirect for non-doctors or doctors without a profile
            return redirect(url_for('web.index'))
        else:
            logger.error(f"Invalid password for user: {email}")
            flash('Login failed. Please check your password.', 'danger')
    
    return render_template('login.html', title='Log In', form=form)

@web.route('/book_appointment/<int:doctor_id>', methods=['GET', 'POST'])
@login_required
def book_appointment(doctor_id):
    """Handle booking an appointment with a doctor."""
    doctor = Doctor.query.get_or_404(doctor_id)
    if current_user.role != 'user':
        flash('Only patients can book appointments.', 'danger')
        return redirect(url_for('web.index'))
        
    if request.method == 'POST':
        procedure_name = request.form.get('procedure_name')
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        
        # Validate inputs
        if not procedure_name or not appointment_date or not appointment_time:
            flash('All fields are required to book an appointment.', 'danger')
            return render_template('book_appointment.html', doctor=doctor)
            
        try:
            # Create new appointment
            appointment = Appointment(
                user_id=current_user.id,
                doctor_id=doctor.id,
                procedure_name=procedure_name,
                appointment_date=datetime.strptime(appointment_date, '%Y-%m-%d').date(),
                appointment_time=appointment_time,
                status='pending'
            )
            db.session.add(appointment)
            db.session.commit()
            
            # Send notification to doctor
            notification = Notification(
                user_id=doctor.user_id,
                message=f"New appointment request from {current_user.name} for {procedure_name}",
                type='appointment_request'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Appointment booked successfully! The doctor will confirm your appointment soon.', 'success')
            return redirect(url_for('web.index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error booking appointment: {str(e)}")
            flash('There was an error booking your appointment. Please try again.', 'danger')
    
    return render_template('book_appointment.html', doctor=doctor)

@web.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    # Redirect to dashboard if user is already logged in
    if current_user.is_authenticated:
        # Redirect doctors to their dashboard
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if doctor:
                return redirect(url_for('web.doctor_dashboard', doctor_id=doctor.id))
        # Other users go to index
        return redirect(url_for('web.index'))
    
    form = SignupForm()
    
    if form.validate_on_submit():
        # Create a new user with the form data
        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            phone_number=form.phone_number.data,
            role='user'  # Default role is user
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in to continue.', 'success')
            return redirect(url_for('web.login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during user registration: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html', title='Register', form=form)

@web.route('/logout')
def logout():
    """Handle user logout."""
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('web.index'))

@web.route('/favorites')
@login_required
def favorites():
    """Display user's saved doctors and procedures."""
    # Get user's saved items with their related objects
    saved_procedures = db.session.query(Favorite, Procedure)\
        .filter(Favorite.user_id == current_user.id)\
        .filter(Favorite.procedure_id != None)\
        .filter(Favorite.procedure_id == Procedure.id)\
        .all()
    
    saved_doctors = db.session.query(Favorite, Doctor)\
        .filter(Favorite.user_id == current_user.id)\
        .filter(Favorite.doctor_id != None)\
        .filter(Favorite.doctor_id == Doctor.id)\
        .all()
    
    return render_template('favorites.html', 
                          title='My Favorites',
                          saved_procedures=saved_procedures,
                          saved_doctors=saved_doctors)

@web.route('/save-item', methods=['POST'])
@login_required
def save_item():
    """Save a doctor or procedure to favorites."""
    try:
        logger.info('==== Save item request received ====')
        logger.info('Request form data: %s', request.form)
        logger.info('Request headers: %s', dict(request.headers))
        
        doctor_id = request.form.get('doctor_id')
        procedure_id = request.form.get('procedure_id')
        logger.info('Doctor ID: %s, Procedure ID: %s', doctor_id, procedure_id)
        logger.info('Current user ID: %s, Email: %s', current_user.id, current_user.email)
        
        # Get referrer URL for redirects
        referrer = request.referrer or url_for('web.index')
        logger.info('Referrer URL: %s', referrer)
        
        # Validate that at least one ID is provided
        if not doctor_id and not procedure_id:
            logger.warning('No item specified to save')
            flash('No item specified to save', 'danger')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False, 
                    'message': 'No item specified to save'
                }), 400
                
            return redirect(referrer)
            
        # Check if item is already saved
        if doctor_id:
            existing = Favorite.query.filter_by(user_id=current_user.id, doctor_id=doctor_id).first()
            item_type = 'doctor'
            # Get doctor name for better feedback
            doctor = Doctor.query.get(doctor_id)
            if doctor:
                item_name = f"Dr. {doctor.name}"
                logger.info(f"Found doctor: {item_name}")
            else:
                item_name = "doctor"
                logger.warning(f"Doctor with ID {doctor_id} not found")
        else:
            existing = Favorite.query.filter_by(user_id=current_user.id, procedure_id=procedure_id).first()
            item_type = 'procedure'
            # Get procedure name for better feedback
            procedure = Procedure.query.get(procedure_id)
            if procedure:
                item_name = procedure.procedure_name
                logger.info(f"Found procedure: {item_name}")
            else:
                item_name = "procedure"
                logger.warning(f"Procedure with ID {procedure_id} not found")
            
        # If already saved, notify user and redirect
        if existing:
            logger.info(f"{item_name} is already in favorites (id: {existing.id})")
            flash(f'{item_name} is already in your favorites', 'info')
            
            # If AJAX request, return JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False, 
                    'message': f'{item_name} is already in your favorites'
                }), 200
                
            return redirect(referrer)
            
        # Create new favorite
        favorite = Favorite(
            user_id=current_user.id,
            doctor_id=doctor_id if doctor_id else None,
            procedure_id=procedure_id if procedure_id else None,
            created_at=datetime.utcnow()
        )
        
        db.session.add(favorite)
        db.session.commit()
        logger.info(f"Successfully added {item_name} to favorites (id: {favorite.id})")
        
        # Provide success feedback
        flash(f'{item_name} saved to your favorites!', 'success')
        
        # If AJAX request, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            logger.info("Returning AJAX success response")
            return jsonify({
                'success': True, 
                'message': f'{item_name} saved to favorites!',
                'favorite_id': favorite.id
            }), 201
        
        logger.info("Redirecting to referrer page")
        # Otherwise redirect back to the referring page
        return redirect(referrer)
        
    except Exception as e:
        logger.error(f"Error saving favorite: {str(e)}")
        logger.exception("Exception details:")
        db.session.rollback()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'An error occurred while saving to favorites: {str(e)}'}), 500
            
        flash(f'An error occurred while saving to favorites: {str(e)}', 'danger')
        return redirect(request.referrer or url_for('web.index'))

@web.route('/remove-favorite/<int:favorite_id>', methods=['POST'])
@login_required
def remove_favorite(favorite_id):
    """Remove an item from favorites."""
    try:
        logger.info('Remove favorite request received: favorite_id=%s', favorite_id)
        favorite = Favorite.query.get(favorite_id)
        logger.info('Favorite found: %s', favorite)
        
        # Get referrer URL for redirects
        referrer = request.referrer or url_for('web.favorites')
        
        # Validate favorite exists and belongs to the current user
        if not favorite:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Favorite not found'}), 404
                
            flash('The item you tried to remove was not found', 'danger')
            return redirect(referrer)
            
        if favorite.user_id != current_user.id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'You do not have permission to remove this favorite'}), 403
                
            flash('You do not have permission to remove this item', 'danger')
            return redirect(referrer)
        
        # Get item details for better feedback
        if favorite.doctor_id:
            item_type = 'doctor'
            doctor = Doctor.query.get(favorite.doctor_id)
            item_name = f"Dr. {doctor.name}" if doctor else "doctor"
        else:
            item_type = 'procedure'
            procedure = Procedure.query.get(favorite.procedure_id)
            item_name = procedure.procedure_name if procedure else "procedure"
        
        # Remove from favorites
        db.session.delete(favorite)
        db.session.commit()
        
        # If AJAX request, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True, 
                'message': f'{item_name} removed from favorites!',
                'item_type': item_type
            }), 200
        
        # Provide success feedback
        flash(f'{item_name} removed from your favorites', 'success')
        return redirect(referrer)
        
    except Exception as e:
        logger.error(f"Error removing favorite: {str(e)}")
        db.session.rollback()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'An error occurred while removing from favorites'}), 500
            
        flash('An error occurred while removing from favorites', 'danger')
        return redirect(request.referrer or url_for('web.favorites'))

@web.route('/submit-review', methods=['POST'])
def submit_review():
    """Submit a review for a procedure or doctor."""
    try:
        if not current_user.is_authenticated:
            flash('Please log in to submit a review', 'warning')
            return redirect(url_for('web.login'))
            
        # Get review details from the form
        procedure_id = request.form.get('procedure_id')
        doctor_id = request.form.get('doctor_id')
        rating = request.form.get('rating')
        comment = request.form.get('comment')
        
        logger.info(f"Review submission: procedure_id={procedure_id}, doctor_id={doctor_id}, rating={rating}")
        
        if not rating:
            flash('Rating is required', 'danger')
            redirect_url = url_for('web.index')
            if procedure_id:
                redirect_url = url_for('web.procedure_detail', procedure_id=procedure_id)
            elif doctor_id:
                redirect_url = url_for('web.doctor_detail', doctor_id=doctor_id)
            return redirect(redirect_url)
        
        # Create a new review
        review = Review(
            user_id=current_user.id,
            procedure_id=procedure_id if procedure_id else None,
            doctor_id=doctor_id if doctor_id else None,
            rating=float(rating),
            content=comment,
            created_at=datetime.utcnow()
        )
        
        db.session.add(review)
        
        # Update the procedure's average rating if provided
        if procedure_id:
            procedure = Procedure.query.get(procedure_id)
            if procedure:
                # Include the new review in the calculation
                all_reviews = list(Review.query.filter_by(procedure_id=procedure_id).all()) + [review]
                procedure.avg_rating = sum(r.rating for r in all_reviews) / len(all_reviews)
                procedure.review_count = len(all_reviews)
        
        # Update the doctor's average rating if provided
        if doctor_id:
            doctor = Doctor.query.get(doctor_id)
            if doctor:
                # Include the new review in the calculation
                all_doctor_reviews = list(Review.query.filter_by(doctor_id=doctor_id).all()) + [review]
                doctor.rating = sum(r.rating for r in all_doctor_reviews) / len(all_doctor_reviews)
                doctor.review_count = len(all_doctor_reviews)
        
        # Save changes to database
        db.session.commit()
        
        # Determine the appropriate redirect URL
        if procedure_id:
            redirect_url = url_for('web.procedure_detail', procedure_id=procedure_id)
        elif doctor_id:
            redirect_url = url_for('web.doctor_detail', doctor_id=doctor_id)
        else:
            redirect_url = url_for('web.index')
            
        flash('Your review has been submitted successfully!', 'success')
        
        # Return response based on request type
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': 'Review submitted successfully',
                'redirect': redirect_url
            })
        else:
            return redirect(redirect_url)
            
    except Exception as e:
        logger.error(f"Error submitting review: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'message': f"Error: {str(e)}"
            }), 500
        else:
            flash(f"Error: {str(e)}", 'danger')
            return redirect(url_for('web.index'))

@web.route('/review/helpful/<int:review_id>', methods=['POST'])
def mark_review_helpful(review_id):
    """Mark a review as helpful (original route)."""
    try:
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Please log in to mark reviews as helpful'}), 401
            
        review = Review.query.get_or_404(review_id)
        review.helpful_count = (review.helpful_count or 0) + 1
        db.session.commit()
        
        logger.info(f"Marked review {review_id} as helpful")
        return jsonify({
            'success': True,
            'message': 'Review marked as helpful',
            'helpful_count': review.helpful_count
        })
    except Exception as e:
        logger.error(f"Error marking review as helpful: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@web.route('/helpful/<int:review_id>', methods=['POST'])
def helpful_review(review_id):
    """Mark a review as helpful."""
    try:
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Please log in to mark reviews as helpful'}), 401
            
        review = Review.query.get_or_404(review_id)
        review.helpful_count = (review.helpful_count or 0) + 1
        db.session.commit()
        
        logger.info(f"Marked review {review_id} as helpful")
        return jsonify({
            'success': True,
            'message': 'Review marked as helpful',
            'helpful_count': review.helpful_count
        })
    except Exception as e:
        logger.error(f"Error marking review as helpful: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@web.route('/review/report/<int:review_id>', methods=['POST'])
def report_review(review_id):
    """Report an inappropriate review (original route)."""
    try:
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Please log in to report reviews'}), 401
            
        review = Review.query.get_or_404(review_id)
        review.reported = True
        db.session.commit()
        
        logger.info(f"Review {review_id} reported as inappropriate")
        return jsonify({
            'success': True,
            'message': 'Review has been reported'
        })
    except Exception as e:
        logger.error(f"Error reporting review: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

@web.route('/report/<int:review_id>', methods=['POST'])
def report_review_alt(review_id):
    """Report an inappropriate review."""
    try:
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Please log in to report reviews'}), 401
            
        review = Review.query.get_or_404(review_id)
        review.reported = True
        db.session.commit()
        
        logger.info(f"Review {review_id} reported as inappropriate")
        return jsonify({
            'success': True,
            'message': 'Review has been reported'
        })
    except Exception as e:
        logger.error(f"Error reporting review: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error: {str(e)}"
        }), 500

# Mobile Navigation Routes
@web.route('/mobile-search')
def mobile_search():
    """Mobile search page with global search functionality."""
    query = request.args.get('q', '')
    procedures = []
    doctors = []
    
    if query:
        # Search procedures
        procedures = Procedure.query.filter(
            Procedure.name.ilike(f"%{query}%")
        ).limit(10).all()
        
        # Search doctors
        doctors = Doctor.query.filter(
            Doctor.name.ilike(f"%{query}%") |
            Doctor.specialization.ilike(f"%{query}%")
        ).limit(10).all()
    
    return render_template('mobile_search.html', 
                         procedures=procedures, 
                         doctors=doctors, 
                         query=query)

# Clinic dashboard route is handled by unified_clinic_dashboard.py blueprint

@web.route('/consult/book', methods=['GET', 'POST'])
def consult_booking():
    """Consultation booking form for mobile navigation."""
    if request.method == 'POST':
        # Handle consultation booking submission
        data = request.get_json()
        
        # Create a new lead for the consultation request
        lead = Lead(
            name=data.get('name'),
            phone=data.get('phone'),
            city=data.get('city'),
            procedure_interest=data.get('treatment'),
            message=data.get('message', ''),
            source='mobile_consult',
            status='pending',
            created_at=datetime.utcnow()
        )
        
        try:
            db.session.add(lead)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Consultation request submitted successfully'})
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error submitting consultation request: {str(e)}")
            return jsonify({'success': False, 'message': 'Error submitting request'})
    
    return render_template('consult_booking.html')



@web.route('/ai-assist')
def ai_assist():
    """AI Assist page showing AI recommendation card from homepage."""
    return render_template('ai_assist.html')

@web.route('/api/procedures')
def api_procedures():
    """API endpoint to get all procedures for autocomplete."""
    procedures = Procedure.query.all()
    procedure_list = []
    
    for procedure in procedures:
        procedure_list.append({
            'id': procedure.id,
            'name': procedure.name,
            'alternative_names': procedure.alternative_names if hasattr(procedure, 'alternative_names') else ''
        })
    
    return jsonify({'procedures': procedure_list})

@web.route('/api/procedures/load-more')
def api_procedures_load_more():
    """API endpoint for loading more procedures (Show More functionality)."""
    try:
        # Get pagination parameters
        offset = request.args.get('offset', 0, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        # Get filter parameters (same as main procedures route)
        category_id = request.args.get('category_id', type=int)
        search_query = request.args.get('search', '').strip()
        body_part = request.args.get('body_part', '').strip()
        sort_by = request.args.get('sort', 'popular')
        
        # Build query with same filters as main route
        base_query = Procedure.query
        
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    Procedure.procedure_name.ilike(f"%{search_query}%"),
                    Procedure.short_description.ilike(f"%{search_query}%"),
                    Procedure.overview.ilike(f"%{search_query}%"),
                    Procedure.body_part.ilike(f"%{search_query}%")
                )
            )
            
        if body_part:
            base_query = base_query.filter(Procedure.body_part.ilike(f"%{body_part}%"))
            
        if category_id:
            base_query = base_query.filter_by(category_id=category_id)
        
        # Apply sorting
        if sort_by == 'name':
            base_query = base_query.order_by(Procedure.procedure_name.asc())
        elif sort_by == 'popular':
            base_query = base_query.order_by(Procedure.id.desc())
        
        # Get total count and paginated results
        total_count = base_query.count()
        procedures = base_query.offset(offset).limit(limit).all()
        
        # Format procedures for JSON response
        procedures_data = []
        for procedure in procedures:
            procedures_data.append({
                'id': procedure.id,
                'procedure_name': procedure.procedure_name,
                'short_description': procedure.short_description,
                'min_cost': procedure.min_cost,
                'max_cost': procedure.max_cost,
                'body_part': procedure.body_part,
                'image_url': procedure.image_url if hasattr(procedure, 'image_url') else None
            })
        
        return jsonify({
            'success': True,
            'procedures': procedures_data,
            'total_count': total_count,
            'has_more': (offset + limit) < total_count
        })
        
    except Exception as e:
        logger.error(f"Error loading more procedures: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error loading more procedures'
        }), 500

@web.route('/api/doctors/load-more')
def api_doctors_load_more():
    """API endpoint for loading more doctors (Show More functionality)."""
    try:
        # Get pagination parameters
        offset = request.args.get('offset', 0, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        # Get filter parameters (same as main doctors route)
        category_id = request.args.get('category_id', type=int)
        procedure_id = request.args.get('procedure_id', type=int)
        sort_by = request.args.get('sort_by', 'experience_desc')
        search_query = request.args.get('search', '').strip()
        location = request.args.get('location', '').strip()
        specialty = request.args.get('specialty', '').strip()
        rating_filter = request.args.get('rating', '')
        
        # Build query with same filters as main route
        base_query = Doctor.query
        
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    Doctor.name.ilike(f"%{search_query}%"),
                    Doctor.specialty.ilike(f"%{search_query}%"),
                    Doctor.bio.ilike(f"%{search_query}%")
                )
            )
            
        if location:
            base_query = base_query.filter(Doctor.city.ilike(f"%{location}%"))
            
        if specialty:
            base_query = base_query.filter(Doctor.specialty.ilike(f"%{specialty}%"))
            
        if rating_filter:
            try:
                min_rating = float(rating_filter)
                base_query = base_query.filter(Doctor.rating >= min_rating)
            except ValueError:
                pass
                
        if category_id:
            base_query = base_query.join(DoctorCategory).filter(DoctorCategory.category_id == category_id)
        elif procedure_id:
            base_query = base_query.join(DoctorProcedure).filter(DoctorProcedure.procedure_id == procedure_id)
        
        # Apply sorting
        if sort_by == 'experience_desc':
            base_query = base_query.order_by(Doctor.experience.desc().nulls_last())
        elif sort_by == 'experience_asc':
            base_query = base_query.order_by(Doctor.experience.asc().nulls_last())
        elif sort_by == 'rating_desc':
            base_query = base_query.order_by(Doctor.rating.desc().nulls_last())
        elif sort_by == 'fee_asc':
            base_query = base_query.order_by(Doctor.consultation_fee.asc().nulls_last())
        elif sort_by == 'fee_desc':
            base_query = base_query.order_by(Doctor.consultation_fee.desc().nulls_last())
        elif sort_by == 'name_asc':
            base_query = base_query.order_by(Doctor.name.asc())
        else:
            base_query = base_query.order_by(Doctor.experience.desc().nulls_last())
        
        # Get total count and paginated results
        total_count = base_query.count()
        doctors = base_query.offset(offset).limit(limit).all()
        
        # Format doctors for JSON response
        doctors_data = []
        for doctor in doctors:
            doctors_data.append({
                'id': doctor.id,
                'name': doctor.name,
                'specialty': doctor.specialty,
                'experience': doctor.experience,
                'rating': doctor.rating,
                'consultation_fee': doctor.consultation_fee,
                'city': doctor.city,
                'profile_image': doctor.profile_image if hasattr(doctor, 'profile_image') else None
            })
        
        return jsonify({
            'success': True,
            'doctors': doctors_data,
            'total_count': total_count,
            'has_more': (offset + limit) < total_count
        })
        
    except Exception as e:
        logger.error(f"Error loading more doctors: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error loading more doctors'
        }), 500

@web.route('/personalization/track-interaction', methods=['POST'])
def track_interaction():
    """Track user interactions for personalization."""
    # This is an API endpoint used by frontend JS, so we handle CSRF differently
    try:
        from personalization_system import PersonalizationEngine
        
        # For API requests, we'll skip CSRF by checking if it's a programmatic request
        if not request.headers.get('X-Requested-With'):
            # If no X-Requested-With header, return success without tracking
            return jsonify({'success': True, 'message': 'Tracking skipped for security'}), 200
        
        # Get data from either JSON or form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        fingerprint = data.get('fingerprint')
        interaction_type = data.get('interaction_type')
        content_type = data.get('content_type')
        content_id = data.get('content_id', 0)
        content_name = data.get('content_name', '')
        page_url = data.get('page_url', '')
        session_id = data.get('session_id', '')
        
        if not fingerprint or not interaction_type or not content_type:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Track the interaction
        user_id = PersonalizationService.fingerprint_to_user_id(fingerprint)
        PersonalizationService.track_interaction(
            user_id=str(user_id),
            session_id=session_id,
            interaction_type=interaction_type,
            target_type=content_type,
            target_id=content_id if content_id else None,
            metadata={'content_name': content_name, 'page_url': page_url}
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error tracking interaction: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@web.route('/personalization/recommendations/<content_type>')
def get_personalized_recommendations(content_type):
    """Get personalized content recommendations."""
    try:
        from personalization_system import PersonalizationEngine
        
        # Get fingerprint from query parameters or headers
        fingerprint = request.args.get('fingerprint')
        if not fingerprint:
            return jsonify({'success': False, 'error': 'Fingerprint required'}), 400
        
        limit = int(request.args.get('limit', 10))
        
        # Get personalized content
        recommendations = PersonalizationService.get_personalized_content(
            fingerprint, content_type, limit
        )
        
        return jsonify({
            'success': True,
            'recommendations': recommendations,
            'content_type': content_type,
            'count': len(recommendations)
        })
        
    except Exception as e:
        logger.error(f"Error getting personalized recommendations: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

def register_routes(app):
    """Register blueprints with the Flask app."""
    
    # Register enhanced lead generation system with Firebase OTP
    try:
        from enhanced_lead_generation import lead_bp, inject_firebase_config
        app.register_blueprint(lead_bp)
        app.context_processor(inject_firebase_config)
        logger.info("Enhanced lead generation system with Firebase OTP registered successfully.")
    except ImportError as e:
        logger.warning(f"Enhanced lead generation system not found: {e}")
    
    # Register clean AI recommendation system
    try:
        from ai_recommendations_clean import ai_bp
        app.register_blueprint(ai_bp)
        logger.info("Clean AI recommendation system registered successfully.")
    except ImportError as e:
        logger.warning(f"Clean AI recommendation system not found: {e}")
    
    # Register enhanced lead capture systems first
    
    try:
        from enhanced_face_analysis import enhanced_face_bp
        app.register_blueprint(enhanced_face_bp)
        logger.info("Enhanced face analysis system with lead capture registered successfully.")
    except ImportError as e:
        logger.warning(f"Enhanced face analysis system not found: {e}")
    
    try:
        from enhanced_cost_calculator import enhanced_cost_bp
        app.register_blueprint(enhanced_cost_bp)
        logger.info("Enhanced cost calculator system with lead capture registered successfully.")
    except ImportError as e:
        logger.warning(f"Enhanced cost calculator system not found: {e}")
    
    try:
        from comprehensive_admin_dashboard import comprehensive_admin_bp
        app.register_blueprint(comprehensive_admin_bp)
        logger.info("Comprehensive admin dashboard for lead analytics registered successfully.")
    except ImportError as e:
        logger.warning(f"Comprehensive admin dashboard not found: {e}")
    # Import new API routes
    from api_routes import api_bp
    from community_routes import community_api
    from community_reply_routes import community_reply_api, thread_reply_web
    from user_routes import user_api
    from message_routes import message_api
    from notification_routes import notification_api
    from moderation_routes import moderation_api
    from verify_doctor_api import verification_api
    from google_reviews_routes import google_reviews_bp
    
    # Import admin dashboard debug blueprint
    try:
        from admin_dashboard_debug import debug_blueprint
        logger.info("Admin dashboard debug blueprint imported successfully.")
    except ImportError:
        logger.warning("Admin dashboard debug blueprint not found.")
        debug_blueprint = None
    
    # Import new community API routes
    try:
        from community_api_routes import api as community_api_routes
        logger.info("Community API routes imported successfully.")
    except ImportError:
        logger.warning("Community API routes not found. API endpoints will not be available.")
        community_api_routes = None
        
    # Old AI recommendation routes removed - using clean system instead
    
    # Import enhanced community routes
    try:
        from community_enhanced import community_bp
        logger.info("Enhanced community routes imported successfully.")
    except ImportError:
        logger.warning("Enhanced community routes not found.")
        community_bp = None
    
    # Import education routes
    try:
        from education_routes import education
        logger.info("Education routes imported successfully.")
    except ImportError:
        logger.warning("Education routes not found. Health education modules will not be available.")
        education = None
        
    # Face scan feature has been removed
        
    # Import cost calculator routes
    try:
        from cost_calculator_routes import cost_calculator_bp
        logger.info("Cost calculator routes imported successfully.")
    except ImportError:
        logger.warning("Cost calculator routes not found. Treatment cost calculator will not be available.")
        cost_calculator_bp = None
    
    # Import enhanced package routes
    try:
        from enhanced_package_routes import enhanced_package_bp
        logger.info("Enhanced package routes imported successfully.")
    except ImportError:
        logger.warning("Enhanced package routes not found. Enhanced package functionality will not be available.")
        enhanced_package_bp = None
    
    # Import new community thread routes
    try:
        from community_thread_routes import web as community_thread_web, api as community_trends_api
    except ImportError:
        logger.warning("Community thread routes not found. New thread creation and real-time updates will not be available.")
        community_thread_web = None
        community_trends_api = None
        
    # Import community reply routes
    try:
        from community_reply_routes import reply_web, thread_reply_web, community_thread_replies_api
        logger.info("Community reply routes imported successfully.")
    except ImportError:
        logger.warning("Community reply routes not found. Reply functionality will not be available.")
        reply_web = None
        thread_reply_web = None
        community_thread_replies_api = None
    
    # GlowUp Community functional routes removed
    
    # Main blueprints will be registered at the end to avoid conflicts
    
    # SEO optimization system - content landing pages disabled temporarily
    logger.info("SEO optimization - core infrastructure active, content pages disabled for debugging.")
    
    # Register API module blueprints
    app.register_blueprint(community_api)
    app.register_blueprint(community_reply_api)
    app.register_blueprint(user_api)
    app.register_blueprint(message_api)
    app.register_blueprint(notification_api)
    app.register_blueprint(moderation_api)
    app.register_blueprint(verification_api)
    
    # Register new community API routes
    if community_api_routes:
        app.register_blueprint(community_api_routes)
        logger.info("Community API blueprint registered successfully.")
    
    # Old AI recommendation routes removed - using clean system instead
        
    # Register education routes
    if education:
        app.register_blueprint(education)
        logger.info("Education blueprint registered successfully.")
        
    # Face scan feature has been removed
    
    # Register face analysis routes
    try:
        from face_analysis_routes import face_analysis
        app.register_blueprint(face_analysis)
        logger.info("Face analysis blueprint registered successfully.")
    except ImportError:
        logger.warning("Face analysis routes not found. Face analysis feature will not be available.")
        
    # Register cost calculator routes
    if cost_calculator_bp:
        app.register_blueprint(cost_calculator_bp)
        logger.info("Cost calculator blueprint registered successfully.")
    
    # Register payment routes for credit billing system
    try:
        from payment_routes import payment_bp
        app.register_blueprint(payment_bp)
        logger.info("Payment routes registered successfully.")
    except ImportError:
        logger.warning("Payment routes not found. Credit billing system will not be available.")
    
    # DISABLED: Legacy billing systems to prevent conflicts
    # Register simplified billing system with promo codes as PRIMARY billing system
    try:
        from simple_billing_system import simple_billing
        app.register_blueprint(simple_billing, url_prefix='/clinic')
        logger.info("Simplified billing system with promo codes registered successfully as primary billing system.")
    except ImportError:
        logger.warning("Simplified billing system not found.")
    
    # DISABLED: Old integrated billing system
    # try:
    #     from integrated_billing_system import integrated_billing_bp
    #     app.register_blueprint(integrated_billing_bp, url_prefix='/clinic')
    #     logger.info("Integrated billing system registered successfully.")
    # except ImportError:
    #     logger.warning("Integrated billing system not found.")
    
    # DISABLED: Enhanced credit billing to prevent route conflicts
    # try:
    #     from enhanced_credit_billing import enhanced_billing_bp
    #     app.register_blueprint(enhanced_billing_bp, url_prefix='/payment')
    #     logger.info("Enhanced credit billing system registered successfully at /payment prefix.")
    # except ImportError:
    #     logger.warning("Enhanced credit billing system not found.")
    
    # Register admin credit management system
    try:
        from admin_credit_system import admin_credit_bp
        app.register_blueprint(admin_credit_bp, url_prefix='/')
        logger.info("Admin credit management system registered successfully.")
    except ImportError:
        logger.warning("Admin credit management system not found.")
    
    # Register dynamic lead pricing system
    try:
        from dynamic_lead_pricing import pricing_bp
        app.register_blueprint(pricing_bp, url_prefix='/')
        logger.info("Dynamic lead pricing system registered successfully.")
    except ImportError:
        logger.warning("Dynamic lead pricing system not found.")
    
    # Admin transaction history integrated into main web blueprint
    # Removed separate blueprint to avoid endpoint conflicts
    
    # Register dispute management system (conditional to avoid conflicts)
    try:
        app.register_blueprint(dispute_bp, url_prefix='/')
        logger.info("Dispute management system registered successfully.")
    except Exception as e:
        logger.warning(f"Dispute management system registration failed: {str(e)}")
    
    # Register enhanced lead capture with credit processing
    try:
        from enhanced_lead_capture import enhanced_lead_bp
        app.register_blueprint(enhanced_lead_bp, url_prefix='/')
        logger.info("Enhanced lead capture with credit processing registered successfully.")
    except ImportError:
        logger.warning("Enhanced lead capture system not found.")
    
    # Enhanced lead generation already registered above at line 7336
    
    # Register lead notification system
    try:
        from lead_notification_system import notification_bp
        app.register_blueprint(notification_bp, url_prefix='/api')
        logger.info("Lead notification system registered successfully.")
    except ImportError:
        logger.warning("Lead notification system not found.")
    
    # Register lead disputes system
    try:
        from lead_disputes_system import disputes_bp
        app.register_blueprint(disputes_bp, url_prefix='/clinic')
        logger.info("Lead disputes system registered successfully.")
    except ImportError:
        logger.warning("Lead disputes system not found.")
        
    # Enhanced package routes are registered below with the main package registration
        
    # Register admin dashboard debug blueprint
    if debug_blueprint:
        app.register_blueprint(debug_blueprint)
        logger.info("Admin dashboard debug blueprint registered successfully.")
    
    # Clinic and package routes are now handled by enhanced blueprints above
    
    # Register complete Gangnam Unni feature set
    try:
        from enhanced_review_system import enhanced_reviews_bp
        app.register_blueprint(enhanced_reviews_bp)
        logger.info("Enhanced review system registered successfully.")
    except ImportError:
        logger.warning("Enhanced review system not found.")
    
    try:
        from virtual_consultation_system import virtual_consultation_bp
        app.register_blueprint(virtual_consultation_bp)
        logger.info("Virtual consultation system registered successfully.")
    except ImportError:
        logger.warning("Virtual consultation system not found.")
    
    try:
        from social_community_system import social_community_bp
        app.register_blueprint(social_community_bp)
        logger.info("Social community system registered successfully.")
    except ImportError:
        logger.warning("Social community system not found.")
    
    try:
        from price_transparency_system import price_transparency_bp
        app.register_blueprint(price_transparency_bp)
        logger.info("Price transparency system registered successfully.")
    except ImportError:
        logger.warning("Price transparency system not found.")
    
    try:
        from enhanced_booking_features import enhanced_booking_bp
        app.register_blueprint(enhanced_booking_bp)
        logger.info("Enhanced booking features registered successfully.")
    except ImportError:
        logger.warning("Enhanced booking features not found.")
    
    # Register authentic Gangnam Unni services & pricing system
    try:
        from gangnam_unni_services_pricing import gangnam_services_bp
        app.register_blueprint(gangnam_services_bp)
        logger.info("Gangnam Unni services & pricing system registered successfully.")
    except ImportError:
        logger.warning("Gangnam Unni services & pricing system not found.")
    
    # Register new community thread routes - DISABLED to prevent conflicts with main web routes
    # The main web blueprint handles /community/thread/<id> routes
    # if community_thread_web:
    #     app.register_blueprint(community_thread_web)
    if community_trends_api:
        app.register_blueprint(community_trends_api)
        
    # Register community reply routes
    if reply_web:
        app.register_blueprint(reply_web)
        app.register_blueprint(thread_reply_web)
        if community_thread_replies_api:
            app.register_blueprint(community_thread_replies_api)
        logger.info("Community reply blueprint registered successfully.")
    
    # Register enhanced community blueprint - DISABLED to prevent conflicts with main web routes
    # The main web blueprint handles /community/thread/<id> routes
    # if community_bp:
    #     app.register_blueprint(community_bp)
    #     logger.info("Enhanced community blueprint registered successfully.")
    
    # Import and register banner routes
    try:
        from banner_routes import banner_bp, banner_api_bp
        app.register_blueprint(banner_bp)
        app.register_blueprint(banner_api_bp)
        logger.info("Banner routes registered successfully.")
    except ImportError:
        logger.warning("Banner routes not found. Banner management will not be available.")
    
    # GlowUp Community routes removed
    
    # Register Modern Community API
    try:
        from community_modern_api import register_community_modern_api
        register_community_modern_api(app)
        logger.info("Modern Community API registered successfully.")
    except ImportError:
        logger.warning("Modern Community API not found.")
    
    # Register Reddit Import System
    try:
        from reddit_import import register_reddit_import
        register_reddit_import(app)
        logger.info("Reddit Import System registered successfully.")
    except ImportError:
        logger.warning("Reddit Import System not found.")
    
    # Register the main web blueprint (contains homepage and core routes)
    try:
        app.register_blueprint(web)
        app.register_blueprint(api)
        app.register_blueprint(api_bp)
        logger.info("Main web and API blueprints registered successfully.")
    except ValueError as e:
        if "already registered" in str(e):
            logger.info("Main web blueprint already registered, skipping.")
        else:
            raise e
    
    # We'll use direct methods for verification instead of API endpoints
    # This is defined in verify_doctor_workflow.py
    
    # Unified clinic dashboard routes are registered in app.py to avoid conflicts
    
    # Register clinic routes for marketplace functionality
    try:
        from clinic_routes import clinic_bp
        app.register_blueprint(clinic_bp)
        logger.info("Clinic marketplace routes registered successfully.")
    except Exception as e:
        logger.error(f"Error registering clinic routes: {e}")
    
    # Register ONLY enhanced package routes (replaces old package routes completely)
    if enhanced_package_bp:
        try:
            app.register_blueprint(enhanced_package_bp)
            logger.info("Enhanced package routes registered successfully.")
        except Exception as e:
            logger.error(f"Error registering enhanced package routes: {e}")
            # Do not fallback to basic routes - enhanced routes are required
    
    # Register Google Reviews management system
    try:
        app.register_blueprint(google_reviews_bp, url_prefix='/')
        logger.info("Google Reviews management system registered successfully.")
    except Exception as e:
        logger.warning(f"Google Reviews management system registration failed: {e}")
    
    # Register admin clinic routes
    try:
        from admin_clinic_routes import register_admin_clinic_routes
        register_admin_clinic_routes(app)
        logger.info("Admin clinic application routes registered successfully.")
    except Exception as e:
        logger.error(f"Error registering admin clinic routes: {e}")
    
    # Note: Basic package routes are now disabled to prevent conflicts



# CLINIC DASHBOARD ROUTES - handled by unified_clinic_dashboard.py blueprint

@web.route("/clinic/leads")
@login_required
def clinic_leads():
    """Clinic leads management page."""
    try:
        # Get clinic for current user
        clinic_result = db.session.execute(text("""
            SELECT * FROM clinics WHERE owner_user_id = :user_id
        """), {"user_id": current_user.id}).fetchone()
        
        if not clinic_result:
            flash("No clinic found for your account.", "error")
            return redirect(url_for("web.index"))
        
        clinic = dict(clinic_result._mapping)
        
        # Get all leads for this clinic
        leads = db.session.execute(text("""
            SELECT l.*, u.name as user_name, u.phone_number as user_phone
            FROM leads l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.clinic_id = :clinic_id
            ORDER BY l.created_at DESC
        """), {"clinic_id": clinic["id"]}).fetchall()
        
        return render_template("clinic_leads.html",
                             clinic=clinic,
                             leads=leads)
        
    except Exception as e:
        logger.error(f"Error in clinic leads: {e}")
        db.session.rollback()
        flash("Error loading leads. Please try again.", "error")
        return redirect(url_for("web.clinic_dashboard"))

@web.route('/admin/transaction-history')
@login_required
def admin_transaction_history():
    """Admin transaction history with comprehensive filtering and audit trails."""
    from admin_transaction_history import AdminHistoryService
    
    # Check admin access
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('web.index'))
    
    try:
        # Get filter parameters
        clinic_id = request.args.get('clinic_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        transaction_type = request.args.get('transaction_type', 'all')
        
        # Convert date strings to datetime objects with validation
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            except ValueError:
                flash('Invalid start date format. Please use YYYY-MM-DD format.', 'error')
                return redirect(url_for("admin_credit.credit_dashboard"))
                
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
            except ValueError:
                flash('Invalid end date format. Please use YYYY-MM-DD format.', 'error')
                return redirect(url_for("admin_credit.credit_dashboard"))
        
        # Validate date range logic
        if start_date and end_date and start_date > end_date:
            flash('Start date cannot be after end date. Please check your date range.', 'error')
            return redirect(url_for("admin_credit.credit_dashboard"))
        
        # Get transaction history
        transactions = AdminHistoryService.get_credit_allocation_history(
            clinic_id=clinic_id,
            start_date=start_date,
            end_date=end_date
        )
        
        # Get all clinics for filter dropdown
        clinics = db.session.execute(text("""
            SELECT id, name FROM clinics WHERE is_approved = true ORDER BY name
        """)).fetchall()
        
        # Calculate comprehensive summary statistics
        total_transactions = len(transactions)
        total_allocated = sum(t['amount'] for t in transactions if t['amount'] > 0)
        total_refunds = sum(abs(t['amount']) for t in transactions if t['amount'] < 0)
        total_adjustments = sum(t['amount'] for t in transactions if t['transaction_type'] == 'adjustment')
        unique_clinics = len(set(t['clinic_id'] for t in transactions if t.get('clinic_id')))
        
        summary = {
            'total_transactions': total_transactions,
            'total_allocated': total_allocated,
            'total_refunds': total_refunds,
            'total_adjustments': total_adjustments,
            'unique_clinics': unique_clinics,
            'net_allocation': total_allocated - total_refunds
        }
        
        return render_template('admin/transaction_history.html',
                             transactions=transactions,
                             clinics=clinics,
                             stats=summary,
                             selected_clinic=clinic_id,
                             start_date=start_date.strftime('%Y-%m-%d') if start_date else '',
                             end_date=end_date.strftime('%Y-%m-%d') if end_date else '',
                             transaction_type=transaction_type)
        
    except Exception as e:
        logger.error(f"Error in admin transaction history: {e}")
        flash("Error loading transaction history. Please try again.", "error")
        return redirect(url_for("admin_credit.credit_dashboard"))

@web.route("/clinic/billing")
@login_required
def clinic_billing():
    """Clinic billing and credit management."""
    try:
        # Get clinic for current user
        clinic_result = db.session.execute(text("""
            SELECT * FROM clinics WHERE owner_user_id = :user_id
        """), {"user_id": current_user.id}).fetchone()
        
        if not clinic_result:
            flash("No clinic found for your account.", "error")
            return redirect(url_for("web.index"))
        
        clinic = dict(clinic_result._mapping)
        
        # Get current credit balance
        credit_balance = db.session.execute(text("""
            SELECT COALESCE(
                (SELECT SUM(amount) FROM credit_transactions 
                 WHERE clinic_id = :clinic_id AND transaction_type = 'credit') -
                (SELECT SUM(amount) FROM credit_transactions 
                 WHERE clinic_id = :clinic_id AND transaction_type = 'deduction'), 
                0
            ) as balance
        """), {"clinic_id": clinic["id"]}).scalar() or 0
        
        # Get recent transactions
        transactions = db.session.execute(text("""
            SELECT * FROM credit_transactions 
            WHERE clinic_id = :clinic_id
            ORDER BY created_at DESC
            LIMIT 20
        """), {"clinic_id": clinic["id"]}).fetchall()
        
        # Credit packages
        credit_packages = [
            {"credits": 1000, "price": 5000, "bonus": 0, "popular": False},
            {"credits": 2500, "price": 12000, "bonus": 100, "popular": True},
            {"credits": 5000, "price": 22500, "bonus": 500, "popular": False},
            {"credits": 10000, "price": 42000, "bonus": 1500, "popular": False},
        ]
        
        return render_template("clinic_billing.html",
                             clinic=clinic,
                             credit_balance=credit_balance,
                             transactions=transactions,
                             credit_packages=credit_packages)
        
    except Exception as e:
        logger.error(f"Error in clinic billing: {e}")
        db.session.rollback()
        flash("Error loading billing information. Please try again.", "error")
        return redirect(url_for("web.clinic_dashboard"))

