from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, JSON, ARRAY, Numeric
from sqlalchemy.orm import relationship, backref
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
import json

# GlowUp models will be integrated directly to avoid conflicts
# Clinic management models integrated for Gangnam Unni-style platform

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BodyPart(db.Model):
    """Body parts table to store anatomical areas."""
    __tablename__ = 'body_parts'
    
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    description = Column(Text)
    icon_url = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    categories = relationship("Category", back_populates="body_part", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<BodyPart {self.name}>"

class Category(db.Model):
    """Categories table to group procedures by body part."""
    __tablename__ = 'categories'
    
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    body_part_id = Column(Integer, ForeignKey('body_parts.id'), nullable=False)
    description = Column(Text)
    image_url = Column(Text)  # Field for beautiful medical procedure images
    popularity_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    body_part = relationship("BodyPart", back_populates="categories")
    procedures = relationship("Procedure", back_populates="category", cascade="all, delete-orphan")
    doctor_categories = relationship("DoctorCategory", back_populates="category", cascade="all, delete-orphan")
    community_threads = relationship("Community", back_populates="category")
    community_taggings = relationship("CommunityTagging", back_populates="category")
    
    def __repr__(self):
        return f"<Category {self.name}>"

class Procedure(db.Model):
    """Procedures table as the platform core."""
    __tablename__ = 'procedures'
    
    id = Column(Integer, primary_key=True)
    procedure_name = Column(Text, nullable=False, unique=True)
    alternative_names = Column(Text)  # New field: alternative names for procedures
    short_description = Column(Text, nullable=False)
    overview = Column(Text, nullable=False)
    procedure_details = Column(Text, nullable=False)
    ideal_candidates = Column(Text, nullable=False)
    recovery_process = Column(Text)
    recovery_time = Column(Text, nullable=False)
    procedure_duration = Column(Text)  # New field: duration of the procedure
    hospital_stay_required = Column(Text)  # New field: whether hospital stay is required (yes/no)
    results_duration = Column(Text)
    min_cost = Column(Integer, nullable=False)
    max_cost = Column(Integer, nullable=False)
    benefits = Column(Text)
    benefits_detailed = Column(Text)
    risks = Column(Text, nullable=False)
    procedure_types = Column(Text, nullable=False)
    alternative_procedures = Column(Text)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    popularity_score = Column(Integer, default=0)
    avg_rating = Column(Float, default=0)
    review_count = Column(Integer, default=0)
    is_featured = Column(Boolean, default=False)  # Field to mark procedures as featured
    image_url = Column(Text)  # Field for procedure images
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # RealSelf structure aligned fields
    # Renamed from body_area to body_part (e.g., Face, Breast)
    body_part = Column(Text)
    # Renamed from category_type to tags (ARRAY of strings) for Surgical/Non-Surgical tags
    tags = Column(ARRAY(String(20)))
    # category column will hold broad treatment focuses (e.g., Rhinoplasty, Breast Augmentation)
    # This is using the existing category relationship
    
    # Legacy fields for backward compatibility during migration
    body_area = Column(Text)
    category_type = Column(Text)
    
    # Relationships
    category = relationship("Category", back_populates="procedures")
    doctor_procedures = relationship("DoctorProcedure", back_populates="procedure", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="procedure", cascade="all, delete-orphan")
    community_threads = relationship("Community", back_populates="procedure")
    community_taggings = relationship("CommunityTagging", back_populates="procedure")
    
    def __repr__(self):
        return f"<Procedure {self.procedure_name}>"

class User(UserMixin, db.Model):
    """Users table for all accounts."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    phone_number = Column(Text, nullable=False, unique=True)
    firebase_uid = Column(Text, unique=True)
    name = Column(Text, nullable=False)
    email = Column(Text, unique=True)
    role = Column(Text, nullable=False, default='user')
    username = Column(Text, unique=True)  # Added username field
    password_hash = Column(Text)  # Added for password-based auth
    role_type = Column(Text)  # Added role_type for user/doctor/expert
    bio = Column(Text)  # Added bio for user profile
    badge = Column(ARRAY(Text))  # Added badge array
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime)
    is_verified = Column(Boolean, default=False)
    saved_items = Column(JSON)
    points = Column(Integer, default=0)  # Gamification points
    
    # Relationships
    doctor = relationship("Doctor", back_populates="user", uselist=False, cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="user", cascade="all, delete-orphan")
    community_threads = relationship("Community", foreign_keys="Community.user_id", back_populates="user", cascade="all, delete-orphan")
    community_replies = relationship("CommunityReply", back_populates="user", cascade="all, delete-orphan")
    interactions = relationship("Interaction", back_populates="user", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    preferences = relationship("UserPreference", back_populates="user", uselist=False, cascade="all, delete-orphan")
    leads = relationship("Lead", back_populates="user", cascade="all, delete-orphan")
    # New relationships
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    moderations = relationship("CommunityModeration", back_populates="moderator", cascade="all, delete-orphan")
    appointments = relationship("Appointment", back_populates="user", foreign_keys="Appointment.user_id")
    
    def set_password(self, password):
        """Set the password hash from a plain text password"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if the provided password matches the hash"""
        if self.password_hash is not None:
            return check_password_hash(str(self.password_hash), password)
        return False
    
    def __repr__(self):
        return f"<User {self.username or self.name}>"

class Doctor(db.Model):
    """Doctors table for profiles."""
    __tablename__ = 'doctors'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(Text, nullable=False)
    specialty = Column(Text, nullable=False)
    experience = Column(Integer, nullable=False)
    city = Column(Text, nullable=False)
    state = Column(Text)
    hospital = Column(Text)
    consultation_fee = Column(Integer)
    is_verified = Column(Boolean, default=False)
    rating = Column(Float, default=0)
    review_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    bio = Column(Text)
    certifications = Column(JSON)
    video_url = Column(Text)
    success_stories = Column(Integer, default=0)
    education = Column(JSON)
    # Profile image fields
    profile_image = Column(Text)  # Path or URL to profile image
    image_url = Column(Text)      # Original source URL for the image
    # New fields for verification
    medical_license_number = Column(Text, unique=True)
    qualification = Column(Text)
    practice_location = Column(Text)
    verification_status = Column(Text, default='pending')  # pending, approved, rejected
    verification_date = Column(DateTime)  # When verification status was last updated
    verification_notes = Column(Text)  # Notes about verification (especially for rejections)
    credentials_url = Column(Text)
    aadhaar_number = Column(Text)  # For India verification
    
    # Clinic relationship field
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=True)  # Link to clinic
    
    # Relationships
    user = relationship("User", back_populates="doctor")
    clinic = relationship("Clinic", back_populates="doctors")
    doctor_categories = relationship("DoctorCategory", back_populates="doctor", cascade="all, delete-orphan")
    doctor_procedures = relationship("DoctorProcedure", back_populates="doctor", cascade="all, delete-orphan")
    doctor_photos = relationship("DoctorPhoto", back_populates="doctor", cascade="all, delete-orphan")
    doctor_availability = relationship("DoctorAvailability", back_populates="doctor", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="doctor", cascade="all, delete-orphan")
    leads = relationship("Lead", back_populates="doctor", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Doctor {self.name}>"

class DoctorCategory(db.Model):
    """Doctor categories junction table for doctor specializations."""
    __tablename__ = 'doctor_categories'
    
    id = Column(Integer, primary_key=True)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_verified = Column(Boolean, default=False)
    
    # Relationships
    doctor = relationship("Doctor", back_populates="doctor_categories")
    category = relationship("Category", back_populates="doctor_categories")
    
    def __repr__(self):
        return f"<DoctorCategory doctor_id={self.doctor_id} category_id={self.category_id}>"

class DoctorProcedure(db.Model):
    """Doctor procedures junction table."""
    __tablename__ = 'doctor_procedures'
    
    id = Column(Integer, primary_key=True)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    procedure_id = Column(Integer, ForeignKey('procedures.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    doctor = relationship("Doctor", back_populates="doctor_procedures")
    procedure = relationship("Procedure", back_populates="doctor_procedures")
    
    def __repr__(self):
        return f"<DoctorProcedure doctor_id={self.doctor_id} procedure_id={self.procedure_id}>"

class Review(db.Model):
    """Reviews table for feedback."""
    __tablename__ = 'reviews'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    doctor_id = Column(Integer, ForeignKey('doctors.id'))
    procedure_id = Column(Integer, ForeignKey('procedures.id'))
    rating = Column(Float, nullable=False)
    content = Column(Text)
    photo = Column(Text)
    verified_purchase = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    helpful_count = Column(Integer, default=0)
    reported = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="reviews")
    doctor = relationship("Doctor", back_populates="reviews")
    procedure = relationship("Procedure", back_populates="reviews")
    replies = relationship("ReviewReply", back_populates="review", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Review {self.id} by user_id={self.user_id}>"
        
class ReviewReply(db.Model):
    """Doctor replies to reviews."""
    __tablename__ = 'review_replies'
    
    id = Column(Integer, primary_key=True)
    review_id = Column(Integer, ForeignKey('reviews.id'), nullable=False)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    reply_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    review = relationship("Review", back_populates="replies")
    doctor = relationship("Doctor", backref="review_replies")
    
    def __repr__(self):
        return f"<ReviewReply {self.id} for review_id={self.review_id} by doctor_id={self.doctor_id}>"
    
class FaceAnalysis(db.Model):
    """Model for storing face analysis results."""
    
    __tablename__ = 'face_analyses'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    image_path = Column(Text, nullable=False)
    analysis_data = Column(JSON, nullable=False)
    geometric_analysis_data = Column(JSON, nullable=True)
    mathematical_scores = Column(JSON, nullable=True)
    has_geometric_analysis = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_anonymous = Column(Boolean, default=False)
    
    # Relationships
    user = relationship('User', backref=backref('face_analyses', cascade='all, delete-orphan'))
    recommendations = relationship('FaceAnalysisRecommendation', backref='analysis', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<FaceAnalysis {self.id}>'

class FaceAnalysisRecommendation(db.Model):
    """Model for storing face analysis recommendations."""
    
    __tablename__ = 'face_analysis_recommendations'
    
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey('face_analyses.id'), nullable=False)
    recommendation_type = Column(Text, nullable=False)  # 'skin', 'structure', or 'surgical'
    feature_name = Column(Text, nullable=False)
    severity_score = Column(Float, nullable=False)
    recommendation_details = Column(Text)
    treatment_options = Column(Text)
    needs_surgery = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<FaceAnalysisRecommendation {self.id} - Analysis {self.analysis_id}>'


class Community(db.Model):
    """Enhanced Community table with all modern features."""
    __tablename__ = 'community'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    title = Column(Text, nullable=False)
    content = Column(Text, nullable=False)
    is_anonymous = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    view_count = Column(Integer, default=0)
    reply_count = Column(Integer, default=0)
    featured = Column(Boolean, default=False)
    tags = Column(ARRAY(Text))
    category_id = Column(Integer, ForeignKey('categories.id'))
    procedure_id = Column(Integer, ForeignKey('procedures.id'))
    
    # Enhanced features
    parent_id = Column(Integer, ForeignKey('community.id'))  # For nested replies
    upvotes = Column(Integer, default=0)
    downvotes = Column(Integer, default=0)
    total_votes = Column(Integer, default=0)
    photo_url = Column(Text)  # Image uploads
    video_url = Column(Text)  # Video uploads
    is_pinned = Column(Boolean, default=False)
    is_locked = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    deleted_reason = Column(Text)
    doctor_verified = Column(Boolean, default=False)  # Verified doctor response
    trending_score = Column(Float, default=0.0)  # Calculated trending score
    
    # Rich content support
    content_type = Column(Text, default='text')  # text, image, video, poll
    poll_options = Column(JSON)  # For polls
    poll_votes = Column(JSON)  # Poll vote counts
    
    # Reddit Integration Features
    source_type = Column(Text, default='native')  # 'native', 'reddit', 'imported'
    source_url = Column(Text)  # Original Reddit URL for imported posts
    source_metadata = Column(JSON)  # Reddit post data, author info, etc.
    reddit_id = Column(Text)  # Original Reddit post ID
    reddit_author = Column(Text)  # Original Reddit username
    imported_at = Column(DateTime)  # When the post was imported
    imported_by_admin = Column(Integer, ForeignKey('users.id'))  # Which admin imported it
    engagement_score = Column(Float, default=0.0)  # Reddit-style engagement ranking
    media_urls = Column(ARRAY(Text))  # Array of image/video URLs from Reddit
    is_professional_verified = Column(Boolean, default=False)  # Expert/doctor verification
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="community_threads")
    imported_by_user = relationship("User", foreign_keys=[imported_by_admin])
    category = relationship("Category", back_populates="community_threads")
    procedure = relationship("Procedure", back_populates="community_threads")
    replies = relationship("CommunityReply", back_populates="thread", cascade="all, delete-orphan")
    taggings = relationship("CommunityTagging", back_populates="community", cascade="all, delete-orphan")
    parent_thread = relationship("Community", remote_side=[id], backref=backref("child_threads", cascade="all, delete-orphan"))
    moderations = relationship("CommunityModeration", foreign_keys="CommunityModeration.community_id", back_populates="community", cascade="all, delete-orphan")
    votes = relationship("ThreadVote", back_populates="thread", cascade="all, delete-orphan")
    saves = relationship("ThreadSave", back_populates="thread", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Community {self.title}>"

class CommunityReply(db.Model):
    """Community replies table."""
    __tablename__ = 'community_replies'
    
    id = Column(Integer, primary_key=True)
    thread_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    content = Column(Text, nullable=False)
    is_anonymous = Column(Boolean, default=False)
    is_doctor_response = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    upvotes = Column(Integer, default=0)
    # New fields
    parent_reply_id = Column(Integer, ForeignKey('community_replies.id'))  # For nested replies
    is_expert_advice = Column(Boolean, default=False)  # Expert flag
    is_ai_response = Column(Boolean, default=False)  # AI flag
    photo_url = Column(Text)  # For image upload
    video_url = Column(Text)  # For video upload
    
    # Relationships
    thread = relationship("Community", back_populates="replies")
    user = relationship("User", back_populates="community_replies")
    # New relationships
    parent_reply = relationship("CommunityReply", remote_side=[id], backref=backref("child_replies", cascade="all, delete-orphan"))
    moderations = relationship("CommunityModeration", foreign_keys="CommunityModeration.reply_id", back_populates="reply", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<CommunityReply {self.id} to thread_id={self.thread_id}>"

class CommunityTagging(db.Model):
    """Community tagging table for AI clustering."""
    __tablename__ = 'community_tagging'
    
    id = Column(Integer, primary_key=True)
    community_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    procedure_id = Column(Integer, ForeignKey('procedures.id'))
    confidence_score = Column(Float)
    user_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    community = relationship("Community", back_populates="taggings")
    category = relationship("Category", back_populates="community_taggings")
    procedure = relationship("Procedure", back_populates="community_taggings")
    
    def __repr__(self):
        return f"<CommunityTagging {self.id} for community_id={self.community_id}>"

class ClinicApplication(db.Model):
    """Model to store clinic applications from Google Forms before approval."""
    __tablename__ = 'clinic_applications'
    
    id = Column(Integer, primary_key=True)
    
    # Application Data
    clinic_name = Column(String(200), nullable=False)
    contact_person = Column(String(100), nullable=False)
    email = Column(String(120), nullable=False)
    phone = Column(String(20), nullable=False)
    address = Column(Text, nullable=False)
    city = Column(String(100), nullable=False)
    state = Column(String(100), nullable=False)
    pincode = Column(String(10))
    website = Column(String(200))
    specialties = Column(Text)  # Comma-separated
    description = Column(Text)
    
    # Application Status
    status = Column(String(20), default='pending')  # pending, approved, rejected
    notes = Column(Text)  # Internal admin notes
    rejection_reason = Column(Text)
    
    # Processing Info
    processed_by_user_id = Column(Integer, ForeignKey('users.id'))
    processed_at = Column(DateTime)
    created_clinic_id = Column(Integer, ForeignKey('clinics.id'))  # Set when approved
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    processed_by = relationship("User", foreign_keys=[processed_by_user_id])
    created_clinic = relationship("Clinic", foreign_keys=[created_clinic_id])
    
    def __repr__(self):
        return f"<ClinicApplication {self.clinic_name} - {self.status}>"

class UserPreference(db.Model):
    """User preferences table."""
    __tablename__ = 'user_preferences'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    preferred_procedures = Column(JSON)
    body_focus = Column(Text)
    budget_range = Column(JSON)
    notification_prefs = Column(JSON)
    
    # Relationships
    user = relationship("User", back_populates="preferences")
    
    def __repr__(self):
        return f"<UserPreference for user_id={self.user_id}>"

class Notification(db.Model):
    """Notifications table."""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    message = Column(Text, nullable=False)
    type = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # New fields
    mentioned_username = Column(Text)  # Username mentioned in post
    response_type = Column(Text)  # Type of response (doctor, expert, ai)
    
    # Relationships
    user = relationship("User", back_populates="notifications")
    
    def __repr__(self):
        return f"<Notification {self.id} for user_id={self.user_id}>"

# New enhanced community engagement models

class ThreadVote(db.Model):
    """Thread voting system for upvotes/downvotes."""
    __tablename__ = 'thread_votes'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    thread_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    vote_type = Column(Text, nullable=False)  # 'upvote' or 'downvote'
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    thread = relationship("Community", back_populates="votes")
    
    # Unique constraint to prevent multiple votes from same user on same thread
    __table_args__ = (db.UniqueConstraint('user_id', 'thread_id', name='unique_user_thread_vote'),)
    
    def __repr__(self):
        return f"<ThreadVote {self.vote_type} by user_id={self.user_id} on thread_id={self.thread_id}>"

class ReplyVote(db.Model):
    """Reply voting system for upvotes/downvotes."""
    __tablename__ = 'reply_votes'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    reply_id = Column(Integer, ForeignKey('community_replies.id'), nullable=False)
    vote_type = Column(Text, nullable=False)  # 'upvote' or 'downvote'
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    reply = relationship("CommunityReply")
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'reply_id', name='unique_user_reply_vote'),)
    
    def __repr__(self):
        return f"<ReplyVote {self.vote_type} by user_id={self.user_id} on reply_id={self.reply_id}>"

# Reddit Integration Models

class RedditImport(db.Model):
    """Track Reddit post imports."""
    __tablename__ = 'reddit_imports'
    
    id = Column(Integer, primary_key=True)
    reddit_url = Column(Text, nullable=False)
    reddit_post_id = Column(Text, nullable=False)
    import_status = Column(Text, default='pending')  # pending, completed, failed
    imported_by_admin = Column(Integer, ForeignKey('users.id'), nullable=False)
    community_id = Column(Integer, ForeignKey('community.id'))
    original_post_data = Column(JSON)  # Store full Reddit response
    import_date = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text)  # If import failed
    
    # Relationships
    admin = relationship("User")
    community_post = relationship("Community")
    
    def __repr__(self):
        return f"<RedditImport {self.id} - {self.reddit_url}>"

class ProfessionalResponse(db.Model):
    """Track professional responses from doctors/experts."""
    __tablename__ = 'professional_responses'
    
    id = Column(Integer, primary_key=True)
    community_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    doctor_id = Column(Integer, ForeignKey('doctors.id'))
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    response_type = Column(Text, nullable=False)  # 'doctor', 'expert', 'verified_user'
    is_verified = Column(Boolean, default=False)
    badge_type = Column(Text)  # 'md', 'specialist', 'expert', 'verified'
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    community_post = relationship("Community")
    doctor = relationship("Doctor")
    user = relationship("User")
    
    def __repr__(self):
        return f"<ProfessionalResponse {self.id} - {self.response_type}>"

class PostCategory(db.Model):
    """Enhanced categorization for posts."""
    __tablename__ = 'post_categories'
    
    id = Column(Integer, primary_key=True)
    community_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    category_type = Column(Text, nullable=False)  # procedure, body_part, discussion_type
    confidence_score = Column(Float, default=0.0)
    auto_tagged = Column(Boolean, default=False)
    manually_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    community_post = relationship("Community")
    
    def __repr__(self):
        return f"<PostCategory {self.id} - {self.category_type}>"

class ThreadSave(db.Model):
    """Save threads for later reading."""
    __tablename__ = 'thread_saves'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    thread_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    thread = relationship("Community", back_populates="saves")
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'thread_id', name='unique_user_thread_save'),)
    
    def __repr__(self):
        return f"<ThreadSave by user_id={self.user_id} on thread_id={self.thread_id}>"

class ThreadFollow(db.Model):
    """Follow threads for notifications."""
    __tablename__ = 'thread_follows'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    thread_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    thread = relationship("Community")
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'thread_id', name='unique_user_thread_follow'),)
    
    def __repr__(self):
        return f"<ThreadFollow by user_id={self.user_id} on thread_id={self.thread_id}>"

class ThreadReaction(db.Model):
    """Emoji reactions on threads."""
    __tablename__ = 'thread_reactions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    thread_id = Column(Integer, ForeignKey('community.id'), nullable=False)
    reaction_type = Column(Text, nullable=False)  # 'heart', 'thumbs_up', 'clap', 'thinking', etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    thread = relationship("Community")
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'thread_id', 'reaction_type', name='unique_user_thread_reaction'),)
    
    def __repr__(self):
        return f"<ThreadReaction {self.reaction_type} by user_id={self.user_id} on thread_id={self.thread_id}>"

class UserBadge(db.Model):
    """User achievements and badges."""
    __tablename__ = 'user_badges'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    badge_type = Column(Text, nullable=False)  # 'verified_patient', 'helpful_contributor', 'recovery_milestone'
    badge_name = Column(Text, nullable=False)
    badge_description = Column(Text)
    badge_icon = Column(Text)  # Icon URL or class
    earned_at = Column(DateTime, default=datetime.utcnow)
    is_visible = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f"<UserBadge {self.badge_type} for user_id={self.user_id}>"

class UserReputation(db.Model):
    """User reputation tracking."""
    __tablename__ = 'user_reputation'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action_type = Column(Text, nullable=False)  # 'thread_upvote', 'helpful_reply', 'doctor_verification'
    points = Column(Integer, nullable=False)
    reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f"<UserReputation {self.points} points for user_id={self.user_id}>"

class UserProfile(db.Model):
    """Extended user profile information."""
    __tablename__ = 'user_profiles'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    avatar_url = Column(Text)
    cover_photo_url = Column(Text)
    location = Column(Text)
    age_range = Column(Text)  # '20-25', '25-30', etc.
    interests = Column(ARRAY(Text))  # Array of procedure interests
    experience_level = Column(Text)  # 'researching', 'planning', 'experienced'
    total_reputation = Column(Integer, default=0)
    helpful_votes = Column(Integer, default=0)
    threads_created = Column(Integer, default=0)
    replies_posted = Column(Integer, default=0)
    
    # Privacy settings
    show_age = Column(Boolean, default=False)
    show_location = Column(Boolean, default=True)
    allow_messages = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f"<UserProfile for user_id={self.user_id}>"

# Message model already exists above, using that one

class Interaction(db.Model):
    """Interactions table."""
    __tablename__ = 'interactions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action_type = Column(Text, nullable=False)
    target_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="interactions")
    
    def __repr__(self):
        return f"<Interaction {self.action_type} by user_id={self.user_id}>"

class DoctorPhoto(db.Model):
    """Doctor photos table for profile images."""
    __tablename__ = 'doctor_photos'
    
    id = Column(Integer, primary_key=True)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    photo_url = Column(Text)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    doctor = relationship("Doctor", back_populates="doctor_photos")
    
    def __repr__(self):
        return f"<DoctorPhoto {self.id} for doctor_id={self.doctor_id}>"

class DoctorAvailability(db.Model):
    """Doctor availability table."""
    __tablename__ = 'doctor_availability'
    
    id = Column(Integer, primary_key=True)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    day_of_week = Column(String(10))  # Monday, Tuesday, etc.
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    date = Column(DateTime)  # For specific date availability
    slots = Column(JSON)  # For time slots within the day
    booked_slots = Column(JSON)  # For tracking booked appointments
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    doctor = relationship("Doctor", back_populates="doctor_availability")
    
    def __repr__(self):
        if self.day_of_week:
            return f"<DoctorAvailability for doctor_id={self.doctor_id} on {self.day_of_week}>"
        else:
            return f"<DoctorAvailability for doctor_id={self.doctor_id} on {self.date}>"

class Lead(db.Model):
    """
    Leads table for storing patient consultation requests.
    
    Standard fields:
    - id: Primary key
    - user_id: Foreign key to user if they're logged in
    - doctor_id: Foreign key to the doctor selected for consultation
    - message: Additional message from the patient
    - appointment_date: Legacy field for scheduled appointments
    - status: Current status of the lead (pending, contacted, completed, etc.)
    - created_at: Timestamp when the lead was created
    
    India launch fields:
    - patient_name: Full name of the patient
    - mobile_number: 10-digit mobile number for contact
    - city: Patient's city in India
    - procedure_name: Name of the procedure they're interested in
    - preferred_date: Patient's preferred consultation date
    - consent_given: DPDP Act compliance consent flag
    """
    __tablename__ = 'leads'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=True)  # Changed to nullable
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=True)  # For clinic marketplace leads
    package_id = Column(Integer, ForeignKey('packages.id'), nullable=True)  # For package-specific leads
    message = Column(Text)
    appointment_date = Column(DateTime)
    status = Column(Text, default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # India launch fields
    patient_name = Column(Text)
    mobile_number = Column(Text)
    city = Column(Text)
    procedure_name = Column(Text)  # Renamed from 'procedure' for clarity
    preferred_date = Column(DateTime)  # Added preferred date
    consent_given = Column(Boolean, default=False)
    source = Column(Text)  # Source tracking (Procedure Page, Doctor Page, etc.)
    
    # Relationships
    user = relationship("User", back_populates="leads")
    doctor = relationship("Doctor", back_populates="leads")
    clinic = relationship("Clinic", back_populates="leads")
    package = relationship("Package", back_populates="package_leads")
    
    def __repr__(self):
        return f"<Lead {self.id} for doctor_id={self.doctor_id}>"

class Message(db.Model):
    """Enhanced Messages table for private messaging."""
    __tablename__ = 'messages'
    
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    subject = Column(Text)
    content = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")
    
    def __repr__(self):
        return f"<Message {self.id} from user_id={self.sender_id} to user_id={self.receiver_id}>"

class Thread(db.Model):
    """Thread model for community analytics."""
    __tablename__ = 'threads'
    
    id = Column(Integer, primary_key=True)
    title = Column(Text, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    procedure_id = Column(Integer, ForeignKey('procedures.id'))
    view_count = Column(Integer, default=0)
    reply_count = Column(Integer, default=0)
    keywords = Column(ARRAY(Text))
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Flag-related fields
    is_flagged = Column(Boolean, default=False)
    flag_reason = Column(Text)
    flag_notes = Column(Text)
    flagged_by = Column(Integer, ForeignKey('users.id'), name="fk_thread_flagged_by")
    flagged_at = Column(DateTime)
    
    # Relationships
    procedure = relationship("Procedure", backref=backref("threads", cascade="all, delete-orphan"))
    user = relationship("User", foreign_keys=[user_id], backref=backref("threads", cascade="all, delete-orphan"))
    flagged_by_user = relationship("User", foreign_keys=[flagged_by], backref=backref("flagged_threads"))
    analytics = relationship("ThreadAnalytics", back_populates="thread", uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Thread {self.id}: {self.title}>"

class ThreadAnalytics(db.Model):
    """Thread analytics for community insights."""
    __tablename__ = 'thread_analytics'
    
    id = Column(Integer, primary_key=True)
    thread_id = Column(Integer, ForeignKey('threads.id'), nullable=False)
    engagement_score = Column(Float, default=0)
    trending_score = Column(Float, default=0)
    topic_categories = Column(ARRAY(Text))
    sentiment_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    thread = relationship("Thread", back_populates="analytics")
    
    def __repr__(self):
        return f"<ThreadAnalytics for thread_id={self.thread_id}>"

class CommunityModeration(db.Model):
    """Community moderation table for content management."""
    __tablename__ = 'community_moderation'
    
    id = Column(Integer, primary_key=True)
    community_id = Column(Integer, ForeignKey('community.id'))
    reply_id = Column(Integer, ForeignKey('community_replies.id'))
    moderator_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(Text, nullable=False)  # approve, reject, flag
    reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    community = relationship("Community", foreign_keys=[community_id], back_populates="moderations")
    reply = relationship("CommunityReply", foreign_keys=[reply_id], back_populates="moderations")
    moderator = relationship("User", back_populates="moderations")
    
    def __repr__(self):
        target_id = self.community_id or self.reply_id
        target_type = "community" if self.community_id else "reply"
        return f"<CommunityModeration {self.id} on {target_type}_id={target_id}>"

class EducationModule(db.Model):
    """Education modules for contextual health education."""
    __tablename__ = 'education_modules'
    
    id = Column(Integer, primary_key=True)
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    content = Column(Text, nullable=False)  # Rich text content
    category_id = Column(Integer, ForeignKey('categories.id'))
    procedure_id = Column(Integer, ForeignKey('procedures.id'))
    level = Column(Integer, default=1)  # Difficulty level (1-5)
    points = Column(Integer, default=10)  # Points awarded for completion
    estimated_minutes = Column(Integer, default=5)  # Estimated time to complete
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    category = relationship("Category", backref=backref("education_modules", cascade="all, delete-orphan"))
    procedure = relationship("Procedure", backref=backref("education_modules", cascade="all, delete-orphan"))
    quizzes = relationship("ModuleQuiz", back_populates="module", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<EducationModule {self.title}>"

class ModuleQuiz(db.Model):
    """Quizzes for educational modules."""
    __tablename__ = 'module_quizzes'
    
    id = Column(Integer, primary_key=True)
    module_id = Column(Integer, ForeignKey('education_modules.id'), nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text)
    passing_score = Column(Integer, default=70)  # Percentage needed to pass
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    module = relationship("EducationModule", back_populates="quizzes")
    questions = relationship("QuizQuestion", back_populates="quiz", cascade="all, delete-orphan")
    attempts = relationship("QuizAttempt", back_populates="quiz", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ModuleQuiz {self.title} for module_id={self.module_id}>"

class QuizQuestion(db.Model):
    """Questions for module quizzes."""
    __tablename__ = 'quiz_questions'
    
    id = Column(Integer, primary_key=True)
    quiz_id = Column(Integer, ForeignKey('module_quizzes.id'), nullable=False)
    question_text = Column(Text, nullable=False)
    question_type = Column(Text, nullable=False)  # multiple_choice, true_false, matching
    options = Column(JSON)  # Array of possible answers
    correct_answer = Column(JSON)  # Index or array of indices of correct answers
    explanation = Column(Text)  # Explanation shown after answering
    points = Column(Integer, default=1)  # Points for correct answer
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    quiz = relationship("ModuleQuiz", back_populates="questions")
    
    def __repr__(self):
        return f"<QuizQuestion {self.id} for quiz_id={self.quiz_id}>"

class QuizAttempt(db.Model):
    """User quiz attempts."""
    __tablename__ = 'quiz_attempts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    quiz_id = Column(Integer, ForeignKey('module_quizzes.id'), nullable=False)
    score = Column(Integer, nullable=False)  # Percentage score
    passed = Column(Boolean, default=False)
    answers = Column(JSON)  # User's answers
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    time_spent_seconds = Column(Integer)
    
    # Relationships
    user = relationship("User", backref=backref("quiz_attempts", cascade="all, delete-orphan"))
    quiz = relationship("ModuleQuiz", back_populates="attempts")
    
    def __repr__(self):
        return f"<QuizAttempt {self.id} by user_id={self.user_id} for quiz_id={self.quiz_id}>"

class Appointment(db.Model):
    """Appointments table for doctor-patient appointments."""
    __tablename__ = 'appointments'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=False)
    procedure_name = Column(Text, nullable=False)
    appointment_date = Column(DateTime, nullable=False)
    appointment_time = Column(Text, nullable=False)
    status = Column(Text, default='pending')  # pending, confirmed, completed, cancelled
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="appointments", foreign_keys=[user_id])
    doctor = relationship("Doctor", backref="doctor_appointments", foreign_keys=[doctor_id])
    
    def __repr__(self):
        return f"<Appointment {self.id} for user_id={self.user_id} with doctor_id={self.doctor_id}>"

class UserAchievement(db.Model):
    """User achievements for gamification."""
    __tablename__ = 'user_achievements'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    achievement_type = Column(Text, nullable=False)  # module_completion, streak, badge
    achievement_key = Column(Text, nullable=False)  # Identifier for the specific achievement
    title = Column(Text, nullable=False)
    description = Column(Text)
    points_awarded = Column(Integer, default=0)
    earned_at = Column(DateTime, default=datetime.utcnow)
    module_id = Column(Integer, ForeignKey('education_modules.id'))
    
    # Relationships
    user = relationship("User", backref=backref("achievements", cascade="all, delete-orphan"))
    module = relationship("EducationModule")
    
    def __repr__(self):
        return f"<UserAchievement {self.title} for user_id={self.user_id}>"

class ModuleProgress(db.Model):
    """User progress through education modules."""
    __tablename__ = 'module_progress'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    module_id = Column(Integer, ForeignKey('education_modules.id'), nullable=False)
    status = Column(Text, default='started')  # started, in_progress, completed
    percent_complete = Column(Integer, default=0)
    last_activity = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationships
    user = relationship("User", backref=backref("module_progress", cascade="all, delete-orphan"))
    module = relationship("EducationModule")
    
    def __repr__(self):
        return f"<ModuleProgress for user_id={self.user_id}, module_id={self.module_id}, status={self.status}>"
        
class Favorite(db.Model):
    """Favorites/saved items table."""
    __tablename__ = 'favorites'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    procedure_id = Column(Integer, ForeignKey('procedures.id'), nullable=True)
    doctor_id = Column(Integer, ForeignKey('doctors.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", backref=backref("favorites", cascade="all, delete-orphan"))
    procedure = relationship("Procedure")
    doctor = relationship("Doctor")
    
    def __repr__(self):
        return f"<Favorite {self.id} by user_id={self.user_id}>"


class RecommendationHistory(db.Model):
    """Table to store AI recommendation history for users."""
    __tablename__ = 'recommendation_history'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    query_text = Column(Text, nullable=False)
    has_image = Column(Boolean, default=False)
    has_audio = Column(Boolean, default=False)
    primary_concern = Column(Text)
    body_part = Column(Text)
    symptoms = Column(ARRAY(Text))
    severity = Column(Text)
    language_detected = Column(Text)
    recommended_procedures = Column(ARRAY(Integer))  # Store procedure IDs
    recommended_doctors = Column(ARRAY(Integer))     # Store doctor IDs
    recommended_clinics = Column(ARRAY(Integer))     # Store clinic IDs
    created_at = Column(DateTime, default=datetime.utcnow)
    feedback_rating = Column(Integer)  # User can rate helpfulness (1-5 stars)
    booking_made = Column(Boolean, default=False)  # If user later booked with recommended doctor
    full_analysis = Column(JSON)  # Store complete AI analysis JSON for reference
    
    # Relationships
    user = relationship("User", backref=backref("recommendation_history", cascade="all, delete-orphan"))
    
    def __repr__(self):
        return f"<RecommendationHistory {self.id} for user_id={self.user_id}, concern={self.primary_concern}>"

# ============================================================================
# CLINIC & PACKAGE MARKETPLACE MODELS
# Implementation following Antidote Core System Architecture Documentation
# ============================================================================

class Clinic(db.Model):
    """Main clinic model for India-focused medical facility directory."""
    __tablename__ = 'clinics'
    
    id = Column(Integer, primary_key=True)
    owner_user_id = Column(Integer, ForeignKey('users.id'), nullable=False)  # Clinic owner account
    name = Column(String(200), nullable=False)
    slug = Column(String(250), unique=True, nullable=False)  # URL-friendly identifier
    
    # Location & Contact
    address = Column(Text, nullable=False)
    area = Column(String(100))  # Bandra, Koramangala, CP, etc.
    city = Column(String(100), nullable=False)
    state = Column(String(100), nullable=False)
    pincode = Column(String(10))
    contact_number = Column(String(20), nullable=False)
    email = Column(String(120))
    website = Column(String(200))
    
    # Working Hours
    working_hours = Column(JSON)  # {mon: "10am - 8pm", tue: ...}
    
    # Profile & Branding
    profile_image = Column(Text)  # Hero image or logo
    banner_image = Column(Text)   # Optional top banner
    description = Column(Text)
    
    # Features & Specialties
    highlights = Column(ARRAY(Text))    # ["Post-procedure care", "Evening hrs"]
    specialties = Column(ARRAY(Text))   # ["Botox", "Fillers"]
    services_offered = Column(ARRAY(Text))  # Detailed services list
    
    # Ratings & Reviews
    rating = Column(Float, default=0.0)
    review_count = Column(Integer, default=0)
    
    # Google Places Integration
    google_business_url = Column(String(500))  # https://g.co/kgs/3mX75vm format
    google_place_id = Column(String(200))      # Extracted Place ID
    google_rating = Column(Float)              # Current Google rating
    google_review_count = Column(Integer)      # Total Google reviews
    last_review_sync = Column(DateTime)        # Last sync timestamp
    google_sync_enabled = Column(Boolean, default=False)  # Admin can enable/disable
    
    # Status & Verification
    is_approved = Column(Boolean, default=False)  # Shown only when true
    verification_status = Column(String(50), default='pending')
    verification_date = Column(DateTime)
    verification_notes = Column(Text)
    
    # Billing & Credits
    credit_balance = Column(Integer, default=0)  # Available credits for leads
    total_credits_purchased = Column(Integer, default=0)
    total_credits_used = Column(Integer, default=0)
    
    # SEO & Analytics
    view_count = Column(Integer, default=0)
    lead_count = Column(Integer, default=0)
    conversion_rate = Column(Float, default=0.0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", backref=backref("clinic", uselist=False))
    doctors = relationship("Doctor", back_populates="clinic", cascade="all, delete-orphan")
    packages = relationship("Package", back_populates="clinic", cascade="all, delete-orphan")
    leads = relationship("Lead", foreign_keys="Lead.clinic_id", back_populates="clinic")
    # clinic_reviews relationship will be added after ClinicReview model is properly defined
    credit_transactions = relationship("CreditTransaction", back_populates="clinic", cascade="all, delete-orphan")
    google_reviews = relationship("GoogleReview", back_populates="clinic", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Clinic {self.name} in {self.city}>"

class GoogleReview(db.Model):
    """Store authentic Google My Business reviews from Places API."""
    __tablename__ = 'google_reviews'
    
    id = Column(Integer, primary_key=True)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    
    # Google Review Data
    google_review_id = Column(String(200), unique=True, nullable=False)  # Unique Google review ID
    author_name = Column(String(200), nullable=False)
    author_url = Column(String(500))  # Google profile URL
    profile_photo_url = Column(String(500))  # Author's profile photo
    
    # Review Content
    rating = Column(Integer, nullable=False)  # 1-5 stars
    text = Column(Text)  # Review text content
    language = Column(String(10))  # Language code (en, hi, etc.)
    
    # Timestamps
    time = Column(DateTime, nullable=False)  # When review was posted on Google
    created_at = Column(DateTime, default=datetime.utcnow)  # When synced to our DB
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Review Metadata
    relative_time_description = Column(String(100))  # "2 weeks ago"
    original_data = Column(JSON)  # Store complete Google API response
    
    # Status
    is_active = Column(Boolean, default=True)  # Can be hidden by admin
    
    # Relationships
    clinic = relationship("Clinic", back_populates="google_reviews")
    
    def __repr__(self):
        return f"<GoogleReview {self.id} by {self.author_name} for clinic_id={self.clinic_id}>"

class Package(db.Model):
    """Treatment packages offered by clinics."""
    __tablename__ = 'packages'
    
    id = Column(Integer, primary_key=True)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    procedure_id = Column(Integer, ForeignKey('procedures.id'), nullable=True)  # Link to existing procedures
    
    # Package Details
    title = Column(String(200), nullable=False)
    slug = Column(String(250), unique=True, nullable=False)
    description = Column(Text)
    procedure_info = Column(Text)  # Rich HTML or markdown
    
    # Pricing
    price_actual = Column(Numeric(10, 2), nullable=False)      # Original price
    price_discounted = Column(Numeric(10, 2))                 # Discounted price
    discount_percentage = Column(Integer)                      # Calculated discount %
    
    # Treatment Information
    category = Column(String(100))  # Category (e.g., Rhinoplasty, Botox)
    tags = Column(ARRAY(Text))      # ["30% OFF", "Popular"]
    side_effects = Column(Text)     # Description
    recommended_for = Column(Text)  # Use case info
    downtime = Column(String(50))   # e.g., "2-3 days"
    duration = Column(String(50))   # e.g., "45 mins"
    anesthetic = Column(String(100)) # Included anesthetic
    
    # Before/After Results
    results = Column(JSON)          # Before/after sections with image URLs
    
    # Billing & Legal
    vat_included = Column(Boolean, default=True)  # Billing transparency
    terms_conditions = Column(Text)
    
    # Media
    featured_image = Column(Text)
    gallery_images = Column(ARRAY(Text))  # Multiple images
    video_url = Column(Text)
    
    # Status & Analytics
    is_active = Column(Boolean, default=True)    # Deactivation flag
    is_featured = Column(Boolean, default=False) # Homepage featured
    view_count = Column(Integer, default=0)
    lead_count = Column(Integer, default=0)
    conversion_rate = Column(Float, default=0.0)
    
    # SEO
    meta_title = Column(String(200))
    meta_description = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    clinic = relationship("Clinic", back_populates="packages")
    procedure = relationship("Procedure")
    package_leads = relationship("Lead", foreign_keys="Lead.package_id", back_populates="package")
    package_reviews = relationship("PackageReview", back_populates="package", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Package {self.title} by {self.clinic.name if self.clinic else 'Unknown'}>"

class CreditTransaction(db.Model):
    """Credit purchase and usage tracking for clinics."""
    __tablename__ = 'credit_transactions'
    
    id = Column(Integer, primary_key=True)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    
    # Transaction Details
    transaction_type = Column(String(20), nullable=False)  # 'purchase', 'deduction', 'refund', 'bonus'
    amount = Column(Integer, nullable=False)  # Credit amount (positive for purchase, negative for usage)
    description = Column(Text)
    
    # Related Entities
    lead_id = Column(Integer, ForeignKey('leads.id'), nullable=True)  # If deduction for a lead
    order_id = Column(String(100))  # Payment gateway order ID
    payment_id = Column(String(100))  # Payment gateway payment ID
    
    # Financial
    monetary_value = Column(Numeric(10, 2))  # INR value of credits
    
    # Status
    status = Column(String(20), default='completed')  # 'pending', 'completed', 'failed', 'refunded'
    
    # Admin fields for enhanced tracking
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)  # Admin who created the transaction
    transaction_metadata = Column(JSON)  # Additional transaction metadata
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime)
    
    # Relationships
    clinic = relationship("Clinic", back_populates="credit_transactions")
    lead = relationship("Lead", backref="credit_transaction")
    admin_user = relationship("User", foreign_keys=[created_by])
    
    def __repr__(self):
        return f"<CreditTransaction {self.transaction_type} {self.amount} credits for clinic {self.clinic_id}>"

# ClinicReview model consolidated - using single definition above

class PackageReview(db.Model):
    """Reviews specifically for packages."""
    __tablename__ = 'package_reviews'
    
    id = Column(Integer, primary_key=True)
    package_id = Column(Integer, ForeignKey('packages.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Review Content
    rating = Column(Float, nullable=False)
    title = Column(String(200))
    content = Column(Text, nullable=False)
    
    # Treatment Experience
    results_rating = Column(Float)      # How satisfied with results
    recovery_rating = Column(Float)     # Recovery experience
    price_rating = Column(Float)        # Value for money
    
    # Before/After Photos
    before_photos = Column(ARRAY(Text))
    after_photos = Column(ARRAY(Text))
    
    # Treatment Details
    treatment_date = Column(DateTime)
    recovery_time_actual = Column(String(50))  # Actual recovery vs promised
    
    # Verification
    is_verified = Column(Boolean, default=False)
    verification_method = Column(String(50))  # 'receipt', 'clinic_confirmed', etc.
    
    # Engagement
    helpful_count = Column(Integer, default=0)
    reported = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    package = relationship("Package", back_populates="package_reviews")
    user = relationship("User", backref="package_reviews")
    
    def __repr__(self):
        return f"<PackageReview {self.rating}★ for package {self.package_id} by user {self.user_id}>"

# ClinicReviewReply model consolidated - will be implemented with main review system

# Old clinic models removed - using new comprehensive clinic implementation above

# Add clinic_id to existing Doctor model to link doctors to clinics


class Banner(db.Model):
    """
    Banner model representing a banner container that can have multiple slides.
    
    A banner is placed in a specific position on the homepage and can contain
    multiple slides that rotate in a carousel/slider.
    """
    __tablename__ = 'banners'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    position = Column(String(50), nullable=False)  # 'hero', 'middle', 'bottom', etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    slides = relationship('BannerSlide', back_populates='banner', cascade='all, delete-orphan')
    
    def __repr__(self):
        """String representation of the Banner model."""
        return f'<Banner {self.id}: {self.name} ({self.position})>'
    
    def to_dict(self):
        """Convert banner to dictionary for API response."""
        return {
            'id': self.id,
            'name': self.name,
            'position': self.position,
            'is_active': self.is_active,
            'slides': [slide.to_dict() for slide in self.slides if slide.is_active]
        }


class BannerSlide(db.Model):
    """
    BannerSlide model representing a single slide within a banner.
    
    Each slide contains its own image, title, subtitle, and redirect URL.
    Slides can be active or inactive and have display order.
    Supports separate images for desktop and mobile views.
    """
    __tablename__ = 'banner_slides'
    
    id = Column(Integer, primary_key=True)
    banner_id = Column(Integer, ForeignKey('banners.id'), nullable=False)
    title = Column(String(200), nullable=False)
    subtitle = Column(Text, nullable=True)
    image_url = Column(String(500), nullable=False)  # Desktop/main image
    mobile_image_url = Column(String(500), nullable=True)  # Mobile-specific image
    redirect_url = Column(String(500), nullable=False)
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    click_count = Column(Integer, default=0)
    impression_count = Column(Integer, default=0)
    
    # Relationships
    banner = relationship('Banner', back_populates='slides')
    
    def __repr__(self):
        """String representation of the BannerSlide model."""
        return f'<BannerSlide {self.id}: {self.title} (Banner: {self.banner_id})>'
    
    def to_dict(self):
        """Convert banner slide to dictionary for API response."""
        return {
            'id': self.id,
            'banner_id': self.banner_id,
            'title': self.title,
            'subtitle': self.subtitle,
            'image_url': self.image_url,
            'mobile_image_url': self.mobile_image_url,
            'redirect_url': self.redirect_url,
            'display_order': self.display_order,
            'is_active': self.is_active,
            'click_count': self.click_count if self.click_count is not None else 0,
            'impression_count': self.impression_count if self.impression_count is not None else 0,
            'ctr': round(((self.click_count or 0) / self.impression_count * 100), 2) if self.impression_count and self.impression_count > 0 and self.click_count is not None else 0
        }


# ============================================================================
# CREDIT BILLING SYSTEM MODELS
# ============================================================================

# Note: CreditTransaction table already exists in database
# Using existing structure: id, clinic_id, transaction_type, amount, description, 
# lead_id, order_id, payment_id, monetary_value, status, created_at, processed_at, payment_method


class LeadDispute(db.Model):
    """
    Lead disputes table for tracking refund requests from clinics.
    
    Allows clinics to dispute leads that are:
    - Invalid/spam
    - Duplicate
    - Not reachable
    - Mistakenly charged
    """
    __tablename__ = 'lead_disputes'
    
    id = Column(Integer, primary_key=True)
    lead_id = Column(Integer, ForeignKey('leads.id'), nullable=False)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    
    # Dispute details
    reason = Column(String(50), nullable=False)  # 'invalid', 'duplicate', 'unreachable', 'error'
    description = Column(Text, nullable=False)  # Clinic's explanation
    evidence_urls = Column(ARRAY(Text))  # Screenshots or other evidence
    
    # Status tracking
    status = Column(String(20), default='pending')  # 'pending', 'approved', 'rejected'
    
    # Admin resolution
    admin_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # Admin who resolved
    admin_notes = Column(Text, nullable=True)  # Admin resolution notes
    refund_amount = Column(Integer, nullable=True)  # Credits refunded (if approved)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)  # When dispute was resolved
    
    # Relationships
    lead = relationship("Lead", backref="disputes")
    clinic = relationship("Clinic", backref="lead_disputes")
    admin_user = relationship("User", backref="resolved_disputes")
    
    def __repr__(self):
        return f"<LeadDispute {self.id}: {self.reason} for lead {self.lead_id} by clinic {self.clinic_id}>"
    
    def to_dict(self):
        """Convert dispute to dictionary for API response."""
        return {
            'id': self.id,
            'lead_id': self.lead_id,
            'reason': self.reason,
            'description': self.description,
            'status': self.status,
            'refund_amount': self.refund_amount,
            'admin_notes': self.admin_notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


class LeadQualityTracking(db.Model):
    """
    Lead quality tracking table for monitoring suspicious patterns.
    
    Tracks potential spam/fraud indicators:
    - Same phone number multiple times
    - Suspicious timing patterns
    - Low engagement leads
    """
    __tablename__ = 'lead_quality_tracking'
    
    id = Column(Integer, primary_key=True)
    lead_id = Column(Integer, ForeignKey('leads.id'), nullable=False)
    
    # Quality indicators
    phone_number_frequency = Column(Integer, default=1)  # How many times this phone number appeared
    same_ip_frequency = Column(Integer, default=1)  # Same IP address frequency
    time_between_leads = Column(Integer, nullable=True)  # Seconds between leads from same source
    
    # Risk scoring
    spam_risk_score = Column(Float, default=0.0)  # 0-1 scale, higher = more suspicious
    quality_flags = Column(ARRAY(Text))  # ['duplicate_phone', 'rapid_fire', 'suspicious_ip']
    
    # Tracking data
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6 address
    user_agent = Column(Text, nullable=True)  # Browser user agent
    referrer_url = Column(Text, nullable=True)  # Where they came from
    
    # Status
    is_flagged = Column(Boolean, default=False)
    reviewed_by_admin = Column(Boolean, default=False)
    admin_notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    lead = relationship("Lead", backref="quality_tracking")
    
    def __repr__(self):
        return f"<LeadQualityTracking {self.id}: risk_score={self.spam_risk_score} for lead {self.lead_id}>"


class PromoCode(db.Model):
    """
    Promotional codes for credit discounts and bonuses.
    Admin-managed promotional offers system.
    """
    __tablename__ = 'promo_codes'
    
    id = Column(Integer, primary_key=True)
    code = Column(String(50), unique=True, nullable=False)  # SUMMER2024, WELCOME50
    description = Column(Text, nullable=False)  # What this promo offers
    
    # Discount settings
    discount_percent = Column(Float, default=0.0)  # Percentage discount (0-100)
    max_discount = Column(Float, nullable=True)  # Maximum discount amount
    bonus_percent = Column(Float, default=0.0)  # Bonus credits percentage
    
    # Usage constraints
    min_amount = Column(Float, default=100.0)  # Minimum purchase amount
    usage_limit_per_user = Column(Integer, nullable=True)  # Max uses per clinic
    total_usage_limit = Column(Integer, nullable=True)  # Max total uses
    
    # Validity period
    start_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_date = Column(DateTime, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_by_admin_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    created_by = relationship("User", backref="created_promo_codes")
    usages = relationship("PromoUsage", back_populates="promo_code", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<PromoCode {self.code}: {self.discount_percent}% off>"
    
    def is_valid(self):
        """Check if promo code is currently valid."""
        now = datetime.utcnow()
        return (self.is_active and 
                self.start_date <= now <= self.end_date)
    
    def get_usage_count(self):
        """Get total usage count for this promo."""
        return len(self.usages)
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'code': self.code,
            'description': self.description,
            'discount_percent': self.discount_percent,
            'max_discount': self.max_discount,
            'bonus_percent': self.bonus_percent,
            'min_amount': self.min_amount,
            'usage_limit_per_user': self.usage_limit_per_user,
            'total_usage_limit': self.total_usage_limit,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'is_active': self.is_active,
            'usage_count': self.get_usage_count()
        }


class PromoUsage(db.Model):
    """
    Track promotional code usage by clinics.
    Records when and how promo codes are used.
    """
    __tablename__ = 'promo_usage'
    
    id = Column(Integer, primary_key=True)
    promo_code_id = Column(Integer, ForeignKey('promo_codes.id'), nullable=False)
    clinic_id = Column(Integer, ForeignKey('clinics.id'), nullable=False)
    transaction_id = Column(Integer, ForeignKey('credit_transactions.id'), nullable=True)
    
    # Usage details
    discount_amount = Column(Float, default=0.0)  # Actual discount given
    bonus_amount = Column(Float, default=0.0)  # Actual bonus credits given
    original_amount = Column(Float, nullable=False)  # Original purchase amount
    
    # Timestamps
    used_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    promo_code = relationship("PromoCode", back_populates="usages")
    clinic = relationship("Clinic", backref="promo_usages")
    transaction = relationship("CreditTransaction", backref="promo_usage")
    
    def __repr__(self):
        return f"<PromoUsage {self.promo_code.code} by clinic {self.clinic_id}>"
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'promo_code': self.promo_code.code,
            'discount_amount': self.discount_amount,
            'bonus_amount': self.bonus_amount,
            'original_amount': self.original_amount,
            'used_at': self.used_at.isoformat() if self.used_at else None
        }


class CreditPromotion(db.Model):
    """
    Credit promotions table for managing bonus credit campaigns.
    
    Allows admins to create promotional offers like:
    - "Top up ₹5000, get 2000 bonus credits"
    - "First time top-up bonus"
    - "Referral bonuses"
    """
    __tablename__ = 'credit_promotions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)  # "New Year Bonus", "First Time Bonus"
    promo_code = Column(String(50), unique=True, nullable=True)  # Optional promo code
    
    # Promotion rules
    min_topup_amount = Column(Integer, nullable=False)  # Minimum topup to qualify
    bonus_type = Column(String(20), nullable=False)  # 'percentage', 'fixed_amount'
    bonus_value = Column(Integer, nullable=False)  # 20 (for 20%) or 2000 (for 2000 credits)
    max_bonus = Column(Integer, nullable=True)  # Maximum bonus credits possible
    
    # Validity
    is_active = Column(Boolean, default=True)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    usage_limit = Column(Integer, nullable=True)  # Max number of uses
    usage_count = Column(Integer, default=0)  # Current usage count
    
    # Targeting
    new_clinics_only = Column(Boolean, default=False)  # Only for first-time topups
    specific_clinic_ids = Column(ARRAY(Integer))  # Limit to specific clinics
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Relationships
    creator = relationship("User", backref="created_promotions")
    
    def __repr__(self):
        return f"<CreditPromotion {self.id}: {self.name}>"
    
    def calculate_bonus(self, topup_amount):
        """Calculate bonus credits for a given topup amount."""
        if topup_amount < self.min_topup_amount:
            return 0
        
        if self.bonus_type == 'percentage':
            bonus = int(topup_amount * self.bonus_value / 100)
        else:  # fixed_amount
            bonus = self.bonus_value
        
        if self.max_bonus and bonus > self.max_bonus:
            bonus = self.max_bonus
        
        return bonus
    
    def is_valid(self):
        """Check if promotion is currently valid."""
        now = datetime.utcnow()
        return (
            self.is_active and 
            self.start_date <= now <= self.end_date and
            (self.usage_limit is None or self.usage_count < self.usage_limit)
        )

# Personalization Models for Anonymous User Tracking
class UserInteraction(db.Model):
    """Track user interactions for personalization without requiring login."""
    __tablename__ = 'user_interactions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(32), nullable=False, index=True)  # Browser fingerprint
    session_id = Column(String(64), nullable=False)
    interaction_type = Column(String(50), nullable=False)  # 'view', 'search', 'click', 'form_submit'
    target_type = Column(String(50))  # 'procedure', 'category', 'doctor', 'package'
    target_id = Column(Integer)
    extra_data = Column(Text)  # JSON string for additional data
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

class UserCategoryAffinity(db.Model):
    """Track user affinity scores for different categories."""
    __tablename__ = 'user_category_affinity'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(32), nullable=False, index=True)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    affinity_score = Column(Float, default=0.0)  # 0.0 to 1.0
    last_updated = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    category = relationship('Category', backref='user_affinities')

class CategoryRelationship(db.Model):
    """Define relationships between categories for better recommendations."""
    __tablename__ = 'category_relationships'
    
    id = Column(Integer, primary_key=True)
    primary_category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    related_category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    relationship_type = Column(String(20), nullable=False)  # 'similar', 'complementary', 'cluster'
    strength = Column(Float, default=0.5)  # 0.0 to 1.0
    
    # Relationships
    primary_category = relationship('Category', foreign_keys=[primary_category_id])
    related_category = relationship('Category', foreign_keys=[related_category_id])
