from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    nationality = db.Column(db.String(50), nullable=True)
    education = db.Column(db.String(50), nullable=True)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationships here
    applications = db.relationship('Application', backref='user', lazy=True)
    documents = db.relationship('Document', backref='user', lazy=True)
    certificates = db.relationship('Certificate', backref='user', lazy=True)
    tickets = db.relationship('Ticket', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'

class Application(db.Model):
    __tablename__ = 'application'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    program = db.Column(db.String(100), nullable=False)
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'), nullable=True)
    status = db.Column(db.String(50), default='Pending Review')
    payment_status = db.Column(db.String(20), default='Pending')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    __tablename__ = 'document'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='Uploaded')
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Certificate(db.Model):
    __tablename__ = 'certificates'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    cert_id = db.Column(db.String(20), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    purpose = db.Column(db.Text)
    copies = db.Column(db.Integer, default=1)
    status = db.Column(db.String(50), default='Pending')
    payment_status = db.Column(db.String(20), default='Pending')
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    # notes = db.Column(db.Text, nullable=True)  # Add this line

class Ticket(db.Model):
    __tablename__ = 'ticket'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='Open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages = db.relationship('TicketMessage', backref='ticket', lazy=True, order_by='TicketMessage.created_at')

class TicketMessage(db.Model):
    __tablename__ = 'ticket_message'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    sender = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notification'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class StudentID(db.Model):
    __tablename__ = 'student_id'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = 'payment'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Completed')
    transaction_id = db.Column(db.String(100), nullable=True)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)

class Project(db.Model):
    __tablename__ = 'project'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    url = db.Column(db.String(200))
    image_path = db.Column(db.String(200))
    is_popular = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'news' or 'announcement'
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    image_path = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

class Course(db.Model):
    __tablename__ = 'course'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    credits = db.Column(db.Integer, nullable=False)
    prerequisites = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationships
    enrolled_students = db.relationship('CourseEnrollment', backref='course', lazy=True)

class CourseEnrollment(db.Model):
    __tablename__ = 'course_enrollment'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Enrolled')  # Enrolled, Completed, Dropped
    grade = db.Column(db.String(2))

class Program(db.Model):
    __tablename__ = 'program'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text)
    degree_type = db.Column(db.String(50), nullable=False)  # Diploma, Master's, Doctorate
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    courses = db.relationship('ProgramCourse', backref='program', lazy=True)

class ProgramCourse(db.Model):
    __tablename__ = 'program_course'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1 or 2
    is_required = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)