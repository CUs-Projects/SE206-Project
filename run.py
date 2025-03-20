from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
from flask.cli import with_appcontext
import click
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm

# Import models
from models import (
    db, User, Application, Document, Certificate, 
    Payment, Project, News, Course, CourseEnrollment,
    Ticket, TicketMessage, Notification, StudentID  # Add StudentID here
)

# Add this right after your imports
from sqlalchemy import text

# Initialize Flask app
app = Flask(__name__)

# Configure app with proper paths
app.config.update(
    SECRET_KEY='your-secret-key-goes-here',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_DATABASE_URI='sqlite:///cu_project.db',  # Add this line
    UPLOAD_FOLDER=os.path.join('static', 'uploads')
)
# Ensure instance and uploads directories exist
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter('time_ago')
def time_ago_filter(time):
    """Format a timestamp as 'time ago' (e.g., "3 hours ago")"""
    now = datetime.utcnow()
    diff = now - time
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"
    elif seconds < 2592000:
        weeks = int(seconds / 604800)
        return f"{weeks} week{'s' if weeks > 1 else ''} ago"
    else:
        return time.strftime("%Y-%m-%d")
    

    
@app.template_filter('initials')
def initials_filter(name):
    if not name:
        return "UN"
    
    parts = name.split()
    if len(parts) == 1:
        return parts[0][0].upper()
    else:
        return (parts[0][0] + parts[-1][0]).upper()


@app.template_filter('slice')
def slice_filter(iterable, start, end=None):
    if end is None:
        return iterable[start:]
    return iterable[start:end]


@app.template_filter('format_date')
def format_date_filter(date):
    if date is None:
        return ""
    try:
        return date.strftime("%b %d, %Y")
    except:
        return str(date)    


@app.route('/')
def index():
    # Get only active and featured projects for the homepage
    featured_projects = Project.query.filter_by(
        is_active=True, 
        is_popular=True
    ).order_by(
        Project.created_at.desc()
    ).limit(6).all()
    
    return render_template('index.html', featured_projects=featured_projects)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))

    class LoginForm(FlaskForm):
        pass  # Empty form just for CSRF protection

    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.is_admin() else 'student_dashboard'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

    # Add this new route to manually create admin user
@app.route('/create-admin', methods=['GET'])
def create_admin():
    # Check if admin user exists
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(
            email='admin@example.com',
            full_name='Admin User',
            role='admin'
        )
        admin.set_password('adminpassword')
        db.session.add(admin)
        db.session.commit()
        return 'Admin user created successfully!'
    else:
        # Reset admin password
        admin.set_password('adminpassword')
        db.session.commit()
        return 'Admin user password reset to "adminpassword"'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('student_dashboard'))

    class RegisterForm(FlaskForm):
        pass  # Empty form just for CSRF protection

    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        full_name = request.form.get('fullName')
        phone = request.form.get('phone')
        nationality = request.form.get('nationality')
        education = request.form.get('education')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html', form=form)
        
        user = User(
            email=email,
            full_name=full_name,
            phone=phone,
            nationality=nationality,
            education=education
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/programs')
def programs():
    return render_template('programs.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))  


@app.route('/admin/applications')
@login_required

def admin_applications():
    applications = Application.query.all()
    return render_template('admin/applications.html', applications=applications)

@app.route('/admin/application/<int:application_id>/<action>', methods=['POST'])
@login_required
def admin_application_action(application_id, action):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        application = Application.query.get_or_404(application_id)
        
        if action == 'approve':
            application.status = 'Documents Approved'
            message = 'Application documents approved successfully'
        elif action == 'reject':
            application.status = 'Documents Rejected'
            message = 'Application documents rejected'
        else:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400
        
        # Create notification for student
        notification = Notification(
            user_id=application.user_id,
            message=f'Your application {application.app_id} has been {action}d.',
            read=False
        )
        
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': message,
            'new_status': application.status
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/enrollments')
@login_required
def admin_enrollments():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    # Get applications with paid status that need student IDs
    enrollments = db.session.query(Application).filter_by(
        status='Documents Approved', 
        payment_status='Paid'
    ).outerjoin(
        StudentID, 
        Application.id == StudentID.application_id
    ).filter(
        StudentID.id == None
    ).all()
    
    # Get applications with student IDs
    enrolled_students = db.session.query(Application, StudentID).join(
        StudentID, 
        Application.id == StudentID.application_id
    ).all()
    
    return render_template('admin/enrollments.html', 
                          enrollments=enrollments,
                          enrolled_students=enrolled_students)

@app.route('/admin/generate_student_id/<int:app_id>', methods=['POST'])
@login_required
def generate_student_id(app_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        application = Application.query.get_or_404(app_id)
        
        # Generate student ID based on year and nationality
        year = datetime.utcnow().year
        is_international = application.user.nationality != 'Egyptian'
        prefix = 'INT-' if is_international else 'LOC-'
        
        # Get program code
        program_code = ''.join(word[0].upper() for word in application.program.split())
        
        # Get latest ID for this year and type
        latest_student = StudentID.query.filter(
            StudentID.student_id.like(f'{year}-{prefix}{program_code}%')
        ).order_by(StudentID.student_id.desc()).first()
        
        if latest_student:
            last_number = int(latest_student.student_id.split('-')[-1])
            new_number = f"{last_number + 1:04d}"
        else:
            new_number = "0001"
        
        # Create new student ID
        student_id = f"{year}-{prefix}{program_code}-{new_number}"
        
        # Create StudentID record
        new_student_id = StudentID(
            student_id=student_id,
            application_id=application.id
        )
        
        # Create notification for student
        notification = Notification(
            user_id=application.user_id,
            message=f'تم إنشاء رقم الطالب الخاص بك: {student_id}',
            read=False
        )
        
        # Update application status
        application.status = 'Enrolled'
        
        db.session.add(new_student_id)
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'student_id': student_id,
            'is_international': is_international
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('Access denied: Admin privileges required', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Get stats for dashboard
    applications_count = Application.query.filter_by(status='Pending Review').count()
    payment_pending_count = Application.query.filter_by(status='Documents Approved', payment_status='Pending').count()
    certificate_requests = Certificate.query.count()
    open_tickets = Ticket.query.filter_by(status='Open').count()
    
    # Get recent applications and tickets
    recent_applications = Application.query.order_by(Application.date_submitted.desc()).limit(3).all()
    recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(3).all()
    
    # Get recent certificate requests
    recent_certificates = Certificate.query.order_by(Certificate.request_date.desc()).limit(3).all()
    
    return render_template('admin/dashboard.html', 
                          applications_count=applications_count,
                          payment_pending_count=payment_pending_count,
                          certificate_requests=certificate_requests,
                          open_tickets=open_tickets,
                          recent_applications=recent_applications,
                          recent_tickets=recent_tickets,
                          recent_certificates=recent_certificates)






# Keep only this route (around line 380)
@app.route('/admin/certificates/update/<int:cert_id>', methods=['POST'])
@login_required
def admin_update_certificate(cert_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        certificate = Certificate.query.get_or_404(cert_id)
        
        # Update certificate status
        certificate.status = 'Ready for Pickup'
        
        # Create notification for student
        notification = Notification(
            user_id=certificate.user_id,
            message=f'Your certificate {certificate.cert_id} is ready for pickup.',
            read=False
        )
        
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'cert_id': certificate.cert_id,
            'message': 'Certificate marked as ready for pickup'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })


@app.route('/admin/certificates')
@login_required
def admin_certificates():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    # Get all certificates including pending payment ones
    certificates = Certificate.query.order_by(Certificate.request_date.desc()).all()
    
    return render_template('admin/certificates.html', certificates=certificates)


@app.route('/admin/tickets')
@login_required
def admin_tickets():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template('admin/tickets.html', tickets=tickets)

@app.route('/admin/tickets/<int:ticket_id>')
@login_required
def admin_ticket_detail(ticket_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('admin/ticket_detail.html', ticket=ticket)

@app.route('/admin/tickets/reply/<int:ticket_id>', methods=['POST'])
@login_required
def admin_ticket_reply(ticket_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        message_text = request.form.get('message')
        
        if not message_text:
            return jsonify({'success': False, 'message': 'Message cannot be empty'})
        
        # Create a new message
        new_message = TicketMessage(
            ticket_id=ticket.id,
            sender='Admin',
            message=message_text,
            created_at=datetime.utcnow()
        )
        
        # Update ticket status to In Progress if it's Open
        if ticket.status == 'Open':
            ticket.status = 'In Progress'
        
        # Create notification for student
        notification = Notification(
            user_id=ticket.user_id,
            message=f'New reply to your ticket: {ticket.subject}',
            read=False
        )
        
        db.session.add(new_message)
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Reply sent successfully',
            'data': {
                'message': message_text,
                'created_at': new_message.created_at.strftime('%Y-%m-%d %H:%M'),
                'sender': 'Admin'
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/tickets/update_status/<int:ticket_id>', methods=['POST'])
@login_required
def admin_update_ticket_status(ticket_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    ticket = Ticket.query.get_or_404(ticket_id)
    new_status = request.form.get('status')
    
    if new_status in ['Open', 'In Progress', 'Closed']:
        ticket.status = new_status
        
        # Notify student of status change
        notification = Notification(
            user_id=ticket.user_id,
            message=f'Your ticket {ticket.ticket_id} status has been updated to {new_status}.'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Invalid status'})

@app.route('/admin/settings')
@login_required
def admin_settings():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    # In a real app, you might load settings from a database
    settings = {
        'local_fee': 600,
        'international_fee': 1500,
        'certificate_fee': 200,
        'email_notifications': True,
        'sms_notifications': True,
        'push_notifications': False
    }
    
    return render_template('admin/settings.html', settings=settings)

# Student Routes
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # Get student's applications, documents, certificates, and tickets
    applications = Application.query.filter_by(user_id=current_user.id).all()
    documents = Document.query.filter_by(user_id=current_user.id).all()
    certificates = Certificate.query.filter_by(user_id=current_user.id).all()
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    
    # Get unread notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, read=False).order_by(Notification.created_at.desc()).all()
    
    # Check if there are any applications with approved documents that need payment
    payment_required = any(app.status == 'Documents Approved' and app.payment_status == 'Pending' for app in applications)
    
    # Check if there are any certificates ready for pickup
    certificate_ready = any(cert.status == 'Ready for Pickup' for cert in certificates)
    
    return render_template('student/dashboard.html',
                          applications=applications,
                          documents=documents,
                          certificates=certificates,
                          tickets=tickets,
                          notifications=notifications,
                          payment_required=payment_required,
                          certificate_ready=certificate_ready)

@app.route('/student/applications')
@login_required
def student_applications():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    applications = Application.query.filter_by(user_id=current_user.id).order_by(Application.date_submitted.desc()).all()
    return render_template('student/applications.html', applications=applications)

@app.route('/student/applications/new', methods=['GET', 'POST'])
@login_required
def student_new_application():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # Add a FlaskForm for CSRF protection
    class ApplicationForm(FlaskForm):
        pass  # Empty form just for CSRF protection
    
    form = ApplicationForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        program = request.form.get('program')
        
        # Generate a unique application ID
        app_count = Application.query.count() + 1
        app_id = f"APP-{app_count:03d}"
        
        # Create new application
        new_application = Application(
            app_id=app_id,
            user_id=current_user.id,
            program=program,
            status='Pending Review',
            payment_status='Pending'
        )
        
        db.session.add(new_application)
        db.session.commit()
        
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('student_documents', app_id=new_application.id))
    
    return render_template('student/new_application.html', form=form)



@app.route('/student/documents')
@login_required
def student_documents():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    documents = Document.query.filter_by(user_id=current_user.id).all()
    applications = Application.query.filter_by(user_id=current_user.id).all()
    
    return render_template('student/documents.html', documents=documents, applications=applications)

@app.route('/student/documents/upload', methods=['GET', 'POST'])
@login_required
def student_upload_document():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # Add a FlaskForm for CSRF protection
    class DocumentForm(FlaskForm):
        pass  # Empty form just for CSRF protection
    
    form = DocumentForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        document_type = request.form.get('document_type')
        application_id = request.form.get('application_id')
        
        if 'document' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['document']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            # Create a unique filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            new_filename = f"{current_user.id}_{timestamp}_{filename}"
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
            
            # Create document record
            new_document = Document(
                user_id=current_user.id,
                application_id=application_id if application_id else None,
                name=document_type,
                file_path=f"uploads/{new_filename}",
                status='Uploaded'
            )
            
            db.session.add(new_document)
            db.session.commit()
            
            flash('Document uploaded successfully!', 'success')
            return redirect(url_for('student_documents'))
    
    applications = Application.query.filter_by(user_id=current_user.id).all()
    return render_template('student/upload_document.html', form=form, applications=applications)

@app.route('/student/document/delete/<int:doc_id>', methods=['POST'])
@login_required
def student_delete_document(doc_id):
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    document = Document.query.get_or_404(doc_id)
    
    # Ensure this document belongs to the current user
    if document.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_documents'))
    
    # Get the file path to remove it from storage
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.file_path.replace('uploads/', ''))
    
    # Delete the document from the database
    db.session.delete(document)
    db.session.commit()
    
    # Try to remove the file (if it exists)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        # Log the error but continue (document is already deleted from database)
        print(f"Error removing file: {e}")
    
    flash('Document deleted successfully', 'success')
    return redirect(url_for('student_documents'))

@app.route('/student/certificates')
@login_required
def student_certificates():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    certificates = Certificate.query.filter_by(user_id=current_user.id).all()
    return render_template('student/certificates.html', certificates=certificates)


# Keep the original route
@app.route('/student/certificates/request', methods=['GET', 'POST'])
@login_required
def student_request_certificate():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # Add a FlaskForm for CSRF protection
    class CertificateForm(FlaskForm):
        pass  # Empty form just for CSRF protection
    
    form = CertificateForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Create new certificate request
        certificate = Certificate(
            user_id=current_user.id,
            type=request.form.get('certificate_type'),
            purpose=request.form.get('purpose'),
            copies=int(request.form.get('copies', 1)),
            status='Pending Payment',
            cert_id=f"CERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            request_date=datetime.now()
        )
        
        db.session.add(certificate)
        db.session.commit()
        
        flash('Certificate request submitted successfully!', 'success')
        return redirect(url_for('student_certificates'))
        
    return render_template('student/request_certificate.html', form=form)

@app.route('/student/support')
@login_required
def student_support():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('student/support.html', tickets=tickets)

@app.route('/student/support/new', methods=['GET', 'POST'])
@login_required
def student_new_ticket():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not subject or not message:
            flash('Please fill out all fields', 'danger')
            return redirect(request.url)
        
        # Generate a unique ticket ID
        ticket_count = Ticket.query.count() + 1
        ticket_id = f"TKT-{ticket_count:03d}"
        
        # Create new ticket
        new_ticket = Ticket(
            ticket_id=ticket_id,
            user_id=current_user.id,
            subject=subject,
            status='Open'
        )
        
        db.session.add(new_ticket)
        db.session.commit()
        
        # Add the first message
        first_message = TicketMessage(
            ticket_id=new_ticket.id,
            sender='Student',
            message=message
        )
        
        db.session.add(first_message)
        db.session.commit()
        
        flash('Support ticket submitted successfully!', 'success')
        return redirect(url_for('student_support'))
    
    return render_template('student/new_ticket.html')

@app.route('/student/support/<int:ticket_id>')
@login_required
def student_ticket_detail(ticket_id):
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Ensure this ticket belongs to the current user
    if ticket.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_support'))
    
    return render_template('student/ticket_detail.html', ticket=ticket)

@app.route('/student/support/reply/<int:ticket_id>', methods=['POST'])
@login_required
def student_ticket_reply(ticket_id):
    if current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Ensure ticket belongs to current user
        if ticket.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Access denied'})
        
        message_text = request.form.get('message')
        if not message_text:
            return jsonify({'success': False, 'message': 'Message cannot be empty'})
        
        # Create new message
        new_message = TicketMessage(
            ticket_id=ticket.id,
            sender='Student',
            message=message_text,
            created_at=datetime.utcnow()
        )
        
        # Create notification for admins
        admins = User.query.filter_by(role='admin').all()
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                message=f'New reply on ticket {ticket.ticket_id} from {current_user.full_name}',
                read=False
            )
            db.session.add(notification)
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Reply sent successfully',
            'data': {
                'message': message_text,
                'created_at': new_message.created_at.strftime('%Y-%m-%d %H:%M'),
                'sender': 'Student'
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/student/payments/<int:app_id>', methods=['GET', 'POST'])
@login_required
def student_payment(app_id):
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    application = Application.query.get_or_404(app_id)
    
    # Create empty form for CSRF protection
    form = FlaskForm()
    
    # Ensure this application belongs to the current user
    if application.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_applications'))
    
    if request.method == 'POST' and form.validate_on_submit():
        # Calculate fee based on nationality
        fee = 1500 if current_user.nationality == 'International' else 600
        
        # Create payment record
        new_payment = Payment(
            user_id=current_user.id,
            application_id=application.id,
            amount=fee,
            payment_method='Simulation',
            transaction_id=f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        )
        
        # Update application payment status
        application.payment_status = 'Paid'
        
        db.session.add(new_payment)
        db.session.commit()
        
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('student_applications'))
    
    # Calculate fee based on nationality
    fee = 1500 if current_user.nationality == 'International' else 600
    
    return render_template('student/payment.html', 
                         application=application, 
                         fee=fee)

@app.route('/student/certificate_payment/<int:cert_id>', methods=['GET', 'POST'])
@login_required
def student_certificate_payment(cert_id):
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    certificate = Certificate.query.get_or_404(cert_id)
    
    # Create empty form for CSRF protection
    class PaymentForm(FlaskForm):
        pass
    
    form = PaymentForm()
    
    # Ensure certificate belongs to current user
    if certificate.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_certificates'))
        
    if request.method == 'POST' and form.validate_on_submit():
        # Process payment
        payment = Payment(
            user_id=current_user.id,
            certificate_id=certificate.id,
            amount=200 * certificate.copies,  # 200 EGP per copy
            payment_method='Simulation',
            transaction_id=f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        )
        
        # Update certificate status
        certificate.payment_status = 'Paid'
        certificate.status = 'Processing'
        
        db.session.add(payment)
        db.session.commit()
        
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('student_certificates'))
    
    # Calculate fee
    fee = 200 * certificate.copies
    
    return render_template('student/certificate_payment.html',
                         certificate=certificate,
                         fee=fee,
                         form=form)

@app.route('/student/settings')
@login_required
def student_settings():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    return render_template('student/settings.html')

@app.route('/student/settings/update', methods=['POST'])
@login_required
def student_update_settings():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    
    current_user.full_name = full_name
    current_user.phone = phone
    
    db.session.commit()
    
    flash('Settings updated successfully!', 'success')
    return redirect(url_for('student_settings'))

@app.route('/student/change_password', methods=['POST'])
@login_required
def student_change_password():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('student_settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('student_settings'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('student_settings'))

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    notifications = Notification.query.filter_by(user_id=current_user.id, read=False).all()
    
    for notification in notifications:
        notification.read = True
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/student/close_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def student_close_ticket(ticket_id):
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Ensure this ticket belongs to the current user
    if ticket.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_support'))
    
    ticket.status = 'Closed'
    db.session.commit()
    
    flash('Ticket closed successfully!', 'success')
    return redirect(url_for('student_ticket_detail', ticket_id=ticket.id))

@app.route('/student/update_notification_preferences', methods=['POST'])
@login_required
def student_update_notification_preferences():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # In a real app, you would update user preferences in the database
    flash('Notification preferences updated successfully!', 'success')
    return redirect(url_for('student_settings'))


# Add this new command function
@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize the database and create admin user."""
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(
            email='admin@example.com',
            full_name='Admin User',
            role='admin'
        )
        admin.set_password('adminpassword')
        db.session.add(admin)
        db.session.commit()
        click.echo('Initialized the database and created admin user.')
    else:
        click.echo('Database already initialized.')




@app.route('/admin/projects')
@login_required
def admin_projects():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects)



@app.route('/admin/projects/new', methods=['GET', 'POST'])
@login_required
def admin_new_project():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        url = request.form.get('url')
        is_popular = 'is_popular' in request.form
        is_active = 'is_active' in request.form
        
        # Handle file upload
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '':
                # Validate file extension
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                if '.' in file.filename and \
                   file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                    
                    # Create unique filename
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    original_filename = secure_filename(file.filename)
                    new_filename = f"project_{timestamp}_{original_filename}"
                    
                    # Ensure upload directory exists
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    
                    # Save file
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                        file.save(file_path)
                        image_path = 'uploads/' + new_filename
                    except Exception as e:
                        flash(f'Error uploading file: {str(e)}', 'danger')
                        return redirect(url_for('admin_new_project'))
                else:
                    flash('Invalid file type. Please upload an image file.', 'danger')
                    return redirect(url_for('admin_new_project'))
        
        try:
            # Create new project
            new_project = Project(
                title=title,
                description=description,
                category=category,
                url=url,
                image_path=image_path,
                is_popular=is_popular,
                is_active=is_active,
                user_id=current_user.id
            )
            
            db.session.add(new_project)
            db.session.commit()
            
            flash('Project added successfully!', 'success')
            return redirect(url_for('admin_projects'))
            
        except Exception as e:
            # If there's an error saving to database, delete uploaded file
            if image_path:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                except:
                    pass
            db.session.rollback()
            flash(f'Error creating project: {str(e)}', 'danger')
            return redirect(url_for('admin_new_project'))
    
    # GET request - show form
    return render_template('admin/new_project.html')


@app.route('/admin/projects/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_project(project_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        project.title = request.form.get('title')
        project.description = request.form.get('description')
        project.category = request.form.get('category')
        project.url = request.form.get('url')
        project.is_popular = 'is_popular' in request.form
        project.is_active = 'is_active' in request.form
        
        # Handle file upload if there's a new image
        if 'project_image' in request.files:
            file = request.files['project_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                # Create a unique filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_filename = f"project_{timestamp}_{filename}"
                
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                
                # Delete the old image if it exists
                if project.image_path:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                                project.image_path.replace('uploads/', ''))
                    try:
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                    except Exception as e:
                        print(f"Error removing old image: {e}")
                
                project.image_path = f"uploads/{new_filename}"
        
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('admin_projects'))
    
    return render_template('admin/edit_project.html', project=project)

@app.route('/admin/projects/delete/<int:project_id>', methods=['POST'])
@login_required
def admin_delete_project(project_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    project = Project.query.get_or_404(project_id)
    
    # Delete image file if it exists
    if project.image_path:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                               project.image_path.replace('uploads/', ''))
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error removing file: {e}")
    
    db.session.delete(project)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/projects/toggle-status/<int:project_id>', methods=['POST'])
@login_required
def admin_toggle_project_status(project_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    project = Project.query.get_or_404(project_id)
    status_type = request.form.get('status_type')
    
    if status_type == 'active':
        project.is_active = not project.is_active
        status_message = 'active' if project.is_active else 'inactive'
    elif status_type == 'popular':
        project.is_popular = not project.is_popular
        status_message = 'popular' if project.is_popular else 'not popular'
    
    db.session.commit()
    return jsonify({'success': True, 'status': status_message})


@app.route('/projects')
def projects():
    # Get all active projects
    projects = Project.query.filter_by(is_active=True).order_by(Project.created_at.desc()).all()
    
    # Get unique categories
    categories = db.session.query(Project.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    
    return render_template('projects.html', 
                         projects=projects,
                         categories=categories)

# Register the command with Flask CLI
app.cli.add_command(init_db_command)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route('/news')
def news():
    news_items = News.query.order_by(News.date.desc()).all()
    return render_template('news.html', news_items=news_items)

@app.route('/admin/news')
@login_required
def admin_news():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    news_items = News.query.order_by(News.date.desc()).all()
    return render_template('admin/news.html', news_items=news_items)

@app.route('/admin/news/add', methods=['GET', 'POST'])
@login_required
def admin_news_add():
    class NewsForm(FlaskForm):
        pass
    
    form = NewsForm()
    if request.method == 'POST' and form.validate_on_submit():
        title = request.form.get('title')
        description = request.form.get('description')
        news_type = request.form.get('type')
        date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
        
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_filename = f"news_{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                image_path = f"uploads/{new_filename}"
        
        news_item = News(
            title=title,
            description=description,
            type=news_type,
            date=date,
            image_path=image_path
        )
        
        db.session.add(news_item)
        db.session.commit()
        
        flash('News item added successfully!', 'success')
        return redirect(url_for('admin_news'))
    
    return render_template('admin/news_add.html', form=form)

@app.route('/admin/news/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def admin_news_edit(id):
    class NewsForm(FlaskForm):
        pass
    
    form = NewsForm()
    news_item = News.query.get_or_404(id)
    
    if request.method == 'POST' and form.validate_on_submit():
        news_item.title = request.form.get('title')
        news_item.description = request.form.get('description')
        news_item.type = request.form.get('type')
        news_item.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
        
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Delete old image if exists
                if news_item.image_path:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                                news_item.image_path.replace('uploads/', ''))
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_filename = f"news_{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                news_item.image_path = f"uploads/{new_filename}"
        
        db.session.commit()
        flash('News item updated successfully!', 'success')
        return redirect(url_for('admin_news'))
    
    return render_template('admin/news_edit.html', form=form, news=news_item)

@app.route('/admin/news/delete/<int:id>', methods=['POST'])
@login_required
def admin_news_delete(id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    news_item = News.query.get_or_404(id)
    
    # Delete image file if exists
    if news_item.image_path:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                news_item.image_path.replace('uploads/', ''))
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(news_item)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/about')
def about():
    """Display about page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Display contact page"""
    return render_template('contact.html')

@app.route('/search')
def search():
    """Handle search functionality"""
    query = request.args.get('q', '')
    # Implement search logic here
    results = []  # Replace with actual search results
    return render_template('search.html', results=results, query=query)

@app.route('/faq')
def faq():
    """Display FAQ page"""
    return render_template('faq.html')

@app.route('/privacy')
def privacy():
    """Display privacy policy page"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Display terms of service page"""
    return render_template('terms.html')

@app.route('/student/courses')
@login_required
def student_courses():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    # Get student's enrolled courses
    enrollments = CourseEnrollment.query.filter_by(student_id=current_user.id).all()
    
    # Get available courses for enrollment
    available_courses = Course.query.filter_by(is_active=True).all()
    
    return render_template('student/courses.html', 
                         enrollments=enrollments,
                         available_courses=available_courses)

@app.route('/student/courses/enroll/<int:course_id>', methods=['POST'])
@login_required
def student_course_enroll(course_id):
    if current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    # Check if already enrolled
    existing_enrollment = CourseEnrollment.query.filter_by(
        student_id=current_user.id,
        course_id=course_id
    ).first()
    
    if existing_enrollment:
        return jsonify({'success': False, 'message': 'Already enrolled in this course'})
    
    # Create new enrollment
    enrollment = CourseEnrollment(
        student_id=current_user.id,
        course_id=course_id
    )
    
    db.session.add(enrollment)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Successfully enrolled in course'})

@app.route('/admin/courses')
@login_required
def admin_courses():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    courses = Course.query.all()
    return render_template('admin/courses.html', courses=courses)

@app.route('/admin/courses/add', methods=['GET', 'POST'])
@login_required
def admin_course_add():
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        course = Course(
            code=request.form.get('code'),
            title=request.form.get('title'),
            description=request.form.get('description'),
            credits=int(request.form.get('credits')),
            prerequisites=request.form.get('prerequisites')
        )
        
        db.session.add(course)
        db.session.commit()
        
        flash('Course added successfully!', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/course_add.html')

@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@login_required
def admin_course_edit(course_id):
    if not current_user.is_admin():
        return redirect(url_for('student_dashboard'))
    
    course = Course.query.get_or_404(course_id)
    
    if request.method == 'POST':
        course.code = request.form.get('code')
        course.title = request.form.get('title')
        course.description = request.form.get('description')
        course.credits = int(request.form.get('credits'))
        course.prerequisites = request.form.get('prerequisites')
        course.is_active = 'is_active' in request.form
        
        db.session.commit()
        flash('Course updated successfully!', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/course_edit.html', course=course)

# Add this context processor
@app.context_processor
def utility_processor():
    return {
        'now': datetime.now()
    }

from commands import init_app
init_app(app)

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                full_name='Admin User',
                role='admin'
            )
            admin.set_password('adminpassword')
            db.session.add(admin)
            db.session.commit()
            print('Admin user created successfully')
        else:
            print('Admin user already exists')
    
    app.run(debug=True)