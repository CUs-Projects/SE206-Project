from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from models import User, db, Project

auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('student.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin():
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('student.dashboard'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main_bp.route('/')
def index():
    featured_projects = Project.query.filter_by(is_active=True, is_popular=True).limit(3).all()
    return render_template('index.html', featured_projects=featured_projects)

@main_bp.route('/projects')
def projects():
    all_projects = Project.query.filter_by(is_active=True).order_by(Project.created_at.desc()).all()
    return render_template('projects.html', projects=all_projects)