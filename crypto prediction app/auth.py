from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from src.models.user import User, db
from werkzeug.security import generate_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
from functools import wraps

auth_bp = Blueprint('auth', __name__)

def mfa_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_authenticated and current_user.mfa_enabled and not session.get('mfa_verified'):
            return redirect(url_for('auth.verify_mfa'))
        return func(*args, **kwargs)
    return decorated_view

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('auth.register'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered')
            return redirect(url_for('auth.register'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.password = password
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.verify_password(password):
            login_user(user)
            
            # If MFA is enabled, redirect to verification
            if user.mfa_enabled:
                session['mfa_verified'] = False
                return redirect(url_for('auth.verify_mfa'))
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('mfa_verified', None)
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth_bp.route('/verify-mfa', methods=['GET', 'POST'])
@login_required
def verify_mfa():
    if request.method == 'POST':
        token = request.form.get('token')
        
        if current_user.verify_totp(token):
            session['mfa_verified'] = True
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        
        flash('Invalid verification code')
    
    return render_template('auth/verify_mfa.html')

@auth_bp.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    if request.method == 'POST':
        token = request.form.get('token')
        
        if current_user.verify_totp(token):
            current_user.mfa_enabled = True
            db.session.commit()
            session['mfa_verified'] = True
            flash('Two-factor authentication has been enabled.')
            return redirect(url_for('main.profile'))
        
        flash('Invalid verification code')
    
    qr_code = current_user.generate_qrcode()
    return render_template('auth/setup_mfa.html', qr_code=qr_code, secret=current_user.otp_secret)

@auth_bp.route('/disable-mfa', methods=['POST'])
@login_required
@mfa_required
def disable_mfa():
    current_user.mfa_enabled = False
    db.session.commit()
    flash('Two-factor authentication has been disabled.')
    return redirect(url_for('main.profile'))
