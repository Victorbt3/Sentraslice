import bcrypt
import json
from functools import wraps
from flask import session, jsonify, request
from database import db_session
from models import User, Role, AuditLog

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            user_role = session.get('role')
            if user_role not in allowed_roles:
                return jsonify({"error": "Forbidden", "message": "Insufficient permissions for role: " + str(user_role)}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_activity(user_id, username, action, details, status, ip=None):
    try:
        log = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            details=details,
            status=status,
            ip_address=ip or request.remote_addr if request else "127.0.0.1"
        )
        db_session.add(log)
        db_session.commit()
    except Exception as e:
        print(f"Failed to write audit log: {e}")
        db_session.rollback()

def seed_users():
    # Verify if roles exist, if not create them
    admin_role = db_session.query(Role).filter_by(name='Admin').first()
    if not admin_role:
        admin_role = Role(name='Admin', permissions=json.dumps(['all']))
        db_session.add(admin_role)
        
    secops_role = db_session.query(Role).filter_by(name='SecOps').first()
    if not secops_role:
        secops_role = Role(name='SecOps', permissions=json.dumps(['read', 'write', 'scan', 'report']))
        db_session.add(secops_role)
        
    viewer_role = db_session.query(Role).filter_by(name='Viewer').first()
    if not viewer_role:
        viewer_role = Role(name='Viewer', permissions=json.dumps(['read']))
        db_session.add(viewer_role)
        
    db_session.commit()
    
    # Verify if users exist, if not create them
    admin_user = db_session.query(User).filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@sentraslice.io',
            password_hash=hash_password('Admin@123456'),
            role_id=admin_role.id
        )
        db_session.add(admin_user)
        
    secops_user = db_session.query(User).filter_by(username='secops').first()
    if not secops_user:
        secops_user = User(
            username='secops',
            email='secops@sentraslice.io',
            password_hash=hash_password('SecOps@123456'),
            role_id=secops_role.id
        )
        db_session.add(secops_user)
        
    viewer_user = db_session.query(User).filter_by(username='viewer').first()
    if not viewer_user:
        viewer_user = User(
            username='viewer',
            email='viewer@sentraslice.io',
            password_hash=hash_password('Viewer@123456'),
            role_id=viewer_role.id
        )
        db_session.add(viewer_user)
        
    db_session.commit()
