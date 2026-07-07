import os
from datetime import datetime, timedelta
import json
from flask import Flask, render_template, request, session, jsonify, send_file, redirect, url_for, make_response
from database import db_session, init_db
from models import User, Role, NetworkSlice, Assessment, Vulnerability, Report, Notification, AuditLog, Setting
from auth import hash_password, verify_password, login_required, role_required, seed_users, log_activity
import scanner
import reports
import time
import io

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sentraslice_super_secret_session_encryption_key_2026')
app.permanent_session_lifetime = timedelta(days=7)

# One-time init guard — safe for Vercel serverless cold starts
_db_initialized = False

def seed_data():
    """Initialize DB schema and seed default data. Safe to call multiple times."""
    global _db_initialized
    if _db_initialized:
        return
    try:
        init_db()
        seed_users()

        # Only seed slices if table is empty
        if db_session.query(NetworkSlice).count() == 0:
            mb = NetworkSlice(
                name="MTN_5G_eMBB_Streaming", slice_type="eMBB", status="active",
                latency=12, bandwidth=12.5, encryption="AES-256",
                authentication="5G-AKA", firewall=True, health_score=92, risk_level="Low"
            )
            ur = NetworkSlice(
                name="Airtel_5G_URLLC_Surgery", slice_type="URLLC", status="active",
                latency=2, bandwidth=1.2, encryption="WireGuard",
                authentication="SIM-based", firewall=True, health_score=100, risk_level="Low"
            )
            mt = NetworkSlice(
                name="Ericsson_5G_mMTC_SmartGrid", slice_type="mMTC", status="active",
                latency=48, bandwidth=0.08, encryption="None",
                authentication="None", firewall=False, health_score=42, risk_level="High"
            )
            db_session.add_all([mb, ur, mt])
            db_session.commit()

            assessment = Assessment(
                slice_id=mt.id, scanner_user_id=1,
                risk_percentage=58.0, security_score=42, threat_count=3,
                status='completed',
                started_at=datetime.utcnow() - timedelta(hours=2),
                completed_at=datetime.utcnow() - timedelta(hours=2) + timedelta(seconds=12)
            )
            db_session.add(assessment)
            db_session.commit()

            db_session.add_all([
                Vulnerability(
                    assessment_id=assessment.id, slice_id=mt.id,
                    name="No encryption on slice data plane", category="Encryption",
                    description="Data packets traversing this slice are not encrypted. Traffic is susceptible to active interception and eavesdropping by rogue cells.",
                    severity="Critical", cvss_score=9.8, likelihood="High", impact="Critical",
                    recommended_fix="Deploy IPsec tunnels or WireGuard configurations to secure data-plane communications between gNodeB and UPF.",
                    estimated_resolution_time="30 Mins", status="detected"
                ),
                Vulnerability(
                    assessment_id=assessment.id, slice_id=mt.id,
                    name="Slice border firewall disabled", category="Firewall",
                    description="The slice perimeter firewall is disabled or misconfigured, permitting unrestricted packet flows from neighboring network slices.",
                    severity="Critical", cvss_score=9.6, likelihood="High", impact="Critical",
                    recommended_fix="Enable the perimeter firewall on the slice VNF and load standard baseline ACL rules.",
                    estimated_resolution_time="5 Mins", status="detected"
                ),
                Vulnerability(
                    assessment_id=assessment.id, slice_id=mt.id,
                    name="Unnecessary open ports on UPF node", category="Ports",
                    description="UPF nodes are exposing management ports (SSH 22, HTTP 8080) directly to the public network interfaces.",
                    severity="Medium", cvss_score=5.3, likelihood="Medium", impact="Low",
                    recommended_fix="Restrict public access to management ports using security groups and bound listener interfaces to internal VPN IPs only.",
                    estimated_resolution_time="15 Mins", status="detected"
                ),
                Notification(
                    type="Critical", title="Vulnerabilities Discovered on mMTC Grid",
                    message="Critical risk detected on slice Ericsson_5G_mMTC_SmartGrid: Firewall Disabled & No Encryption.",
                    created_at=datetime.utcnow() - timedelta(hours=2)
                ),
                Notification(
                    type="Info", title="System Initialization Complete",
                    message="Sentraslice 5G Vulnerability Platform loaded security parameters.",
                    created_at=datetime.utcnow() - timedelta(hours=4)
                ),
            ])
            db_session.commit()

        _db_initialized = True
    except Exception as e:
        db_session.rollback()
        print(f"[SliceGuard] DB seed warning: {e}")
        _db_initialized = True  # Don't retry on every request even if seed fails

@app.before_request
def ensure_db_ready():
    """Called before every request — initializes DB on first cold start."""
    seed_data()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

# --- WEB ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

# --- API ROUTES ---

# Authentication
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    mfa_code = data.get('mfa_code')
    
    if not email or not password:
        return jsonify({"error": "Bad Request", "message": "Email and password are required"}), 400
        
    user = db_session.query(User).filter((User.email == email) | (User.username == email)).first()
    
    if not user or not verify_password(password, user.password_hash):
        log_activity(None, email, "User Login", "Failed login attempt (invalid credentials)", "failed")
        return jsonify({"error": "Unauthorized", "message": "Invalid email or password"}), 401
        
    # Check mock 2FA if user has email 'admin@sentraslice.io' or password requires 2FA
    if user.username == 'admin' and not mfa_code:
        # Request 2FA verification step
        return jsonify({
            "mfa_required": True,
            "message": "Two-factor authentication code required"
        }), 200
        
    if user.username == 'admin' and mfa_code != '123456':
        log_activity(user.id, user.username, "User Login", "Failed MFA verification", "failed")
        return jsonify({"error": "Unauthorized", "message": "Invalid MFA validation code"}), 401

    # Login successful
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    session['email'] = user.email
    session['role'] = user.role.name
    
    user.last_login = datetime.utcnow()
    db_session.commit()
    
    log_activity(user.id, user.username, "User Login", "Successfully authenticated session", "success")
    
    return jsonify({
        "message": "Authentication successful",
        "user": user.to_dict()
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        log_activity(user_id, username, "User Logout", "Terminated session", "success")
        session.clear()
        return jsonify({"message": "Successfully logged out"}), 200
    
    return jsonify({"error": "Bad Request", "message": "No active session"}), 400

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if 'user_id' not in session:
        return jsonify({"authenticated": False}), 200
        
    user = db_session.get(User, session['user_id'])
    if not user:
        session.clear()
        return jsonify({"authenticated": False}), 200
        
    return jsonify({
        "authenticated": True,
        "user": user.to_dict()
    }), 200

# Dashboard summary endpoint
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    slices = db_session.query(NetworkSlice).all()
    total_slices = len(slices)
    active_slices = sum(1 for s in slices if s.status == 'active')
    avg_score = round(sum(s.health_score or 0 for s in slices) / total_slices, 1) if total_slices else 0
    
    critical_threats = db_session.query(Vulnerability).filter_by(status='detected', severity='Critical').count()
    high_threats = db_session.query(Vulnerability).filter_by(status='detected', severity='High').count()
    total_threats = db_session.query(Vulnerability).filter_by(status='detected').count()
    
    unread_notifs = db_session.query(Notification).filter_by(is_read=False).count()
    
    assessments = db_session.query(Assessment).all()
    total_assessments = len(assessments)
    completed_assessments = sum(1 for a in assessments if a.status == 'completed')
    
    slice_health = sorted(
        [{"name": s.name, "score": s.health_score, "risk_level": s.risk_level, "slice_type": s.slice_type} for s in slices],
        key=lambda x: x["score"]
    )
    
    return jsonify({
        "total_slices": total_slices,
        "active_slices": active_slices,
        "avg_security_score": avg_score,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "total_threats": total_threats,
        "unread_notifications": unread_notifs,
        "total_assessments": total_assessments,
        "completed_assessments": completed_assessments,
        "slice_health": slice_health
    }), 200

# Network Slices CRUD
@app.route('/api/slices', methods=['GET'])
@login_required
def get_slices():
    search = request.args.get('search', '')
    slice_type = request.args.get('type', '')
    status = request.args.get('status', '')
    sort_by = request.args.get('sort_by', 'name')
    
    query = db_session.query(NetworkSlice)
    
    if search:
        query = query.filter(NetworkSlice.name.like(f"%{search}%"))
    if slice_type:
        query = query.filter(NetworkSlice.slice_type == slice_type)
    if status:
        query = query.filter(NetworkSlice.status == status)
        
    slices = query.all()
    
    # Manual sorting
    reverse = False
    if sort_by.startswith('-'):
        sort_by = sort_by[1:]
        reverse = True
        
    def sort_key(s):
        val = getattr(s, sort_by, '')
        if isinstance(val, str):
            return val.lower()
        return val
        
    slices.sort(key=sort_key, reverse=reverse)
    
    return jsonify([s.to_dict() for s in slices]), 200

@app.route('/api/slices', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def create_slice():
    data = request.json or {}
    name = data.get('name')
    slice_type = data.get('slice_type')
    
    if not name or not slice_type:
        return jsonify({"error": "Bad Request", "message": "Slice name and type are required"}), 400
        
    # Check if duplicate name
    existing = db_session.query(NetworkSlice).filter_by(name=name).first()
    if existing:
        return jsonify({"error": "Conflict", "message": f"Slice name '{name}' already exists"}), 409
        
    # Set default values based on type
    latency = int(data.get('latency', 10 if slice_type == 'eMBB' else (2 if slice_type == 'URLLC' else 50)))
    bandwidth = float(data.get('bandwidth', 10.0 if slice_type == 'eMBB' else (1.0 if slice_type == 'URLLC' else 0.1)))
    
    new_slice = NetworkSlice(
        name=name,
        slice_type=slice_type,
        status="active",
        latency=latency,
        bandwidth=bandwidth,
        encryption=data.get('encryption', 'AES-256'),
        authentication=data.get('authentication', '5G-AKA'),
        firewall=bool(data.get('firewall', True)),
        health_score=100,
        risk_level="Low"
    )
    db_session.add(new_slice)
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Create Slice", f"Created network slice {name} ({slice_type})", "success")
    
    return jsonify(new_slice.to_dict()), 201

@app.route('/api/slices/<int:slice_id>', methods=['PUT'])
@login_required
@role_required(['Admin', 'SecOps'])
def update_slice(slice_id):
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return jsonify({"error": "Not Found", "message": "Slice not found"}), 404
        
    data = request.json or {}
    name = data.get('name')
    if name and name != slice_obj.name:
        existing = db_session.query(NetworkSlice).filter_by(name=name).first()
        if existing:
            return jsonify({"error": "Conflict", "message": f"Slice name '{name}' already exists"}), 409
        slice_obj.name = name
        
    slice_obj.slice_type = data.get('slice_type', slice_obj.slice_type)
    slice_obj.latency = int(data.get('latency', slice_obj.latency))
    slice_obj.bandwidth = float(data.get('bandwidth', slice_obj.bandwidth))
    slice_obj.encryption = data.get('encryption', slice_obj.encryption)
    slice_obj.authentication = data.get('authentication', slice_obj.authentication)
    slice_obj.firewall = bool(data.get('firewall', True) if 'firewall' in data else slice_obj.firewall)
    
    # Recalculate health state dynamically if updated
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Update Slice", f"Modified configuration for network slice {slice_obj.name}", "success")
    
    return jsonify(slice_obj.to_dict()), 200

@app.route('/api/slices/<int:slice_id>', methods=['DELETE'])
@login_required
@role_required(['Admin', 'SecOps'])
def delete_slice(slice_id):
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return jsonify({"error": "Not Found", "message": "Slice not found"}), 404
        
    name = slice_obj.name
    db_session.delete(slice_obj)
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Delete Slice", f"Removed network slice {name}", "success")
    
    return jsonify({"message": f"Slice '{name}' successfully deleted"}), 200

@app.route('/api/slices/<int:slice_id>/toggle', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def toggle_slice(slice_id):
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return jsonify({"error": "Not Found", "message": "Slice not found"}), 404
        
    if slice_obj.status == 'active':
        slice_obj.status = 'paused'
        action = "paused"
    elif slice_obj.status == 'paused':
        slice_obj.status = 'active'
        action = "activated"
    else:
        return jsonify({"error": "Conflict", "message": f"Cannot toggle status while slice is {slice_obj.status}"}), 409
        
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Toggle Slice Status", f"Toggled status of {slice_obj.name} to {action}", "success")
    
    return jsonify(slice_obj.to_dict()), 200

@app.route('/api/slices/<int:slice_id>/duplicate', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def duplicate_slice(slice_id):
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return jsonify({"error": "Not Found", "message": "Slice not found"}), 404
        
    base_name = slice_obj.name
    new_name = f"{base_name}_copy"
    counter = 1
    while db_session.query(NetworkSlice).filter_by(name=new_name).first():
        new_name = f"{base_name}_copy_{counter}"
        counter += 1
        
    new_slice = NetworkSlice(
        name=new_name,
        slice_type=slice_obj.slice_type,
        status="active",
        latency=slice_obj.latency,
        bandwidth=slice_obj.bandwidth,
        encryption=slice_obj.encryption,
        authentication=slice_obj.authentication,
        firewall=slice_obj.firewall,
        health_score=100,
        risk_level="Low"
    )
    db_session.add(new_slice)
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Duplicate Slice", f"Duplicated {base_name} as {new_name}", "success")
    
    return jsonify(new_slice.to_dict()), 201

# Vulnerability Scanning
@app.route('/api/scan/start', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def start_scan():
    data = request.json or {}
    slice_id = data.get('slice_id')
    
    if not slice_id:
        return jsonify({"error": "Bad Request", "message": "slice_id is required"}), 400
        
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return jsonify({"error": "Not Found", "message": "Slice not found"}), 404
        
    if slice_obj.status == 'scanning':
        # Retrieve active assessment
        active_assessment = db_session.query(Assessment).filter_by(slice_id=slice_id, status='in_progress').order_by(Assessment.started_at.desc()).first()
        if active_assessment:
            return jsonify({
                "message": "Scan already running",
                "assessment": active_assessment.to_dict()
            }), 200
            
    assessment = scanner.trigger_scan(slice_id, session['user_id'])
    
    log_activity(session['user_id'], session['username'], "Start Assessment Scan", f"Triggered security assessment scan for {slice_obj.name}", "success")
    
    return jsonify({
        "message": "Vulnerability scan initialized",
        "assessment": assessment.to_dict()
    }), 201

@app.route('/api/scan/status/<int:assessment_id>', methods=['GET'])
@app.route('/api/scan/status', methods=['GET'])
@login_required
def get_scan_status(assessment_id=None):
    if assessment_id is None:
        assessment_id = request.args.get('assessment_id', type=int)
    if not assessment_id:
        return jsonify({"error": "Bad Request", "message": "assessment_id is required"}), 400
        
    assessment = scanner.check_and_update_scan(assessment_id)
    if not assessment:
        return jsonify({"error": "Not Found", "message": "Assessment not found"}), 404
        
    elapsed = (datetime.utcnow() - assessment.started_at).total_seconds()
    progress = min(100, int((elapsed / 12.0) * 100)) if assessment.status == 'in_progress' else 100
    
    logs = scanner.get_live_logs(assessment.started_at)
    
    vulnerabilities = []
    if assessment.status == 'completed':
        vulnerabilities = [v.to_dict() for v in assessment.vulnerabilities]
        
    return jsonify({
        "assessment": assessment.to_dict(),
        "progress": progress,
        "status": assessment.status,
        "threat_count": assessment.threat_count,
        "logs": logs,
        "vulnerabilities": vulnerabilities
    }), 200

@app.route('/api/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    # Retrieve all detected vulnerabilities (optionally filter by status/severity/slice)
    severity = request.args.get('severity', '')
    slice_id = request.args.get('slice_id', '')
    status = request.args.get('status', 'detected')
    
    query = db_session.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if slice_id:
        query = query.filter(Vulnerability.slice_id == slice_id)
    if status:
        query = query.filter(Vulnerability.status == status)
        
    vulns = query.all()
    return jsonify([v.to_dict() for v in vulns]), 200

@app.route('/api/vulnerabilities/<int:vuln_id>/mitigate', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def mitigate_vulnerability(vuln_id):
    vuln = db_session.get(Vulnerability, vuln_id)
    if not vuln:
        return jsonify({"error": "Not Found", "message": "Vulnerability not found"}), 404
        
    if vuln.status == 'mitigated':
        return jsonify({"message": "Vulnerability already mitigated", "vulnerability": vuln.to_dict()}), 200
        
    vuln.status = 'mitigated'
    
    # Recalculate security score of the associated slice
    slice_obj = vuln.network_slice
    assessment = vuln.assessment
    
    # Recalculate based on active detected vulnerabilities
    active_vulns = db_session.query(Vulnerability).filter_by(assessment_id=assessment.id, status='detected').all()
    
    score_penalty = 0
    for v in active_vulns:
        if v.severity == 'Critical':
            score_penalty += 25
        elif v.severity == 'High':
            score_penalty += 15
        elif v.severity == 'Medium':
            score_penalty += 8
        else:
            score_penalty += 3
            
    security_score = max(10, 100 - score_penalty)
    risk_percentage = 100 - security_score
    
    if security_score >= 85:
        risk_level = 'Low'
    elif security_score >= 70:
        risk_level = 'Medium'
    elif security_score >= 50:
        risk_level = 'High'
    else:
        risk_level = 'Critical'
        
    # Update slice
    slice_obj.health_score = security_score
    slice_obj.risk_level = risk_level
    
    # Update assessment
    assessment.security_score = security_score
    assessment.risk_percentage = risk_percentage
    assessment.threat_count = len(active_vulns)
    
    # Generate Info Notification
    notif = Notification(
        type="Info",
        title="Vulnerability Mitigated",
        message=f"Threat '{vuln.name}' on slice {slice_obj.name} was marked as mitigated. Score updated to {security_score}%.",
        is_read=False
    )
    db_session.add(notif)
    db_session.commit()
    
    log_activity(session['user_id'], session['username'], "Mitigate Vulnerability", f"Mitigated threat '{vuln.name}' on {slice_obj.name}", "success")
    
    return jsonify({
        "message": "Vulnerability successfully mitigated",
        "vulnerability": vuln.to_dict(),
        "slice": slice_obj.to_dict()
    }), 200

# Admin User Management
@app.route('/api/users', methods=['GET'])
@login_required
@role_required(['Admin'])
def get_users():
    users = db_session.query(User).all()
    return jsonify([u.to_dict() for u in users]), 200

@app.route('/api/users', methods=['POST'])
@login_required
@role_required(['Admin'])
def create_user():
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role_name = data.get('role', 'Viewer')
    
    if db_session.query(User).filter_by(username=username).first() or db_session.query(User).filter_by(email=email).first():
        return jsonify({"error": "Conflict", "message": "Username or email already exists"}), 409
        
    role = db_session.query(Role).filter_by(name=role_name).first()
    if not role:
        return jsonify({"error": "Not Found", "message": "Role not found"}), 404
        
    new_user = User(username=username, email=email, password_hash=hash_password(password), role_id=role.id)
    db_session.add(new_user)
    db_session.commit()
    log_activity(session['user_id'], session['username'], "Create User", f"Created user {username}", "success")
    return jsonify(new_user.to_dict()), 201

# Reports
@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    reports_list = db_session.query(Report).order_by(Report.created_at.desc()).all()
    return jsonify([r.to_dict() for r in reports_list]), 200

@app.route('/api/reports/generate', methods=['POST'])
@login_required
@role_required(['Admin', 'SecOps'])
def generate_report():
    data = request.json or {}
    assessment_id = data.get('assessment_id')
    file_format = data.get('format', 'CSV') # CSV, EXCEL, PDF
    
    if not assessment_id:
        return jsonify({"error": "Bad Request", "message": "assessment_id is required"}), 400
        
    assessment = db_session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({"error": "Not Found", "message": "Assessment not found"}), 404
        
    report = reports.create_report_record(assessment_id, file_format, session['user_id'])
    
    log_activity(session['user_id'], session['username'], "Generate Report", f"Generated security report {report.name} in {file_format} format", "success")
    
    return jsonify({
        "message": "Report generated successfully",
        "report": report.to_dict()
    }), 201

@app.route('/api/reports/<int:report_id>/download', methods=['GET'])
@login_required
def download_report(report_id):
    report = db_session.get(Report, report_id)
    if not report:
        return jsonify({"error": "Not Found", "message": "Report not found"}), 404
        
    if not os.path.exists(report.file_path):
        return jsonify({"error": "Gone", "message": "Report file no longer exists on filesystem"}), 410
        
    # Return as download attachment
    return send_file(report.file_path, as_attachment=True, download_name=report.name)

# High Fidelity HTML printable report
@app.route('/api/reports/<int:assessment_id>/print', methods=['GET'])
def print_report(assessment_id):
    assessment = db_session.get(Assessment, assessment_id)
    if not assessment:
        return "Assessment not found", 404
        
    slice_obj = assessment.network_slice
    vulnerabilities = db_session.query(Vulnerability).filter_by(assessment_id=assessment_id).all()
    
    html = render_template(
        'print_report.html',
        assessment=assessment,
        slice=slice_obj,
        vulnerabilities=vulnerabilities,
        generation_time=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    
    return html

# Analytics dashboard endpoint
@app.route('/api/analytics', methods=['GET'])
@login_required
def get_analytics_metrics():
    # Return timeseries lists, charts parameters, CPU/RAM, threat distribution details
    # Risk trend line data (past 7 scans/days)
    risk_trend_labels = ["Day 1", "Day 2", "Day 3", "Day 4", "Day 5", "Day 6", "Day 7"]
    risk_trend_data = [20, 24, 18, 35, 42, 38, 30] # percentage values
    
    slices = db_session.query(NetworkSlice).all()
    
    threat_distribution = {
        "Critical": db_session.query(Vulnerability).filter_by(severity="Critical", status="detected").count(),
        "High": db_session.query(Vulnerability).filter_by(severity="High", status="detected").count(),
        "Medium": db_session.query(Vulnerability).filter_by(severity="Medium", status="detected").count(),
        "Low": db_session.query(Vulnerability).filter_by(severity="Low", status="detected").count()
    }
    
    slice_scores = {}
    for s in slices:
        slice_scores[s.name] = s.health_score
        
    # World attack vectors mockup
    attack_sources = [
        {"country": "United States", "ip": "194.26.29.102", "slices_targeted": 2, "threats_blocked": 1420, "coordinates": [40.7128, -74.0060]},
        {"country": "China", "ip": "222.186.30.55", "slices_targeted": 3, "threats_blocked": 3840, "coordinates": [39.9042, 116.4074]},
        {"country": "Russia", "ip": "185.156.177.8", "slices_targeted": 1, "threats_blocked": 2980, "coordinates": [55.7558, 37.6173]},
        {"country": "Germany", "ip": "46.165.230.12", "slices_targeted": 1, "threats_blocked": 680, "coordinates": [52.5200, 13.4050]},
        {"country": "Netherlands", "ip": "82.197.202.1", "slices_targeted": 2, "threats_blocked": 940, "coordinates": [52.3676, 4.9041]}
    ]
    
    return jsonify({
        "risk_trend": {
            "labels": risk_trend_labels,
            "data": risk_trend_data
        },
        "threat_distribution": threat_distribution,
        "slice_scores": slice_scores,
        "attack_sources": attack_sources,
        "system_status": {
            "cpu_usage": 14.5,
            "memory_usage": 32.8,
            "storage_usage": 18.2,
            "network_throughput": "824.5 Mbps"
        }
    }), 200

# Audit logs query
@app.route('/api/audit-logs', methods=['GET'])
@login_required
def get_audit_logs():
    logs = db_session.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in logs]), 200

# Notifications
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    unread_only = request.args.get('unread', 'false') == 'true'
    
    query = db_session.query(Notification)
    if unread_only:
        query = query.filter_by(is_read=False)
        
    notifications = query.order_by(Notification.created_at.desc()).all()
    return jsonify([n.to_dict() for n in notifications]), 200

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def read_all_notifications():
    db_session.query(Notification).filter_by(is_read=False).update({Notification.is_read: True}, synchronize_session=False)
    db_session.commit()
    return jsonify({"message": "All notifications marked as read"}), 200

# System Settings
@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    settings = db_session.query(Setting).all()
    settings_dict = {s.key: s.value for s in settings}
    
    # Fill in default settings if empty
    defaults = {
        "alert_email": "noc-alerts@sentraslice.io",
        "alert_sms": "+15550198",
        "scan_profile": "Standard Baseline Scan",
        "auto_mitigate": "disabled"
    }
    
    for k, v in defaults.items():
        if k not in settings_dict:
            setting = Setting(key=k, value=v)
            db_session.add(setting)
            settings_dict[k] = v
            
    db_session.commit()
    return jsonify(settings_dict), 200

@app.route('/api/settings', methods=['POST'])
@login_required
@role_required(['Admin'])
def save_settings():
    data = request.json or {}
    
    for key, value in data.items():
        setting = db_session.query(Setting).filter_by(key=key).first()
        if setting:
            setting.value = str(value)
        else:
            setting = Setting(key=key, value=str(value))
            db_session.add(setting)
            
    db_session.commit()
    log_activity(session['user_id'], session['username'], "Save Settings", "Updated system configurations", "success")
    return jsonify({"message": "Settings saved successfully", "settings": data}), 200

if __name__ == '__main__':
    # Bind to all interfaces for local testing
    app.run(host='0.0.0.0', port=5000, debug=True)
