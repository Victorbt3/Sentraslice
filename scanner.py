from datetime import datetime, timedelta
import random
from database import db_session
from models import NetworkSlice, Assessment, Vulnerability, Notification

VULN_TEMPLATES = {
    "weak_passwords": {
        "name": "Weak Passwords in SBA orchestrator",
        "category": "Authentication",
        "description": "The Service Based Architecture (SBA) orchestrator dashboard uses default credentials or weak, easily guessable administrative passwords, exposing the core routing tables.",
        "severity": "High",
        "cvss_score": 8.1,
        "likelihood": "High",
        "impact": "High",
        "recommended_fix": "Enforce strong password policies (min 14 characters, complexity requirements) and rotate credentials immediately.",
        "estimated_resolution_time": "10 Mins"
    },
    "open_ports": {
        "name": "Unnecessary open ports on UPF node",
        "category": "Ports",
        "description": "User Plane Function (UPF) nodes are exposing management ports (SSH 22, HTTP 8080) directly to the public network interfaces.",
        "severity": "Medium",
        "cvss_score": 5.3,
        "likelihood": "Medium",
        "impact": "Low",
        "recommended_fix": "Restrict public access to management ports using security groups and bound listener interfaces to internal VPN IPs only.",
        "estimated_resolution_time": "15 Mins"
    },
    "no_mfa": {
        "name": "MFA disabled for network engineer accounts",
        "category": "IAM",
        "description": "Administrative accounts in the slice orchestrator do not have Multi-Factor Authentication (MFA) enabled, leaving them vulnerable to credential harvesting.",
        "severity": "High",
        "cvss_score": 7.5,
        "likelihood": "High",
        "impact": "High",
        "recommended_fix": "Enforce 2FA/MFA across all administrative accounts on the MTN / Cisco dashboard orchestrator.",
        "estimated_resolution_time": "10 Mins"
    },
    "no_encryption": {
        "name": "No encryption on slice data plane",
        "category": "Encryption",
        "description": "Data packets traversing this slice are not encrypted. Traffic is susceptible to active interception and eavesdropping by rogue cells.",
        "severity": "Critical",
        "cvss_score": 9.8,
        "likelihood": "High",
        "impact": "Critical",
        "recommended_fix": "Deploy IPsec tunnels or WireGuard configurations to secure data-plane communications between gNodeB and UPF.",
        "estimated_resolution_time": "30 Mins"
    },
    "expired_certs": {
        "name": "Expired TLS certificates on AMF control link",
        "category": "Certificates",
        "description": "The certificate securing communication between the Access and Mobility Management Function (AMF) and the RAN node has expired.",
        "severity": "Medium",
        "cvss_score": 6.5,
        "likelihood": "Low",
        "impact": "High",
        "recommended_fix": "Renew the AMF node security certificates using the telecom CA trust store.",
        "estimated_resolution_time": "15 Mins"
    },
    "firewall_disabled": {
        "name": "Slice border firewall disabled",
        "category": "Firewall",
        "description": "The slice perimeter firewall is disabled or misconfigured, permitting unrestricted packet flows from neighboring network slices.",
        "severity": "Critical",
        "cvss_score": 9.6,
        "likelihood": "High",
        "impact": "Critical",
        "recommended_fix": "Enable the perimeter firewall on the slice virtual network function (VNF) and load standard baseline ACL rules.",
        "estimated_resolution_time": "5 Mins"
    },
    "misconfigured_apis": {
        "name": "Broken Object Level Authorization (BOLA) in NEF API",
        "category": "APIs",
        "description": "The Network Exposure Function (NEF) API fails to validate tenant ownership, allowing authenticated slices to view other slices' configurations.",
        "severity": "High",
        "cvss_score": 8.8,
        "likelihood": "Medium",
        "impact": "High",
        "recommended_fix": "Update NEF endpoint routing to validate access tokens against tenant IDs before retrieving profile data.",
        "estimated_resolution_time": "20 Mins"
    },
    "privilege_escalation": {
        "name": "Privilege escalation via weak Kubernetes config",
        "category": "IAM",
        "description": "Container environments running AMF services run as root, allowing container breakout and node-level control takeover.",
        "severity": "High",
        "cvss_score": 8.8,
        "likelihood": "Low",
        "impact": "Critical",
        "recommended_fix": "Enforce container security contexts: set runAsNonRoot=true and readOnlyRootFilesystem=true in deployment templates.",
        "estimated_resolution_time": "25 Mins"
    },
    "ddos_risk": {
        "name": "DDoS vulnerability in GTP-U tunnel processing",
        "category": "Software Version",
        "description": "The GTP-U tunnel parser library is vulnerable to resource exhaustion when receiving malformed GTP headers, potentially leading to slice downtime.",
        "severity": "High",
        "cvss_score": 7.5,
        "likelihood": "High",
        "impact": "Medium",
        "recommended_fix": "Apply vendor security patch (v2.4.1) for the GTP tunneling module on core gateway routers.",
        "estimated_resolution_time": "20 Mins"
    },
    "isolation_failure": {
        "name": "Inter-slice side-channel data leakage",
        "category": "Isolation",
        "description": "Lack of proper physical or hardware isolation allows shared CPU cache leakage, letting virtual machines inmMTC read active cryptographic memory from URLLC.",
        "severity": "Critical",
        "cvss_score": 9.0,
        "likelihood": "Low",
        "impact": "Critical",
        "recommended_fix": "Configure hardware-assisted memory encryption and hypervisor cache pinning to partition slice workloads.",
        "estimated_resolution_time": "45 Mins"
    },
    "outdated_software": {
        "name": "Outdated Linux Kernel on RAN node",
        "category": "Software Version",
        "description": "Radio Access Network (RAN) node controllers are running Linux Kernel v5.4, which contains known remote code execution vulnerabilities.",
        "severity": "High",
        "cvss_score": 8.8,
        "likelihood": "Medium",
        "impact": "High",
        "recommended_fix": "Upgrade edge nodes to Kernel v6.1 LTS and apply standard security patches.",
        "estimated_resolution_time": "40 Mins"
    },
    "insecure_protocols": {
        "name": "Use of unencrypted HTTP/FTP for config updates",
        "category": "Configurations",
        "description": "Configuration provisioning requests are sent using cleartext HTTP and FTP protocol feeds, allowing credential sniffing on management links.",
        "severity": "Medium",
        "cvss_score": 5.9,
        "likelihood": "High",
        "impact": "Low",
        "recommended_fix": "Enforce HTTPS (TLS 1.3) and SFTP for all provisioning tasks on local configuration endpoints.",
        "estimated_resolution_time": "15 Mins"
    },
    "config_errors": {
        "name": "Permissive CORS policies on slice management interface",
        "category": "Configurations",
        "description": "CORS headers are set to '*' on administrative dashboards, allowing attackers to perform cross-site request attacks.",
        "severity": "Low",
        "cvss_score": 3.7,
        "likelihood": "Medium",
        "impact": "Low",
        "recommended_fix": "Restrict Access-Control-Allow-Origin headers to authorized management subdomains only.",
        "estimated_resolution_time": "10 Mins"
    }
}

SCAN_LOG_MESSAGES = [
    (5, "[INFO] Scan started. Spawning network security probes..."),
    (10, "[INFO] [CHECK] Authentication: Scanning slice credential mappings..."),
    (15, "[WARN] Authentication: Detected weak administrative passwords on dashboard endpoint."),
    (20, "[INFO] [CHECK] Encryption: Checking control/user-plane crypto configurations..."),
    (25, "[INFO] Encryption: Validating cipher suites on IPsec gateway..."),
    (30, "[INFO] [CHECK] APIs: Running security tests on REST API interfaces..."),
    (35, "[INFO] APIs: Querying HTTP routes. Discovered unsecured swagger definitions."),
    (40, "[INFO] [CHECK] Firewall: Verifying ACL configurations..."),
    (45, "[WARN] Firewall: Slice perimeter firewall status check completed."),
    (50, "[INFO] [CHECK] Isolation: Simulating side-channel cache attacks..."),
    (55, "[INFO] Isolation: Querying hardware separation controllers..."),
    (60, "[INFO] [CHECK] Ports: Performing port scan on physical slice gateways..."),
    (65, "[WARN] Ports: Discovered open management ports: 22, 8080."),
    (70, "[INFO] [CHECK] Software Version: Inspecting container images and libraries..."),
    (75, "[INFO] Software Version: Checking package registry logs for CVE alerts..."),
    (80, "[INFO] [CHECK] IAM: Auditing role-based privilege mappings..."),
    (85, "[INFO] IAM: Inspecting access credentials for slice orchestration engine..."),
    (90, "[INFO] [CHECK] Certificates: Validating TLS certificate chain lifetimes..."),
    (95, "[INFO] [CHECK] Configurations: Assessing system profile alignment with GSMA security guidelines..."),
    (100, "[INFO] Scan concluded. Compiled vulnerability report.")
]

def trigger_scan(slice_id, user_id=None):
    slice_obj = db_session.get(NetworkSlice, slice_id)
    if not slice_obj:
        return None
    
    # Mark slice status as scanning
    slice_obj.status = 'scanning'
    db_session.commit()
    
    # Create new assessment record
    assessment = Assessment(
        slice_id=slice_id,
        scanner_user_id=user_id,
        status='in_progress',
        started_at=datetime.utcnow()
    )
    db_session.add(assessment)
    db_session.commit()
    
    return assessment

def check_and_update_scan(assessment_id):
    assessment = db_session.get(Assessment, assessment_id)
    if not assessment:
        return None
    
    if assessment.status != 'in_progress':
        return assessment
        
    started = assessment.started_at
    elapsed = (datetime.utcnow() - started).total_seconds()
    
    # Scan takes 12 seconds to complete
    scan_duration = 12.0
    progress = min(100, int((elapsed / scan_duration) * 100))
    
    if progress >= 100:
        # Complete the scan!
        slice_obj = assessment.network_slice
        
        # Determine vulnerabilities based on slice configuration
        vulnerabilities_to_add = []
        
        # 1. Check Firewall
        if not slice_obj.firewall:
            vulnerabilities_to_add.append(VULN_TEMPLATES["firewall_disabled"])
        
        # 2. Check Encryption
        if slice_obj.encryption == 'None':
            vulnerabilities_to_add.append(VULN_TEMPLATES["no_encryption"])
        elif slice_obj.encryption == 'WEP' or slice_obj.encryption == 'DES':
            vulnerabilities_to_add.append(VULN_TEMPLATES["insecure_protocols"])
            
        # 3. Check Authentication
        if slice_obj.authentication == 'None':
            vulnerabilities_to_add.append(VULN_TEMPLATES["no_mfa"])
            vulnerabilities_to_add.append(VULN_TEMPLATES["weak_passwords"])
            
        # 4. Check Slice Types
        if slice_obj.slice_type == 'URLLC':
            # Critical vulnerability: Isolation Failure
            vulnerabilities_to_add.append(VULN_TEMPLATES["isolation_failure"])
        elif slice_obj.slice_type == 'eMBB':
            # High vulnerability: DDoS Risk / APIs
            vulnerabilities_to_add.append(VULN_TEMPLATES["ddos_risk"])
            vulnerabilities_to_add.append(VULN_TEMPLATES["misconfigured_apis"])
        elif slice_obj.slice_type == 'mMTC':
            # Outdated software
            vulnerabilities_to_add.append(VULN_TEMPLATES["outdated_software"])
            vulnerabilities_to_add.append(VULN_TEMPLATES["open_ports"])
            
        # 5. Add a random vulnerability for variety
        random_vulns = ["expired_certs", "privilege_escalation", "config_errors"]
        chosen_rand = random.choice(random_vulns)
        vulnerabilities_to_add.append(VULN_TEMPLATES[chosen_rand])
        
        # Deduplicate vulns by name
        unique_vulns = []
        seen_names = set()
        for v in vulnerabilities_to_add:
            if v["name"] not in seen_names:
                unique_vulns.append(v)
                seen_names.add(v["name"])
        
        # Save vulnerabilities to database
        threat_count = len(unique_vulns)
        score_penalty = 0
        
        for vuln in unique_vulns:
            db_vuln = Vulnerability(
                assessment_id=assessment.id,
                slice_id=slice_obj.id,
                name=vuln["name"],
                category=vuln["category"],
                description=vuln["description"],
                severity=vuln["severity"],
                cvss_score=vuln["cvss_score"],
                likelihood=vuln["likelihood"],
                impact=vuln["impact"],
                recommended_fix=vuln["recommended_fix"],
                estimated_resolution_time=vuln["estimated_resolution_time"],
                status='detected'
            )
            db_session.add(db_vuln)
            
            # Deduct points based on severity
            if vuln["severity"] == 'Critical':
                score_penalty += 25
            elif vuln["severity"] == 'High':
                score_penalty += 15
            elif vuln["severity"] == 'Medium':
                score_penalty += 8
            else: # Low
                score_penalty += 3
                
        # Calculate scores
        security_score = max(10, 100 - score_penalty)
        risk_percentage = 100 - security_score
        
        # Determine slice risk level
        if security_score >= 85:
            risk_level = 'Low'
        elif security_score >= 70:
            risk_level = 'Medium'
        elif security_score >= 50:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
            
        # Update assessment
        assessment.status = 'completed'
        assessment.security_score = security_score
        assessment.risk_percentage = risk_percentage
        assessment.threat_count = threat_count
        assessment.completed_at = datetime.utcnow()
        
        # Update slice status and health
        slice_obj.status = 'active'
        slice_obj.health_score = security_score
        slice_obj.risk_level = risk_level
        
        # Generate critical alert notification if threat count > 0
        if threat_count > 0:
            notif = Notification(
                type='Critical' if risk_level in ['High', 'Critical'] else 'Warning',
                title=f"Scan Completed: {threat_count} Threats on {slice_obj.name}",
                message=f"Vulnerability assessment for slice {slice_obj.name} completed with a security score of {security_score}%. Discovered {threat_count} vulnerabilities.",
                is_read=False
            )
            db_session.add(notif)
            
        db_session.commit()
        
    return assessment

def get_live_logs(started_at, current_time=None):
    if not current_time:
        current_time = datetime.utcnow()
    
    elapsed = (current_time - started_at).total_seconds()
    scan_duration = 12.0
    progress = min(100, int((elapsed / scan_duration) * 100))
    
    logs = []
    for pct, msg in SCAN_LOG_MESSAGES:
        if progress >= pct:
            # Add a slight variable offset to the log time for realism
            offset_seconds = (pct / 100.0) * scan_duration
            log_time = started_at + timedelta(seconds=offset_seconds)
            logs.append({
                "timestamp": log_time.strftime("%H:%M:%S.%f")[:-3],
                "message": msg,
                "percentage": pct
            })
    return logs
