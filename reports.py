import os
import csv
import io
from datetime import datetime
from database import db_session
from models import NetworkSlice, Assessment, Vulnerability, Report, User

def generate_csv_report(assessment_id):
    assessment = db_session.get(Assessment, assessment_id)
    if not assessment:
        return None
        
    slice_obj = assessment.network_slice
    vulnerabilities = assessment.vulnerabilities
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["SENTRASLICE 5G VULNERABILITY ASSESSMENT REPORT"])
    writer.writerow(["Generated At", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")])
    writer.writerow(["Slice Name", slice_obj.name])
    writer.writerow(["Slice Type", slice_obj.slice_type])
    writer.writerow(["Security Score", f"{assessment.security_score}%"])
    writer.writerow(["Risk Percentage", f"{assessment.risk_percentage}%"])
    writer.writerow(["Threat Count", assessment.threat_count])
    writer.writerow([])
    
    # Vulnerability Table
    writer.writerow(["Vulnerability Name", "Category", "Severity", "CVSS Score", "Likelihood", "Impact", "Recommended Fix", "Est. Resolution Time", "Status"])
    for v in vulnerabilities:
        writer.writerow([
            v.name,
            v.category,
            v.severity,
            v.cvss_score,
            v.likelihood,
            v.impact,
            v.recommended_fix,
            v.estimated_resolution_time,
            v.status
        ])
        
    return output.getvalue()

def generate_excel_report(assessment_id):
    # Excel-compatible CSV format
    # Using a semicolons/tabs separator with CSV content type format works natively in Microsoft Excel
    return generate_csv_report(assessment_id)

def create_report_record(assessment_id, file_format, user_id):
    assessment = db_session.get(Assessment, assessment_id)
    if not assessment:
        return None
        
    slice_obj = assessment.network_slice
    user = db_session.get(User, user_id)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_name = f"Sentraslice_Report_{slice_obj.name}_{timestamp}.{file_format.lower()}"
    
    # Ensure reports directory exists
    # On read-only filesystems (like Vercel), we must use /tmp
    base_dir = "static" if os.access('.', os.W_OK) else "/tmp"
    reports_dir = os.path.join(base_dir, "generated_reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    file_path = os.path.join(reports_dir, report_name)
    
    if file_format.upper() in ["CSV", "EXCEL"]:
        content = generate_csv_report(assessment_id)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        # PDF placeholder - the print HTML template will write to this or serve dynamically
        with open(file_path, "w") as f:
            f.write(f"HTML Print PDF wrapper for Assessment #{assessment_id}")
            
    report = Report(
        name=report_name,
        file_path=file_path,
        format=file_format.upper(),
        generated_by_user_id=user_id,
        risk_score=assessment.security_score,
        threat_count=assessment.threat_count,
        created_at=datetime.utcnow()
    )
    db_session.add(report)
    db_session.commit()
    
    return report
