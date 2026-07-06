import os
import sys
import unittest
from datetime import datetime, timedelta
import json

# Setup environment
os.environ['DATABASE_URL'] = 'sqlite:///:memory:' # Use in-memory SQLite for testing

from database import db_session, init_db
import models
import auth
import scanner
import reports

class TestSentraslicePlatform(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Initialize tables
        init_db()
        auth.seed_users()
        
    def setUp(self):
        # Pre-seed a test slice
        self.slice_name = "TEST_SLICE_eMBB"
        self.slice = models.NetworkSlice(
            name=self.slice_name,
            slice_type="eMBB",
            status="active",
            latency=10,
            bandwidth=5.0,
            encryption="AES-256",
            authentication="5G-AKA",
            firewall=True,
            health_score=100,
            risk_level="Low"
        )
        db_session.add(self.slice)
        db_session.commit()
        
    def tearDown(self):
        db_session.query(models.Vulnerability).delete()
        db_session.query(models.Assessment).delete()
        db_session.query(models.NetworkSlice).delete()
        db_session.commit()
        
    def test_database_seeding(self):
        # Check users were created
        admin = db_session.query(models.User).filter_by(username='admin').first()
        self.assertIsNotNone(admin)
        self.assertEqual(admin.email, 'admin@sentraslice.io')
        
        # Check roles exist
        admin_role = db_session.query(models.Role).filter_by(name='Admin').first()
        self.assertIsNotNone(admin_role)
        permissions = json.loads(admin_role.permissions)
        self.assertIn('all', permissions)
        
    def test_auth_hashing(self):
        passwd = "TestPassword@123!"
        hashed = auth.hash_password(passwd)
        self.assertTrue(auth.verify_password(passwd, hashed))
        self.assertFalse(auth.verify_password("wrongpassword", hashed))
        
    def test_slice_operations(self):
        # Read
        s = db_session.query(models.NetworkSlice).filter_by(name=self.slice_name).first()
        self.assertIsNotNone(s)
        self.assertEqual(s.latency, 10)
        
        # Update
        s.latency = 15
        db_session.commit()
        s_updated = db_session.query(models.NetworkSlice).filter_by(name=self.slice_name).first()
        self.assertEqual(s_updated.latency, 15)
        
    def test_scanner_simulation(self):
        # Trigger scan
        assessment = scanner.trigger_scan(self.slice.id, user_id=1)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.status, 'in_progress')
        
        # Check slice is marked as scanning
        s = db_session.get(models.NetworkSlice, self.slice.id)
        self.assertEqual(s.status, 'scanning')
        
        # Check logs are generated
        logs = scanner.get_live_logs(assessment.started_at, assessment.started_at + timedelta(seconds=2))
        self.assertGreater(len(logs), 0)
        
        # Fast-forward time to simulate completed scan
        assessment.started_at = datetime.utcnow() - timedelta(seconds=15)
        db_session.commit()
        
        # Check and update (completes the scan)
        scanner.check_and_update_scan(assessment.id)
        
        updated_assessment = db_session.get(models.Assessment, assessment.id)
        self.assertEqual(updated_assessment.status, 'completed')
        self.assertGreater(updated_assessment.threat_count, 0)
        
        # Verify vulnerabilities were registered
        vulns = db_session.query(models.Vulnerability).filter_by(assessment_id=assessment.id).all()
        self.assertGreater(len(vulns), 0)
        
        # Verify security score was calculated
        self.assertLess(updated_assessment.security_score, 100)
        self.assertGreater(updated_assessment.security_score, 0)
        
    def test_reports_compilation(self):
        assessment = scanner.trigger_scan(self.slice.id, user_id=1)
        assessment.started_at = datetime.utcnow() - timedelta(seconds=15)
        db_session.commit()
        scanner.check_and_update_scan(assessment.id)
        
        # Generate CSV contents
        csv_content = reports.generate_csv_report(assessment.id)
        self.assertIn("SENTRASLICE 5G VULNERABILITY ASSESSMENT REPORT", csv_content)
        self.assertIn(self.slice_name, csv_content)
        
        # Generate Report Record
        record = reports.create_report_record(assessment.id, "CSV", user_id=1)
        self.assertIsNotNone(record)
        self.assertTrue(os.path.exists(record.file_path))
        
        # Clean up generated report file
        if os.path.exists(record.file_path):
            os.remove(record.file_path)

if __name__ == '__main__':
    print("Running Sentraslice core test suite...")
    unittest.main()
