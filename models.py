from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import json
from database import Base

class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    permissions = Column(Text, default="[]") # JSON string list of permissions
    
    users = relationship("User", back_populates="role")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "permissions": json.loads(self.permissions) if self.permissions else []
        }

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.name if self.role else None,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }

class NetworkSlice(Base):
    __tablename__ = 'network_slices'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    slice_type = Column(String(50), nullable=False) # eMBB, URLLC, mMTC
    status = Column(String(50), default='active') # active, paused, scanning
    latency = Column(Integer, default=10) # ms
    bandwidth = Column(Float, default=1.0) # Gbps
    encryption = Column(String(100), default='AES-256')
    authentication = Column(String(100), default='5G-AKA')
    firewall = Column(Boolean, default=True)
    health_score = Column(Integer, default=100)
    risk_level = Column(String(50), default='Low') # Low, Medium, High, Critical
    created_at = Column(DateTime, default=datetime.utcnow)
    
    assessments = relationship("Assessment", back_populates="network_slice", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="network_slice", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "slice_type": self.slice_type,
            "status": self.status,
            "latency": self.latency,
            "bandwidth": self.bandwidth,
            "encryption": self.encryption,
            "authentication": self.authentication,
            "firewall": self.firewall,
            "health_score": self.health_score,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class Assessment(Base):
    __tablename__ = 'assessments'
    
    id = Column(Integer, primary_key=True)
    slice_id = Column(Integer, ForeignKey('network_slices.id'), nullable=False)
    scanner_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    risk_percentage = Column(Float, default=0.0)
    security_score = Column(Integer, default=100)
    threat_count = Column(Integer, default=0)
    status = Column(String(50), default='completed') # completed, failed, in_progress
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    network_slice = relationship("NetworkSlice", back_populates="assessments")
    vulnerabilities = relationship("Vulnerability", back_populates="assessment", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "slice_id": self.slice_id,
            "slice_name": self.network_slice.name if self.network_slice else None,
            "risk_percentage": self.risk_percentage,
            "security_score": self.security_score,
            "threat_count": self.threat_count,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False)
    slice_id = Column(Integer, ForeignKey('network_slices.id'), nullable=True)
    name = Column(String(100), nullable=False)
    category = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False) # Low, Medium, High, Critical
    cvss_score = Column(Float, default=0.0)
    likelihood = Column(String(50), nullable=False) # Low, Medium, High
    impact = Column(String(50), nullable=False) # Low, Medium, High, Critical
    recommended_fix = Column(Text, nullable=False)
    estimated_resolution_time = Column(String(50), default='5 mins')
    status = Column(String(50), default='detected') # detected, mitigated
    detected_at = Column(DateTime, default=datetime.utcnow)
    
    assessment = relationship("Assessment", back_populates="vulnerabilities")
    network_slice = relationship("NetworkSlice", back_populates="vulnerabilities")

    def to_dict(self):
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "slice_id": self.slice_id,
            "slice_name": self.network_slice.name if self.network_slice else None,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "recommended_fix": self.recommended_fix,
            "estimated_resolution_time": self.estimated_resolution_time,
            "status": self.status,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None
        }

class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    file_path = Column(String(200), nullable=False)
    format = Column(String(50), nullable=False) # PDF, Excel, CSV
    generated_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Integer, default=100)
    threat_count = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "file_path": self.file_path,
            "format": self.format,
            "generated_by": self.generated_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "risk_score": self.risk_score,
            "threat_count": self.threat_count
        }

class Notification(Base):
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    type = Column(String(50), nullable=False) # Critical, Warning, Info
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "message": self.message,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(200), nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String(50), nullable=False) # success, failed
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="audit_logs")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "action": self.action,
            "details": self.details,
            "status": self.status,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class Setting(Base):
    __tablename__ = 'settings'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value
        }
