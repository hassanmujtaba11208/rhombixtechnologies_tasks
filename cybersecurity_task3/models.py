from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_name = db.Column(db.String(255), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    language = db.Column(db.String(50), nullable=False)

    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)

    security_score = db.Column(db.Integer, default=100)
    risk_level = db.Column(db.String(50), default="Unknown")

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    vulnerabilities = db.relationship(
        "Vulnerability", backref="scan", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "scan_name": self.scan_name,
            "file_name": self.file_name,
            "language": self.language,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)

    vuln_name = db.Column(db.String(255), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)

    cwe_id = db.Column(db.String(50), nullable=True)
    cwe_name = db.Column(db.String(255), nullable=True)
    owasp_category = db.Column(db.String(100), nullable=True)

    severity = db.Column(db.String(20), nullable=False, index=True)
    cvss_score = db.Column(db.Float, default=0.0)

    file_name = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    code_snippet = db.Column(db.Text, nullable=False)

    description = db.Column(db.Text, nullable=False)
    risk_explanation = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=False)

    confidence = db.Column(db.String(20), default="High")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "vuln_name": self.vuln_name,
            "vuln_type": self.vuln_type,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "file_name": self.file_name,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "risk_explanation": self.risk_explanation,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
    return db