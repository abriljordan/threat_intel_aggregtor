from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
from . import db, login_manager

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        # Use sha256 method instead of scrypt to avoid LibreSSL compatibility issues
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Report(db.Model):
    """Model for storing threat intelligence reports."""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(45), nullable=False, index=True)  # IP or domain
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    results = db.Column(db.Text, nullable=False)  # JSON string
    abuse_score = db.Column(db.Integer, default=0, index=True)
    is_malicious = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # PostgreSQL-specific: Add JSONB column for better JSON performance
    results_jsonb = db.Column(db.JSON, nullable=True)  # PostgreSQL JSONB equivalent
    
    def set_results(self, results_dict):
        """Store results as JSON string and JSONB."""
        self.results = json.dumps(results_dict, indent=2)
        self.results_jsonb = results_dict  # Store as native JSON for PostgreSQL
        
        # Calculate abuse score and malicious status
        self.abuse_score = 0
        self.is_malicious = False
        
        for api_name, api_result in results_dict.items():
            if isinstance(api_result, dict):
                data = api_result.get('data', api_result)
                if 'abuseConfidenceScore' in data:
                    score = data['abuseConfidenceScore']
                    self.abuse_score = max(self.abuse_score, score)
                    if score > 80:
                        self.is_malicious = True
                
                # Check VirusTotal stats
                if 'last_analysis_stats' in data:
                    stats = data['last_analysis_stats']
                    if stats.get('malicious', 0) > 0:
                        self.is_malicious = True
    
    def get_results(self):
        """Get results as dictionary."""
        # Try JSONB first (PostgreSQL), fallback to JSON string
        if self.results_jsonb:
            return self.results_jsonb
        try:
            return json.loads(self.results)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'results': self.get_results(),
            'abuse_score': self.abuse_score,
            'is_malicious': self.is_malicious,
            'created_at': self.created_at.isoformat()
        }

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id)) 