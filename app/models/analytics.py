import datetime
from app.models.models import db, Site

class SiteAnalytics(db.Model):
    """Model to store site analytics data by date"""
    __tablename__ = 'site_analytics'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    requests = db.Column(db.Integer, default=0)
    bandwidth_bytes = db.Column(db.BigInteger, default=0)
    cache_hits = db.Column(db.Integer, default=0)
    response_time_ms = db.Column(db.Float, default=0)
    
    # Define the relationship with the site model
    site = db.relationship('Site', backref=db.backref('analytics_data', lazy=True, cascade='all, delete-orphan'))
    
    # Add index for better performance
    __table_args__ = (
        db.Index('idx_site_date', site_id, date),
    )
    
    def __repr__(self):
        return f'<SiteAnalytics site_id={self.site_id} date={self.date}>'
        
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'site_id': self.site_id,
            'date': self.date.isoformat() if self.date else None,
            'requests': self.requests,
            'bandwidth_bytes': self.bandwidth_bytes,
            'bandwidth_mb': round(self.bandwidth_bytes / (1024 * 1024), 2) if self.bandwidth_bytes else 0,
            'cache_hits': self.cache_hits,
            'response_time_ms': self.response_time_ms,
            'cache_hit_ratio': round(self.cache_hits / self.requests * 100, 2) if self.requests > 0 else 0
        }


class RequestLog(db.Model):
    """Model to store individual request logs for analytics purposes"""
    __tablename__ = 'request_log'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id', ondelete='CASCADE'), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    response_time_ms = db.Column(db.Float, nullable=False)
    bytes_sent = db.Column(db.Integer, nullable=False)
    is_cache_hit = db.Column(db.Boolean, default=False)
    country_code = db.Column(db.String(2))
    request_method = db.Column(db.String(10), default='GET')
    user_agent = db.Column(db.String(255))
    referer = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    site = db.relationship('Site', backref=db.backref('request_logs', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<RequestLog site_id={self.site_id} path={self.path} status={self.status_code}>'


class ErrorLog(db.Model):
    """Model to store error logs for analytics purposes"""
    __tablename__ = 'error_log'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id', ondelete='CASCADE'), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    site = db.relationship('Site', backref=db.backref('error_logs', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<ErrorLog site_id={self.site_id} status={self.status_code}>'