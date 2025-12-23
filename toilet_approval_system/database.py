from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """用户模型"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'A' 或 'B'
    is_active = db.Column(db.Boolean, default=True)  # 添加 is_active 字段
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Flask-Login 需要的属性
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True  # 或者根据用户状态返回
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)
    
    # 关系
    submitted_requests = db.relationship('ToiletRequest', foreign_keys='ToiletRequest.applicant_id', backref='applicant', lazy=True)
    requests_to_approve = db.relationship('ToiletRequest', foreign_keys='ToiletRequest.approver_id', backref='approver', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class ToiletRequest(db.Model):
    """上厕所申请模型"""
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(500))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, cancelled
    apply_time = db.Column(db.DateTime, default=datetime.utcnow)
    approve_time = db.Column(db.DateTime)
    notes = db.Column(db.String(500))
    
    def __repr__(self):
        return f'<ToiletRequest {self.id} - {self.status}>'
    
    def get_status_text(self):
        status_map = {
            'pending': '待审批',
            'approved': '已批准',
            'rejected': '已拒绝',
            'cancelled': '已取消'
        }
        return status_map.get(self.status, self.status)
    
    def get_applicant(self):
        return User.query.get(self.applicant_id)
    
    def get_approver(self):
        return User.query.get(self.approver_id)