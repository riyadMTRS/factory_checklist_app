from datetime import datetime, UTC
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    last_login = db.Column(db.DateTime)
    
    # Relationships
    checklists = db.relationship('Checklist', backref='owner', lazy='dynamic')
    tasks = db.relationship('Task', backref='assignee', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Checklist(db.Model):
    __tablename__ = 'checklists'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    department = db.Column(db.String(50))
    frequency = db.Column(db.String(20))  # daily, weekly, monthly
    priority = db.Column(db.String(20))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    tasks = db.relationship('Task', backref='checklist', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Checklist {self.title}>'

class Task(db.Model):
    __tablename__ = 'tasks'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(20))
    status = db.Column(db.String(20), default='pending')
    due_date = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    checklist_id = db.Column(db.Integer, db.ForeignKey('checklists.id'))
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'))
    
    # Relationships
    attachments = db.relationship('Attachment', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Task {self.title}>'

class Equipment(db.Model):
    __tablename__ = 'equipment'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50), unique=True)
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default='operational')
    maintenance_due = db.Column(db.DateTime)
    last_maintenance = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    # Relationships
    tasks = db.relationship('Task', backref='equipment', lazy='dynamic')
    maintenance_logs = db.relationship('MaintenanceLog', backref='equipment', lazy='dynamic')
    
    def __repr__(self):
        return f'<Equipment {self.name}>'

class MaintenanceLog(db.Model):
    __tablename__ = 'maintenance_logs'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'))
    performed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    maintenance_type = db.Column(db.String(50))
    description = db.Column(db.Text)
    date_performed = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    next_due_date = db.Column(db.DateTime)
    status = db.Column(db.String(20))
    
    def __repr__(self):
        return f'<MaintenanceLog {self.id}>'

class Attachment(db.Model):
    __tablename__ = 'attachments'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<Attachment {self.filename}>'

class Comment(db.Model):
    __tablename__ = 'comments'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<Comment {self.id}>'

# Removed duplicate Notification class definition to avoid SQLAlchemy registry conflict
# Notification model is defined in database.py 