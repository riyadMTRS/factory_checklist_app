import os
import logging
from datetime import datetime, UTC
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import scoped_session, sessionmaker
from typing import List, Dict, Any, Optional
from flask import current_app
import hashlib
import sqlite3

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add file handler for logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logger.addHandler(
    logging.FileHandler('logs/database.log')
)

# Database initialization
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120))
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Equipment(db.Model):
    __tablename__ = 'equipment'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100), unique=True)
    location = db.Column(db.String(100))
    maintenance_interval = db.Column(db.Integer)  # in days
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    incidents = db.relationship('Incident', backref='equipment', lazy=True)

class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'))
    location = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(20), default='open')

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def init_db(app):
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'factory_checklist.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize database
    db.init_app(app)

    # Create tables
    with app.app_context():
        db.create_all()

        # Import models here to avoid circular imports
        from models import User

        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()

def get_db():
    if 'db' not in current_app:
        init_db(current_app)
    return db

def verify_user(username, password_hash):
    """Verify user credentials."""
    try:
        from models import User  # Import here to avoid circular imports
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password_hash):
            user.last_login = datetime.now(UTC)
            db.session.commit()
            return user
        return None
    except Exception as e:
        logger.error(f"Error verifying user: {str(e)}")
        db.session.rollback()
        return None

def get_user_role(username):
    """Get user role."""
    try:
        from models import User  # Import here to avoid circular imports
        user = User.query.filter_by(username=username).first()
        return user.role if user else None
    except Exception as e:
        logger.error(f"Error getting user role: {str(e)}")
        return None

def create_user(username, password_hash, role, email=None):
    try:
        conn = get_db()
    cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, email)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def add_multiple_tasks(checklist_id: int, tasks: List[Dict[str, Any]]) -> bool:
    """Add multiple tasks with transaction support and error handling."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Start transaction
            cursor.execute('BEGIN TRANSACTION')
            
            try:
                for task in tasks:
                    # Validate required fields
                    if not task.get('description'):
                        raise ValueError("Task description is required")
                        
                    # Insert task with all fields
                    cursor.execute('''
                        INSERT INTO tasks (
                            checklist_id, title, description, priority, assigned_to, equipment_id, estimated_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        checklist_id,
                        task['title'],
                        task['description'],
                        task.get('priority', 'medium'),
                        task.get('assigned_to'),
                        task.get('equipment_id'),
                        task.get('estimated_time')
                    ))
                
                # Commit transaction
                conn.commit()
                logger.info(f"Successfully added {len(tasks)} tasks to checklist {checklist_id}")
                return True
                
            except Exception as e:
                # Rollback transaction on error
                conn.rollback()
                logger.error(f"Error adding tasks: {str(e)}")
                return False
                
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        return False

def log_task_change(task_id: int, user_id: int, field_changed: str, 
                   old_value: Any, new_value: Any) -> None:
    """Log changes to tasks for audit trail."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO task_history 
                (task_id, changed_by, field_name, old_value, new_value)
                VALUES (?, ?, ?, ?, ?)
            ''', (task_id, user_id, field_changed, str(old_value), str(new_value)))
            conn.commit()
    except Exception as e:
        logger.error(f"Error logging task change: {str(e)}")

def add_checklist(title: str, description: str, department: str, shift: str, priority: str = 'medium', 
                  created_by: Optional[int] = None, assigned_to: Optional[int] = None, due_date: Optional[str] = None) -> int:
    """Add a new checklist to the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO checklists (title, description, department, shift, priority, assigned_to, due_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (title, description, department, shift, priority, assigned_to, due_date))
            checklist_id = cursor.lastrowid
            conn.commit()
            logger.info(f"Checklist {title} added successfully with ID: {checklist_id}")
            return checklist_id
    except Exception as e:
        logger.error(f"Error adding checklist: {str(e)}")
        return -1

def add_task(checklist_id: int, title: str, description: str, priority: str = 'medium', 
             assigned_to: Optional[int] = None, equipment_id: Optional[int] = None, estimated_time: Optional[int] = None) -> int:
    """Add a new task to the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tasks (checklist_id, title, description, priority, assigned_to, equipment_id, estimated_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (checklist_id, title, description, priority, assigned_to, equipment_id, estimated_time))
            task_id = cursor.lastrowid
            conn.commit()
            logger.info(f"Task {title} added successfully with ID: {task_id}")
            return task_id
    except Exception as e:
        logger.error(f"Error adding task: {str(e)}")
        return -1

def update_task_status(task_id: int, status: str, user_id: int) -> bool:
    """Update the status of a task in the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT status FROM tasks WHERE id = ?', (task_id,))
            old_status = cursor.fetchone()[0]
            
            cursor.execute('''
                UPDATE tasks 
                SET status = ?, updated_at = ?
                WHERE id = ?
            ''', (status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), task_id))
    
    cursor.execute('''
                INSERT INTO task_history (task_id, changed_by, field_name, old_value, new_value)
                VALUES (?, ?, 'status_change', ?, ?)
            ''', (task_id, user_id, old_status, status))
    
    conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error updating task status: {str(e)}")
        return False

def get_checklist_tasks(checklist_id: int) -> List[Dict[str, Any]]:
    """Get all tasks for a specific checklist."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.*, u.username as assigned_to_username, e.name as equipment_name
                FROM tasks t
                LEFT JOIN users u ON t.assigned_to = u.id
                LEFT JOIN equipment e ON t.equipment_id = e.id
                WHERE t.checklist_id = ?
                ORDER BY 
                    CASE t.priority
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                    END,
                    t.created_at
            ''', (checklist_id,))
            return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error getting checklist tasks: {str(e)}")
        return []

def add_equipment(name: str, model: str, serial_number: str, location: str, maintenance_interval: Optional[int] = None) -> bool:
    """Add a new piece of equipment to the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO equipment (name, model, serial_number, location, maintenance_interval)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, model, serial_number, location, maintenance_interval))
            conn.commit()
            logger.info(f"Equipment {name} added successfully")
            return True
    except Exception as e:
        logger.error(f"Error adding equipment: {str(e)}")
        return False

def report_incident(title: str, description: str, severity: str, reported_by: int, equipment_id: Optional[int] = None, location: Optional[str] = None) -> bool:
    """Report a new incident to the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO incidents (title, description, severity, reported_by, equipment_id, location)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (title, description, severity, reported_by, equipment_id, location))
            conn.commit()
            logger.info(f"Incident {title} reported successfully")
            return True
    except Exception as e:
        logger.error(f"Error reporting incident: {str(e)}")
        return False

def add_notification(user_id: int, title: str, message: str, type: str = 'info') -> bool:
    """Add a new notification to the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (?, ?, ?, ?)
            ''', (user_id, title, message, type))
            conn.commit()
            logger.info(f"Notification {title} added successfully")
            return True
    except Exception as e:
        logger.error(f"Error adding notification: {str(e)}")
        return False

def get_user_notifications(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """Get all notifications for a specific user."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM notifications 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
            return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error getting user notifications: {str(e)}")
        return []

def mark_notification_read(notification_id: int) -> bool:
    """Mark a notification as read in the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE notifications 
                SET is_read = 1 
                WHERE id = ?
            ''', (notification_id,))
            conn.commit()
            logger.info(f"Notification ID {notification_id} marked as read")
            return True
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        return False

def get_settings() -> Dict[str, Any]:
    """Get all settings from the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM settings')
            return dict(cursor.fetchall())
    except Exception as e:
        logger.error(f"Error getting settings: {str(e)}")
        return {}

def update_setting(key: str, value: Any) -> bool:
    """Update a setting in the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            ''', (key, value, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            logger.info(f"Setting {key} updated successfully")
            return True
    except Exception as e:
        logger.error(f"Error updating setting: {str(e)}")
        return False

def get_user_permissions(username: str) -> List[str]:
    """Get permissions for a user based on their role."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            
            if not result:
                return []
                
            role = result[0]
            # For now, return basic permissions based on role
            if role == 'admin':
                return ['manage_users', 'manage_roles', 'manage_checklists', 'manage_tasks']
            elif role == 'supervisor':
                return ['manage_checklists', 'manage_tasks']
            else:
                return ['view_tasks']
    except Exception as e:
        logger.error(f"Error getting user permissions: {str(e)}")
        return []

def get_all_users() -> List[Dict[str, Any]]:
    """Get all users from the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, role, department, shift, email, 
                       phone, last_login, created_at, is_active 
                FROM users
                ORDER BY username
            ''')
            users = cursor.fetchall()
            
            return [{
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'department': user[3],
                'shift': user[4],
                'email': user[5],
                'phone': user[6],
                'last_login': user[7],
                'created_at': user[8],
                'is_active': user[9]
            } for user in users]
    except Exception as e:
        logger.error(f"Error getting all users: {str(e)}")
        return []

def update_user(username: str, new_password: Optional[str] = None, 
                new_role: Optional[str] = None, new_email: Optional[str] = None, 
                is_active: Optional[bool] = None) -> tuple[bool, str]:
    """Update user information."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            updates = []
            params = []
            
            if new_password:
                salt = os.urandom(32).hex()
                password_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()
                updates.extend(['password_hash = ?', 'salt = ?'])
                params.extend([password_hash, salt])
                
            if new_role:
                updates.append('role = ?')
                params.append(new_role)
                
            if new_email:
                updates.append('email = ?')
                params.append(new_email)
                
            if is_active is not None:
                updates.append('is_active = ?')
                params.append(1 if is_active else 0)
                
            if not updates:
                return True, "No changes requested"
                
            query = f'''
                UPDATE users 
                SET {', '.join(updates)},
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
            '''
            params.append(username)
            
            cursor.execute(query, params)
            conn.commit()
            
            return True, "User updated successfully"
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return False, f"Error updating user: {str(e)}"

def delete_user(username: str) -> tuple[bool, str]:
    """Delete a user from the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if not cursor.fetchone():
                return False, "User not found"
                
            # Delete user
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            
            return True, "User deleted successfully"
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return False, f"Error deleting user: {str(e)}"

if __name__ == '__main__':
    init_db()