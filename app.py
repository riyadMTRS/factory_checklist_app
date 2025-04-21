from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_from_directory, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta, UTC
from database import (
    init_db, 
    add_checklist, 
    add_task, 
    update_task_status, 
    get_checklist_tasks,
    create_user, 
    verify_user, 
    get_user_role,
    get_user_permissions,
    get_all_users,
    update_user,
    delete_user,
    get_user_notifications,
    add_notification,
    db,
    User,
    Notification
)
from models import User, Task, Checklist
import os
import socket
import csv
from io import StringIO
from werkzeug.utils import secure_filename
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, case

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, instance_relative_config=True)

# Set secret key for session management
app.config['SECRET_KEY'] = os.urandom(24)

# Load configuration based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app.config.from_object('config.ProductionConfig')
else:
    app.config.from_object('config.DevelopmentConfig')

# Ensure instance folder exists with proper permissions
instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(instance_path, exist_ok=True)

# Set database configuration with absolute path
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "factory_checklist.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure SQLAlchemy for thread safety
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {
        'check_same_thread': False,
        'timeout': 30
    }
}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database
init_db(app)
with app.app_context():
    db.create_all()
    # Create default admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            role='admin',
            email='admin@factory.com',
            is_active=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        logger.info("Default admin user created")

# Network configuration
HOST_IP = '0.0.0.0'
PORT = 5000

# Configure upload folder with absolute path
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create required directories with proper permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Context processors
@app.context_processor
def utility_processor():
    return {
        'current_year': datetime.now(UTC).year,
        'now': datetime.now(UTC),
        'current_user': current_user if current_user else None
    }

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f'404 error: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'500 error: {str(error)}')
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def too_large(error):
    app.logger.warning(f'413 error: File too large')
    return render_template('errors/413.html'), 413

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.now(UTC)
            db.session.commit()
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for {username} from {request.remote_addr}")
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Protected route decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    try:
        checklists = Checklist.query.order_by(Checklist.created_at.desc()).all()
        return render_template('index.html', checklists=checklists)
    except Exception as e:
        logger.error(f'Error loading checklists: {str(e)}')
        flash(f'Error loading checklists: {str(e)}', 'error')
        return render_template('index.html', checklists=[])
        flash(f'Error loading checklists: {str(e)}', 'error')
        return render_template('index.html', checklists=[])

@app.route('/create_checklist', methods=['POST'])
def create_checklist():
    try:
        title = request.form.get('title', 'Checklist ' + datetime.now().strftime('%Y-%m-%d'))
        department = request.form.get('department', 'General')
        notes = request.form.get('notes', '')
        
        checklist = Checklist(
            title=title,
            description=notes,
            department=department
        )
        db.session.add(checklist)
        db.session.commit()
        flash('Checklist created successfully!', 'success')
        return redirect(url_for('view_checklist', checklist_id=checklist.id))
    except Exception as e:
        flash(f'Error creating checklist: {str(e)}', 'error')
    return redirect(url_for('index'))

@app.route('/checklist/<int:checklist_id>')
@login_required
def view_checklist(checklist_id):
    try:
        checklist = Checklist.query.get_or_404(checklist_id)
        tasks = checklist.tasks.all()
        if not tasks:
            flash('No tasks found for this checklist', 'warning')
            return redirect(url_for('index'))
            
        # Group tasks by status
        pending_tasks = [t for t in tasks if t.status == 'pending']
        in_progress_tasks = [t for t in tasks if t.status == 'in_progress']
        completed_tasks = [t for t in tasks if t.status == 'completed']
        
        return render_template('checklist.html', 
                             checklist_id=checklist_id,
                             pending_tasks=pending_tasks,
                             in_progress_tasks=in_progress_tasks,
                             completed_tasks=completed_tasks)
    except Exception as e:
        flash(f'Error loading checklist: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/add_task', methods=['POST'])
def add_task_route():
    try:
        checklist_id = request.form.get('checklist_id')
        description = request.form.get('description')
        priority = request.form.get('priority', 'medium')
        
        if not description:
            flash('Task description is required', 'error')
            return redirect(url_for('view_checklist', checklist_id=checklist_id))
            
        task = Task(
            title='Task',  # Placeholder title since title is required in the model
            description=description,
            priority=priority,
            checklist_id=checklist_id
        )
        db.session.add(task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('view_checklist', checklist_id=checklist_id))
    except Exception as e:
        flash(f'Error adding task: {str(e)}', 'error')
        return redirect(url_for('view_checklist', checklist_id=checklist_id))

@app.route('/update_task_status', methods=['POST'])
def update_task_status_route():
    try:
        task_id = request.form.get('task_id')
        status = request.form.get('status')
        checklist_id = request.form.get('checklist_id')
        worker_name = request.form.get('worker_name')
        
        if not all([task_id, status, checklist_id]):
            flash('Missing required information', 'error')
    return redirect(url_for('view_checklist', checklist_id=checklist_id))
            
        task = Task.query.get_or_404(task_id)
        task.status = status
        if worker_name:
            task.worker_name = worker_name
        if status == 'completed':
            task.completed_at = datetime.now(UTC)
        db.session.commit()
        
        # Add notification message
        if status == 'completed':
            flash(f'Task completed by {worker_name}!', 'success')
        elif status == 'in_progress':
            flash(f'Task started by {worker_name}', 'info')
        else:
            flash('Task status updated!', 'success')
            
        return redirect(url_for('view_checklist', checklist_id=checklist_id))
    except Exception as e:
        flash(f'Error updating task status: {str(e)}', 'error')
        return redirect(url_for('view_checklist', checklist_id=checklist_id))

@app.route('/supervisor')
def supervisor_dashboard():
    try:
        # Get today's date
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Get all checklists for today with task statistics
        checklists = db.session.query(
            Checklist,
            func.count(Task.id).label('total_tasks'),
            func.sum(case((Task.status == 'completed', 1), else_=0)).label('completed_tasks')
        ).outerjoin(Task).filter(
            Checklist.date == today
        ).group_by(Checklist.id).order_by(Checklist.shift).all()
        
        # Get task statistics by category
        category_stats = db.session.query(
            Task.process_category,
            func.count().label('total'),
            func.sum(case((Task.status == 'completed', 1), else_=0)).label('completed'),
            func.sum(case((Task.status == 'in_progress', 1), else_=0)).label('in_progress')
        ).join(Checklist).filter(
            Checklist.date == today
        ).group_by(Task.process_category).all()
        
        # Get worker performance
        worker_stats = db.session.query(
            Task.worker_name,
            func.count().label('total_tasks'),
            func.sum(case((Task.status == 'completed', 1), else_=0)).label('completed_tasks')
        ).join(Checklist).filter(
            Checklist.date == today,
            Task.worker_name.isnot(None)
        ).group_by(Task.worker_name).all()
        
        return render_template('supervisor.html',
                             checklists=checklists,
                             category_stats=category_stats,
                             worker_stats=worker_stats,
                             today=today)
    except Exception as e:
        logger.error(f'Error loading supervisor dashboard: {str(e)}')
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/generate_report')
def generate_report():
    try:
        # Get date range (last 7 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        # Get all checklists and tasks for the period
        data = db.session.query(
            Checklist.date,
            Checklist.shift,
            Task.process_category,
            Task.description,
            Task.status,
            Task.worker_name,
            Task.completed_at,
            Task.responsible_role
        ).join(Task).filter(
            Checklist.date.between(
                start_date.strftime('%Y-%m-%d'),
                end_date.strftime('%Y-%m-%d')
            )
        ).order_by(
            Checklist.date.desc(),
            Checklist.shift,
            Task.process_category
        ).all()
        
        # Create CSV response
        output = []
        output.append(['Date', 'Shift', 'Category', 'Task', 'Status', 'Worker', 'Completed At', 'Responsible Role'])
        
        for row in data:
            output.append([
                row.date,
                row.shift,
                row.process_category,
                row.description,
                row.status,
                row.worker_name or 'N/A',
                row.completed_at or 'N/A',
                row.responsible_role or 'N/A'
            ])
        
        # Generate CSV
        si = StringIO()
        cw = csv.writer(si)
        cw.writerows(output)
        output = si.getvalue()
        
        # Create response
        response = make_response(output)
        response.headers["Content-Disposition"] = f"attachment; filename=task_report_{end_date.strftime('%Y-%m-%d')}.csv"
        response.headers["Content-type"] = "text/csv"
        
        return response
    except Exception as e:
        logger.error(f'Error generating report: {str(e)}')
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('supervisor_dashboard'))

@app.route('/worker/<worker_name>')
def worker_dashboard(worker_name):
    try:
        # Get today's date
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Get worker's tasks using SQLAlchemy
        tasks = db.session.query(
            Task, Checklist
        ).join(Checklist).filter(
            Task.worker_name == worker_name,
            Checklist.date == today
        ).order_by(
            Task.priority.desc(),
            Task.created_at
        ).all()
        
        return render_template('worker.html',
                             worker_name=worker_name,
                             tasks=tasks,
                             today=today)
    except Exception as e:
        logger.error(f'Error loading worker dashboard: {str(e)}')
        flash(f'Error loading worker dashboard: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/update_task', methods=['POST'])
def update_task():
    try:
        task_id = request.form.get('task_id')
        status = request.form.get('status')
        worker_name = request.form.get('worker_name')
        completion_notes = request.form.get('completion_notes')
        
        # Get the task using SQLAlchemy
        task = Task.query.get_or_404(task_id)
        
        # Handle photo upload
        photo_path = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{task_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo_path = filename
        
        # Update task using SQLAlchemy
        task.status = status
        task.worker_name = worker_name
        task.completion_notes = completion_notes
        if photo_path:
            task.photo_path = photo_path
        if status == 'completed':
            task.completed_at = datetime.now(UTC)
        
        db.session.commit()
        
        if status == 'completed':
            flash('Task marked as completed!', 'success')
        else:
            flash('Task status updated!', 'info')
            
        return redirect(url_for('worker_dashboard', worker_name=worker_name))
    except Exception as e:
        logger.error(f'Error updating task: {str(e)}')
        flash(f'Error updating task: {str(e)}', 'error')
        return redirect(url_for('worker_dashboard', worker_name=worker_name))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def print_network_info():
    """Print network information for the application."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("=" * 50)
    print("Factory Checklist App - Network Information")
    print("=" * 50)
    print("Local Access:")
    print("http://localhost:5000")
    print("http://127.0.0.1:5000")
    print("Network Access:")
    print(f"http://{local_ip}:5000")
    print("Other Network Information:")
    for iface in socket.getaddrinfo(hostname, None):
        if iface[0] == socket.AF_INET6:  # IPv6
            print(f"IPv6 Address: {iface[4][0]}")
    print("Port: 5000")
    print("Instructions:")
    print("1. Make sure your firewall allows connections on port 5000")
    print("2. Team members can access using the Network Access URL")
    print("3. Press Ctrl+C to stop the server")
    print("=" * 50)

# Add permission check decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please login to access this page', 'warning')
                return redirect(url_for('login'))
            
            user_permissions = get_user_permissions(session['username'])
            if permission not in user_permissions:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users')
@permission_required('manage_users')
def manage_users():
    users = get_all_users()
    return render_template('admin/users.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@permission_required('manage_users')
def admin_create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_name = request.form['role']
        full_name = request.form['full_name']
        email = request.form.get('email')
        
        success, message = create_user(username, password, role_name, full_name, email)
        flash(message, 'success' if success else 'danger')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/create_user.html')

@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
@permission_required('manage_users')
def edit_user(username):
    if request.method == 'POST':
        new_password = request.form.get('password')
        new_role = request.form.get('role')
        new_email = request.form.get('email')
        is_active = request.form.get('is_active') == '1'
        
        success, message = update_user(username, new_password, new_role, new_email, is_active)
        flash(message, 'success' if success else 'danger')
        return redirect(url_for('manage_users'))
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/delete_user/<username>', methods=['POST'])
@permission_required('manage_users')
def delete_user(username):
    success, message = delete_user(username)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('manage_users'))

@app.route('/admin/roles')
@permission_required('manage_roles')
def manage_roles():
    roles = UserRole.query.all() # type: ignore
    return render_template('admin/roles.html', roles=roles)

@app.route('/notifications')
@login_required
def notifications():
    user_id = session.get('user_id')
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    if mark_notification_read(notification_id):
        flash('Notification marked as read', 'success')
    else:
        flash('Error marking notification as read', 'danger')
    return redirect(url_for('notifications'))

@app.route('/assign_task', methods=['POST'])
@login_required
def assign_task():
    task_id = request.form.get('task_id')
    user_id = request.form.get('user_id')
    
    task = Task.query.get(task_id)
    
    if task:
        message = f"New task assigned: {task.description}"
        notification = Notification(
            user_id=user_id,
            task_id=task_id,
            message=message
        )
        db.session.add(notification)
        db.session.commit()
        flash('Task assigned successfully', 'success')
    else:
        flash('Error assigning task', 'danger')
    
    return redirect(url_for('index'))

@app.route('/update_task_status', methods=['POST'])
@login_required
def update_task_status():
    task_id = request.form.get('task_id')
    status = request.form.get('status')
    worker_name = request.form.get('worker_name')
    
    task = Task.query.get(task_id)
    
    if task:
        if status == 'completed':
            message = f"Task completed: {task.description} by {worker_name}"
            # Notify supervisor
            notification = Notification(
                user_id=task.checklist.created_by,
                task_id=task_id,
                message=message
            )
            db.session.add(notification)
        elif status == 'pending':
            message = f"Task marked as pending: {task.description}"
            # Notify assigned worker
            if task.assigned_user:
                notification = Notification(
                    user_id=task.assigned_user.id,
                    task_id=task_id,
                    message=message
                )
                db.session.add(notification)
        
        task.status = status
        db.session.commit()
        flash('Task status updated successfully', 'success')
    else:
        flash('Error updating task status', 'danger')
    
    return redirect(url_for('index'))

@app.route('/bulk_update_tasks', methods=['POST'])
@login_required
def bulk_update_tasks():
    try:
        task_ids = request.form.getlist('task_ids[]')
        action = request.form.get('action')
        notes = request.form.get('notes')
        
        if not task_ids:
            return jsonify({'success': False, 'message': 'No tasks selected'})
        
        tasks = Task.query.filter(Task.id.in_(task_ids)).all()
        for task in tasks:
            task.status = action
            if notes:
                task.completion_notes = notes
            if action == 'completed':
                task.completed_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Tasks updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/filter_tasks', methods=['GET'])
@login_required
def filter_tasks():
    try:
        status = request.args.get('status')
        priority = request.args.get('priority')
        category = request.args.get('category')
        search = request.args.get('search')
        
        query = Task.query
        
        if status:
            query = query.filter_by(status=status)
        
        if priority:
            query = query.filter_by(priority=priority)
        
        if category:
            query = query.filter_by(process_category=category)
        
        if search:
            query = query.filter(
                db.or_(
                    Task.description.ilike(f'%{search}%'),
                    Task.notes.ilike(f'%{search}%')
                )
            )
        
        tasks = query.order_by(Task.priority.desc(), Task.created_at).all()
        return jsonify({'success': True, 'tasks': [task.to_dict() for task in tasks]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/checklists')
@login_required
def api_checklists():
    try:
        checklists = Checklist.query.all()
        checklist_data = [
            {
                'id': c.id,
                'name': c.title,
                'description': c.description or '',
                'status': c.status if hasattr(c, 'status') else 'active',
                'created_at': c.created_at.strftime('%Y-%m-%d') if c.created_at else '',
                'updated_at': c.updated_at.strftime('%Y-%m-%d %H:%M:%S') if c.updated_at else c.created_at.strftime('%Y-%m-%d') if c.created_at else ''
            }
            for c in checklists
        ]
        return jsonify(checklist_data)
    except Exception as e:
        logger.error(f'Error fetching checklists: {str(e)}')
        return jsonify({'error': 'Failed to fetch checklists'}), 500

if __name__ == "__main__":
    print_network_info()
    app.run(debug=True, host=HOST_IP, port=PORT)