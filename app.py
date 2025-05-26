from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from mail_reminder import *
from datetime import datetime, timedelta
import json
from otp_utils import generate_otp, store_otp, verify_otp, send_otp_email
import re


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    priority = db.Column(db.String(10), nullable=False, default="Medium")
    category = db.Column(db.String(50), default="General")
    deadline = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def home():
    # Get statistics for the home page
    total_users = User.query.count()
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(completed=True).count()
    
    # If user is logged in, redirect to dashboard
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    return render_template('home.html',
        total_users=total_users,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if 'verify_otp' in request.form:
            email = session.get('temp_email')
            otp = request.form.get('otp')
            
            if verify_otp(email, otp):
                # Get the temporary user data
                username = session.get('temp_username')
                password = session.get('temp_password')
                
                # Create the user
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, email=email, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                
                # Clear temporary session data
                session.pop('temp_email', None)
                session.pop('temp_username', None)
                session.pop('temp_password', None)
                
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid or expired OTP. Please try again.", "error")
                return render_template('verify_otp.html', email=email)
        
        # Initial registration form submission
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate password strength
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for('register'))
        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter.", "error")
            return redirect(url_for('register'))
        if not re.search(r"[a-z]", password):
            flash("Password must contain at least one lowercase letter.", "error")
            return redirect(url_for('register'))
        if not re.search(r"\d", password):
            flash("Password must contain at least one number.", "error")
            return redirect(url_for('register'))
        
        # Check if username or email exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "error")
            return redirect(url_for('register'))
        
        # Get admin email for sending OTP
        admin = User.query.filter_by(is_admin=True).first()
        sender_email = admin.email if admin else None
        
        # Generate and send OTP
        otp = generate_otp()
        if send_otp_email(email, otp, sender_email):
            store_otp(email, otp)
            # Store temporary user data in session
            session['temp_username'] = username
            session['temp_email'] = email
            session['temp_password'] = password
            return render_template('verify_otp.html', email=email)
        else:
            flash("Failed to send OTP. Please try again.", "error")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    email = session.get('temp_email')
    if not email:
        return jsonify({'error': 'No pending registration found'}), 400
    
    # Get admin email for sending OTP
    admin = User.query.filter_by(is_admin=True).first()
    sender_email = admin.email if admin else None
    
    otp = generate_otp()
    if send_otp_email(email, otp, sender_email):
        store_otp(email, otp)
        return jsonify({'message': 'OTP sent successfully'})
    return jsonify({'error': 'Failed to send OTP'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            session['user'] = user.username
            session['is_admin'] = user.is_admin  # Store admin status in session
            flash("Login successful!", "success")
            # Redirect admin users to admin dashboard
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash("Invalid username or password!", "error")
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    
    if not user:
        session.pop('user', None)  # Remove invalid session
        flash("Your session has expired. Please log in again.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        task_content = request.form.get('task')
        task_priority = request.form.get('priority', 'Medium')
        task_category = request.form.get('category', 'General')
        deadline_str = request.form.get('deadline')
        
        if task_content:
            new_task = Task(
                content=task_content,
                priority=task_priority,
                category=task_category,
                user_id=user.id
            )
            
            if deadline_str:
                try:
                    new_task.deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
                except ValueError:
                    flash("Invalid deadline format", "error")
            
            db.session.add(new_task)
            db.session.commit()
            flash("Task added successfully!", "success")

    # Get selected category filter
    selected_category = request.args.get('category', 'all')
    
    # Fetch tasks based on category filter
    query = Task.query.filter_by(user_id=user.id, completed=False)
    if selected_category != 'all':
        query = query.filter_by(category=selected_category)
    
    tasks = query.order_by(
        Task.deadline.asc(),  # Sort by deadline (if exists)
        Task.priority.desc()  # Then by priority
    ).all()

    # Get unique categories for the filter dropdown
    categories = db.session.query(Task.category).filter_by(user_id=user.id).distinct().all()
    categories = [cat[0] for cat in categories]

    total_tasks = Task.query.filter_by(user_id=user.id).count()
    completed_tasks = Task.query.filter_by(user_id=user.id, completed=True).count()

    # Check for tasks due soon
    now = datetime.utcnow()
    for task in tasks:
        if task.deadline and task.deadline <= now + timedelta(days=1):
            flash(f"Task '{task.content}' is due soon!", "warning")

    return render_template(
        'dashboard.html',
        user=user.username,
        tasks=tasks,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        now=now,
        timedelta=timedelta,
        categories=categories,
        selected_category=selected_category
    )


@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get(task_id)
    if task and task.user.username == session['user']:
        db.session.delete(task)
        db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/complete_task/<int:task_id>')
def complete_task(task_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get(task_id)
    if task and task.user.username == session['user']:
        task.completed = True
        task.completed_at = datetime.utcnow()
        db.session.commit()
        flash("Task completed successfully!", "success")
    
    return redirect(url_for('dashboard'))


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get(task_id)
    if task and task.user.username == session['user']:
        if request.method == 'POST':
            task.content = request.form.get('task_content')
            db.session.commit()
            return redirect(url_for('dashboard'))
        return render_template('edit_task.html', task=task)
    return redirect(url_for('dashboard'))

@app.route('/completed_tasks')
def completed_tasks():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    tasks = Task.query.filter_by(user_id=user.id, completed=True).all()

    return render_template('completed_tasks.html', user=user.username, tasks=tasks)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    
    if request.method == 'POST':
        # Handle profile updates
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        email = request.form.get('email')
        
        if current_password and new_password:
            if check_password_hash(user.password, current_password):
                if len(new_password) >= 8:
                    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    flash("Password updated successfully!", "success")
                else:
                    flash("New password must be at least 8 characters long.", "error")
            else:
                flash("Current password is incorrect.", "error")
        
        if email and email != user.email:
            if User.query.filter_by(email=email).first():
                flash("Email already registered!", "error")
            else:
                user.email = email
                flash("Email updated successfully!", "success")
        
        db.session.commit()
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

@app.route('/statistics')
def statistics():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    
    # Get task completion statistics
    total_tasks = Task.query.filter_by(user_id=user.id).count()
    completed_tasks = Task.query.filter_by(user_id=user.id, completed=True).count()
    completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
    
    # Get category distribution
    categories = db.session.query(
        Task.category,
        db.func.count(Task.id).label('count')
    ).filter_by(user_id=user.id).group_by(Task.category).all()
    
    # Convert categories to list of tuples
    categories_list = [(cat[0], cat[1]) for cat in categories]
    
    # Get priority distribution
    priorities = db.session.query(
        Task.priority,
        db.func.count(Task.id).label('count')
    ).filter_by(user_id=user.id).group_by(Task.priority).all()
    
    # Convert priorities to list of tuples
    priorities_list = [(pri[0], pri[1]) for pri in priorities]
    
    # Get completion trend (last 7 days)
    today = datetime.utcnow().date()
    completion_trend = []
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        completed_count = Task.query.filter(
            Task.user_id == user.id,
            Task.completed == True,
            db.func.date(Task.completed_at) == date
        ).count()
        completion_trend.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': completed_count
        })

    # New Analytics Features
    # 1. Productivity Score (based on completion rate and task complexity)
    productivity_score = 0
    if total_tasks > 0:
        # Weight factors
        completion_weight = 0.6
        priority_weight = 0.4
        
        # Calculate completion component
        completion_component = (completed_tasks / total_tasks) * 100
        
        # Calculate priority component (higher priority tasks completed = better score)
        high_priority_completed = Task.query.filter_by(
            user_id=user.id,
            completed=True,
            priority='High'
        ).count()
        high_priority_total = Task.query.filter_by(
            user_id=user.id,
            priority='High'
        ).count()
        
        priority_component = (high_priority_completed / high_priority_total * 100) if high_priority_total > 0 else 0
        
        # Calculate final score
        productivity_score = (completion_component * completion_weight) + (priority_component * priority_weight)
    
    # 2. Task Completion Time Analysis
    completed_tasks_with_time = Task.query.filter_by(
        user_id=user.id,
        completed=True
    ).all()
    
    avg_completion_time = 0
    if completed_tasks_with_time:
        total_time = sum(
            (task.completed_at - task.created_at).total_seconds() / 3600  # Convert to hours
            for task in completed_tasks_with_time
            if task.completed_at and task.created_at
        )
        avg_completion_time = total_time / len(completed_tasks_with_time)
    
    # 3. Category Performance Analysis
    category_performance = []
    for category, count in categories_list:
        category_tasks = Task.query.filter_by(
            user_id=user.id,
            category=category
        ).all()
        completed_in_category = sum(1 for task in category_tasks if task.completed)
        performance_rate = (completed_in_category / count * 100) if count > 0 else 0
        category_performance.append({
            'category': category,
            'total': count,
            'completed': completed_in_category,
            'performance_rate': performance_rate
        })
    
    # 4. Streak Analysis
    current_streak = 0
    max_streak = 0
    current_date = datetime.utcnow().date()
    
    while True:
        tasks_completed = Task.query.filter(
            Task.user_id == user.id,
            Task.completed == True,
            db.func.date(Task.completed_at) == current_date
        ).count()
        
        if tasks_completed > 0:
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            break
        
        current_date -= timedelta(days=1)
    
    return render_template('statistics.html',
        user=user,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        completion_rate=completion_rate,
        categories=categories_list,
        priorities=priorities_list,
        completion_trend=json.dumps(completion_trend),
        productivity_score=productivity_score,
        avg_completion_time=round(avg_completion_time, 2),
        category_performance=category_performance,
        current_streak=current_streak,
        max_streak=max_streak
    )

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    if not user or not user.is_admin:
        flash("Access denied. Admin privileges required.", "error")
        return redirect(url_for('dashboard'))

    # Get total statistics
    total_users = User.query.count()
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(completed=True).count()
    pending_tasks = total_tasks - completed_tasks

    # Get user statistics
    user_stats = []
    for u in User.query.all():
        user_tasks = Task.query.filter_by(user_id=u.id)
        total_user_tasks = user_tasks.count()
        completed_user_tasks = user_tasks.filter_by(completed=True).count()
        pending_user_tasks = total_user_tasks - completed_user_tasks
        
        user_stats.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'total_tasks': total_user_tasks,
            'completed_tasks': completed_user_tasks,
            'pending_tasks': pending_user_tasks
        })

    # Get activity data for the chart (last 7 days)
    today = datetime.utcnow().date()
    activity_labels = []
    activity_data = []
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        activity_labels.append(date.strftime('%Y-%m-%d'))
        count = Task.query.filter(
            db.func.date(Task.created_at) == date
        ).count()
        activity_data.append(count)

    # Get recent completed tasks from all users
    recent_completed_tasks = Task.query.filter_by(completed=True)\
        .order_by(Task.completed_at.desc())\
        .limit(10)\
        .all()

    return render_template('admin_dashboard.html',
        total_users=total_users,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        pending_tasks=pending_tasks,
        user_stats=user_stats,
        activity_labels=json.dumps(activity_labels),
        activity_data=json.dumps(activity_data),
        recent_completed_tasks=recent_completed_tasks
    )

@app.route('/admin/send_reminders', methods=['POST'])
def admin_send_reminders():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.filter_by(username=session['user']).first()
    if not user or not user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    users = User.query.all()
    for user in users:
        pending_tasks = Task.query.filter_by(
            user_id=user.id,
            completed=False
        ).all()
        
        if pending_tasks:
            send_reminder_email(
                user.email,
                f"You have {len(pending_tasks)} pending tasks",
                pending_tasks
            )

    return jsonify({'message': 'Reminders sent successfully'})

@app.route('/admin/send_reminder/<int:user_id>', methods=['POST'])
def admin_send_user_reminder(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    admin = User.query.filter_by(username=session['user']).first()
    if not admin or not admin.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    pending_tasks = Task.query.filter_by(
        user_id=user.id,
        completed=False
    ).all()
    
    if pending_tasks:
        send_reminder_email(
            user.email,
            f"You have {len(pending_tasks)} pending tasks",
            pending_tasks
        )
        return jsonify({'message': f'Reminder sent to {user.username}'})
    
    return jsonify({'message': f'No pending tasks for {user.username}'})

@app.route('/admin/user/<int:user_id>/tasks')
def admin_view_user_tasks(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    admin = User.query.filter_by(username=session['user']).first()
    if not admin or not admin.is_admin:
        flash("Access denied. Admin privileges required.", "error")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('admin_dashboard'))

    # Get all tasks with sorting and filtering
    tasks = Task.query.filter_by(user_id=user.id).order_by(
        Task.created_at.desc()
    ).all()

    # Calculate task statistics
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.completed])
    pending_tasks = total_tasks - completed_tasks

    # Get category distribution
    categories = db.session.query(
        Task.category,
        db.func.count(Task.id).label('count')
    ).filter_by(user_id=user.id).group_by(Task.category).all()
    categories_list = [(cat[0], cat[1]) for cat in categories]

    # Get priority distribution
    priorities = db.session.query(
        Task.priority,
        db.func.count(Task.id).label('count')
    ).filter_by(user_id=user.id).group_by(Task.priority).all()
    priorities_list = [(pri[0], pri[1]) for pri in priorities]

    # Get completion trend (last 7 days)
    today = datetime.utcnow().date()
    completion_trend = []
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        completed_count = Task.query.filter(
            Task.user_id == user.id,
            Task.completed == True,
            db.func.date(Task.completed_at) == date
        ).count()
        completion_trend.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': completed_count
        })

    return render_template('admin_user_tasks.html',
        user=user,
        tasks=tasks,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        pending_tasks=pending_tasks,
        categories=categories_list,
        priorities=priorities_list,
        completion_trend=json.dumps(completion_trend)
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)