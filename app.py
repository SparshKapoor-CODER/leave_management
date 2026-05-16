# [file name]: app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime, timedelta, time
import secrets
from models import Student, Proctor, HostelSupervisor, AdminModel
from database import Database
import os
from dotenv import load_dotenv
import functools
import traceback
from pdf_generator import PDFGenerator, ReportData
import base64

load_dotenv('.env')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

print("\n" + "="*60)
print("VIT LEAVE MANAGEMENT SYSTEM - STARTING...")
print("="*60)

# Initialize database - handle connection failures gracefully
db = None
db_connected = False

try:
    print("Attempting to connect to PostgreSQL database...")
    db = Database()
    db_connected = db.init_db()
    
    if db_connected:
        print("✓ Database initialized successfully!")
        
        # Check if we need to add minimal admin user
        try:
            connection = db.get_connection()
            try:
                with connection.cursor() as cursor:
                    # Check if any admin exists
                    cursor.execute("SELECT COUNT(*) as count FROM admins")
                    result = cursor.fetchone()
                    admin_count = result[0] if result else 0
                    
                    if admin_count == 0:
                        print("⚠ No admin found. Adding minimal admin user...")
                        from models import UserModel
                        admin_password = UserModel.hash_password("Admin@123")
                        cursor.execute("""
                            INSERT INTO admins (admin_id, name, password_hash, email, role)
                            VALUES (%s, %s, %s, %s, %s)
                        """, ("ADMIN001", "System Administrator", admin_password, "admin@vit.ac.in", "super_admin"))
                        connection.commit()
                        print("✓ Default admin created: ADMIN001 / Admin@123")
                    else:
                        print(f"✓ Found {admin_count} existing admin(s)")
                        
            except Exception as e:
                print(f"⚠ Error checking/creating admin: {e}")
            finally:
                if connection:
                    connection.close()
        except Exception as e:
            print(f"⚠ Warning: Could not verify admin: {e}")
    else:
        print("⚠ Database tables may already exist, continuing...")
        db_connected = True
        
except Exception as e:
    print(f"\n✗ DATABASE CONNECTION FAILED!")
    print(f"Error: {e}")
    print(f"\nThe application will start but database features won't work.")
    print(f"Please check your environment variables:")
    print(f"  - DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME")
    traceback.print_exc()
    print("="*60 + "\n")
    db_connected = False

def login_required(role):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if role not in session:
                if role == 'student_id':
                    return redirect(url_for('student_login'))
                elif role == 'proctor_id':
                    return redirect(url_for('proctor_login'))
                elif role == 'supervisor_id':
                    return redirect(url_for('hostel_login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ── IP BLOCKING ──────────────────────────────────────────────────────────────

def get_client_ip():
    """Get real client IP, respecting X-Forwarded-For proxy header."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def is_ip_blocked(ip_address):
    """Return True if the given IP is actively blocked."""
    try:
        if not db_connected:
            return False
        db = Database()
        connection = db.get_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT block_id FROM blocked_ips WHERE ip_address = %s AND is_active = TRUE",
                (ip_address,)
            )
            result = cursor.fetchone()
            return result is not None
    except Exception:
        return False
    finally:
        if connection:
            connection.close()

@app.before_request
def block_banned_ips():
    """Reject every request coming from a blocked IP before it hits any route."""
    # Always allow admin login so the admin isn't locked out themselves
    if request.endpoint in ('admin_login', 'static'):
        return None

    ip = get_client_ip()
    if is_ip_blocked(ip):
        return render_template('blocked.html', ip=ip), 403

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        reg_number = request.form['reg_number'].strip().upper()
        password = request.form['password']
        
        print(f"Student login attempt: {reg_number}")
        
        try:
            student = Student.login(reg_number, password)
            if student:
                session['student_id'] = student['reg_number']
                session['student_name'] = student['name']
                flash(f'Welcome back, {student["name"]}!', 'success')
                return redirect(url_for('student_dashboard'))
            
            flash('Invalid registration number or password', 'error')
            return render_template('student_login.html', error='Invalid credentials')
        except Exception as e:
            print(f"Error during student login: {e}")
            traceback.print_exc()
            flash(f'Login error: {str(e)}', 'error')
            return render_template('student_login.html', error='Login error')
    
    return render_template('student_login.html')

@app.route('/student/dashboard')
@login_required('student_id')
def student_dashboard():
    try:
        leaves = Student.get_leave_history(session['student_id'])
        return render_template('student_dashboard.html', 
                             leaves=leaves, 
                             student_name=session['student_name'],
                             today=datetime.now().strftime('%Y-%m-%d'))
    except Exception as e:
        print(f"Error in student_dashboard: {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return redirect(url_for('student_login'))

@app.route('/student/apply', methods=['GET', 'POST'])
@login_required('student_id')
def apply_leave():
    if request.method == 'POST':
        try:
            leave_data = {
                'leave_type': request.form['leave_type'],
                'from_date': request.form['from_date'],
                'to_date': request.form['to_date'],
                'from_time': request.form['from_time'],
                'to_time': request.form['to_time'],
                'reason': request.form['reason'],
                'destination': request.form.get('destination', ''),
                'parent_contacted': 'parent_contacted' in request.form
            }
            
            from_date = datetime.strptime(leave_data['from_date'], '%Y-%m-%d')
            to_date = datetime.strptime(leave_data['to_date'], '%Y-%m-%d')
            
            if from_date > to_date:
                flash('Invalid date range!', 'error')
                return render_template('apply_leave.html', 
                                     today=datetime.now().strftime('%Y-%m-%d'))
            
            leave_id = Student.apply_leave(session['student_id'], leave_data)
            if leave_id:
                flash('Leave application submitted successfully!', 'success')
            else:
                flash('Failed to apply for leave', 'error')
                
        except Exception as e:
            print(f"Error applying leave: {e}")
            traceback.print_exc()
            flash(f'Error: {str(e)}', 'error')
            
    return render_template('apply_leave.html', 
                         today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/proctor/login', methods=['GET', 'POST'])
def proctor_login():
    if request.method == 'POST':
        employee_id = request.form['employee_id'].strip()
        password = request.form['password']
        
        try:
            proctor = Proctor.login(employee_id, password)
            if proctor:
                session['proctor_id'] = proctor['employee_id']
                session['proctor_name'] = proctor['name']
                flash(f'Welcome, Dr. {proctor["name"]}!', 'success')
                return redirect(url_for('proctor_dashboard'))
            
            flash('Invalid employee ID or password', 'error')
            return render_template('proctor_login.html', error='Invalid credentials')
        except Exception as e:
            print(f"Error during proctor login: {e}")
            traceback.print_exc()
            flash(f'Login error: {str(e)}', 'error')
            return render_template('proctor_login.html', error='Login error')
    
    return render_template('proctor_login.html')

@app.route('/proctor/dashboard')
@login_required('proctor_id')
def proctor_dashboard():
    try:
        pending_leaves = Proctor.get_pending_leaves(session['proctor_id'])
        return render_template('proctor_dashboard.html', 
                             leaves=pending_leaves, 
                             proctor_name=session['proctor_name'])
    except Exception as e:
        print(f"Error in proctor_dashboard: {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return redirect(url_for('proctor_login'))

@app.route('/proctor/approve/<int:leave_id>')
@login_required('proctor_id')
def approve_leave(leave_id):
    try:
        qr_token = Proctor.approve_leave(leave_id, session['proctor_id'])
        if qr_token:
            flash('Leave approved successfully! QR code generated.', 'success')
        else:
            flash('Error approving leave', 'error')
    except Exception as e:
        print(f"Error approving leave: {e}")
        traceback.print_exc()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('proctor_dashboard'))

@app.route('/proctor/reject/<int:leave_id>')
@login_required('proctor_id')
def reject_leave(leave_id):
    try:
        success = Proctor.reject_leave(leave_id, session['proctor_id'])
        if success:
            flash('Leave rejected successfully.', 'info')
        else:
            flash('Error rejecting leave', 'error')
    except Exception as e:
        print(f"Error rejecting leave: {e}")
        traceback.print_exc()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('proctor_dashboard'))

@app.route('/hostel/login', methods=['GET', 'POST'])
def hostel_login():
    if request.method == 'POST':
        supervisor_id = request.form['supervisor_id'].strip()
        password = request.form['password']
        
        try:
            supervisor = HostelSupervisor.login(supervisor_id, password)
            if supervisor:
                # Log attempted login with IP
                ip_address = request.remote_addr
                print(f"Hostel login attempt: {supervisor_id} from IP: {ip_address}")
                
                # Additional security: Log successful login
                try:
                    db_temp = Database()
                    connection = db_temp.get_connection()
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO admin_logs 
                            (admin_id, action_type, target_type, target_id, details, ip_address, user_agent)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (
                            supervisor_id,
                            'LOGIN',
                            'SUPERVISOR',
                            supervisor_id,
                            f'Hostel supervisor login from IP: {ip_address}',
                            ip_address,
                            request.headers.get('User-Agent', '')
                        ))
                        connection.commit()
                except Exception as e:
                    print(f"Error logging supervisor login: {e}")
                finally:
                    if connection:
                        connection.close()
                
                session['supervisor_id'] = supervisor['supervisor_id']
                session['supervisor_name'] = supervisor['name']
                session['hostel_block'] = supervisor['hostel_block']
                flash(f'Welcome, {supervisor["name"]}! You are assigned to Block {supervisor["hostel_block"]}', 'success')
                return redirect(url_for('hostel_verify'))
            
            flash('Invalid supervisor ID or password', 'error')
            return render_template('hostel_login.html', error='Invalid credentials')
        except Exception as e:
            print(f"Error during hostel login: {e}")
            traceback.print_exc()
            flash(f'Login error: {str(e)}', 'error')
            return render_template('hostel_login.html', error='Login error')
    
    return render_template('hostel_login.html')

@app.route('/hostel/verify', methods=['GET', 'POST'])
@login_required('supervisor_id')
def hostel_verify():
    error = None
    success = None
    slip = None
    
    if 'slip_data' in session:
        slip = session.pop('slip_data', None)
        success = "Verification successful!"
    
    if request.method == 'POST':
        qr_token = request.form.get('qr_token', '').strip().upper()
        
        if not qr_token:
            error = 'Please enter QR code'
            flash(error, 'error')
            return render_template('hostel_verify.html',
                                 supervisor_name=session.get('supervisor_name', ''),
                                 hostel_block=session.get('hostel_block', ''),
                                 error=error)
        
        print(f"Verifying QR token: {qr_token}")
        
        try:
            # Get supervisor's block from session
            supervisor_block = session.get('hostel_block', '')
            
            leave, message = HostelSupervisor.verify_qr_token(
                qr_token, 
                session['supervisor_id'],
                supervisor_block
            )
            
            if leave:
                # Additional verification: Check if student's block matches supervisor's block
                student_block = leave.get('hostel_block', '')
                
                if student_block.upper() != supervisor_block.upper():
                    error = f"Access denied! You can only verify students from Block {supervisor_block}. This student is from Block {student_block}."
                    flash(error, 'error')
                    return render_template('hostel_verify.html',
                                         supervisor_name=session.get('supervisor_name', ''),
                                         hostel_block=session.get('hostel_block', ''),
                                         error=error)
                
                def format_time(time_obj):
                    if isinstance(time_obj, time):
                        return time_obj.strftime('%H:%M')
                    elif isinstance(time_obj, timedelta):
                        total_seconds = int(time_obj.total_seconds())
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        return f"{hours:02d}:{minutes:02d}"
                    elif isinstance(time_obj, str):
                        if ':' in time_obj:
                            return time_obj.split('.')[0]
                        return time_obj
                    else:
                        return "00:00"
                
                def format_date(date_obj):
                    if hasattr(date_obj, 'strftime'):
                        return date_obj.strftime('%Y-%m-%d')
                    elif isinstance(date_obj, str):
                        return date_obj
                    else:
                        return str(date_obj)
                
                from_date = format_date(leave['from_date'])
                to_date = format_date(leave['to_date'])
                from_time = format_time(leave['from_time'])
                to_time = format_time(leave['to_time'])
                
                slip_data = {
                    'student_name': leave.get('student_name', 'Unknown'),
                    'reg_number': leave.get('student_reg', 'Unknown'),
                    'hostel_block': leave.get('hostel_block', 'Unknown'),
                    'room_number': leave.get('room_number', 'Unknown'),
                    'from_date': from_date,
                    'to_date': to_date,
                    'from_time': from_time,
                    'to_time': to_time,
                    'proctor_name': leave.get('proctor_name', 'Unknown'),
                    'verified_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'supervisor_name': session.get('supervisor_name', 'Supervisor'),
                    'destination': leave.get('destination', 'Not specified')
                }
                
                session['slip_data'] = slip_data
                session.modified = True
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json':
                    return jsonify({
                        'success': True,
                        'message': message,
                        'slip': slip_data,
                        'redirect': url_for('hostel_verify')
                    })
                
                success = message
                slip = slip_data
                flash(success, 'success')
            else:
                error = message
                flash(error, 'error')
                
        except Exception as e:
            error = f"Server error: {str(e)}"
            print(f"Error in hostel_verify: {e}")
            traceback.print_exc()
            flash(error, 'error')
    
    return render_template('hostel_verify.html',
                         supervisor_name=session.get('supervisor_name', ''),
                         hostel_block=session.get('hostel_block', ''),
                         slip=slip,
                         error=error,
                         success=success)

@app.route('/hostel/verify/clear')
@login_required('supervisor_id')
def clear_verification():
    if 'slip_data' in session:
        session.pop('slip_data', None)
    return redirect(url_for('hostel_verify'))

@app.route('/api/generate_qr/<int:leave_id>')
@login_required('student_id')
def generate_qr(leave_id):
    try:
        leaves = Student.get_leave_history(session['student_id'])
        target_leave = None
        for leave in leaves:
            if leave['leave_id'] == leave_id and leave['status'] == 'approved':
                target_leave = leave
                break
        
        if not target_leave or not target_leave['qr_token']:
            return jsonify({'error': 'No valid QR code available'}), 404
        
        qr_image = HostelSupervisor.generate_qr_code(target_leave['qr_token'])
        
        return jsonify({
            'qr_image': qr_image,
            'leave_id': leave_id,
            'valid_until': target_leave['qr_expiry'].strftime('%Y-%m-%d %H:%M:%S') if target_leave['qr_expiry'] else None
        })
    except Exception as e:
        print(f"Error generating QR code: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_id = request.form['admin_id'].strip().upper()
        password = request.form['password']
        
        try:
            admin = AdminModel.login(admin_id, password)
            if admin:
                session['admin_id'] = admin['admin_id']
                session['admin_name'] = admin['name']
                session['admin_role'] = admin['role']
                
                # Log admin login
                AdminModel.log_action(
                    admin_id=admin['admin_id'],
                    action_type='LOGIN',
                    target_type='SYSTEM',
                    target_id=None,
                    details='Admin logged into system',
                    request=request
                )
                
                flash(f'Welcome, {admin["name"]}!', 'success')
                return redirect(url_for('admin_dashboard'))
            
            flash('Invalid admin ID or password', 'error')
            return render_template('admin_login.html', error='Invalid credentials')
        except Exception as e:
            print(f"Error during admin login: {e}")
            traceback.print_exc()
            flash(f'Login error: {str(e)}', 'error')
            return render_template('admin_login.html', error='Login error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        stats = AdminModel.get_system_stats()
        recent_logs = AdminModel.get_all_logs(limit=20)
        suspicious_leaves = AdminModel.get_all_leaves({'suspicious_only': True})
        
        return render_template('admin_dashboard.html',
                             stats=stats,
                             recent_logs=recent_logs,
                             suspicious_leaves=suspicious_leaves,
                             admin_name=session['admin_name'],
                             admin_role=session['admin_role'])
    except Exception as e:
        print(f"Error in admin_dashboard: {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return redirect(url_for('admin_login'))

@app.route('/admin/leaves')
@admin_required
def admin_leaves():
    try:
        filters = {
            'status': request.args.get('status'),
            'leave_type': request.args.get('leave_type'),
            'date_from': request.args.get('date_from'),
            'date_to': request.args.get('date_to'),
            'suspicious_only': request.args.get('suspicious_only') == 'true',
            'cross_block': request.args.get('cross_block') == 'true'
        }
        
        leaves = AdminModel.get_all_leaves(filters)
        
        # Check for cross-block verifications
        if filters.get('cross_block'):
            suspicious_leaves = []
            for leave in leaves:
                if leave.get('student_block') != leave.get('supervisor_block'):
                    leave['cross_block_warning'] = True
                    suspicious_leaves.append(leave)
            leaves = suspicious_leaves
        
        return render_template('admin_leaves.html',
                             leaves=leaves,
                             filters=filters,
                             admin_name=session['admin_name'])
    except Exception as e:
        print(f"Error in admin_leaves: {e}")
        traceback.print_exc()
        flash('Error loading leaves', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    try:
        logs = AdminModel.get_all_logs(limit=200)
        return render_template('admin_logs.html',
                             logs=logs,
                             admin_name=session['admin_name'])
    except Exception as e:
        print(f"Error in admin_logs: {e}")
        traceback.print_exc()
        flash('Error loading logs', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        users = AdminModel.get_all_users()
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT employee_id, name FROM proctors ORDER BY name")
                proctors = cursor.fetchall()
        finally:
            if connection:
                connection.close()
        
        return render_template('admin_users.html',
                             users=users,
                             proctors=proctors,
                             admin_name=session['admin_name'])
    except Exception as e:
        print(f"Error in admin_users: {e}")
        traceback.print_exc()
        flash('Error loading users', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/add-user', methods=['POST'])
@admin_required
def admin_add_user():
    user_type = request.form['user_type']
    
    print(f"\n{'='*50}")
    print(f"ADD USER REQUEST - Type: {user_type}")
    print(f"Form data: {dict(request.form)}")
    print(f"{'='*50}\n")
    
    try:
        if user_type == 'proctor':
            proctor_data = {
                'employee_id': request.form['employee_id'].strip(),
                'name': request.form['name'].strip(),
                'password': request.form['password'],
                'email': request.form['email'].strip(),
                'department': request.form['department'].strip()
            }
            
            if not all([proctor_data['employee_id'], proctor_data['name'], proctor_data['password']]):
                flash('Please fill all required fields for proctor', 'error')
                return redirect(url_for('admin_users'))
            
            success = AdminModel.add_proctor(proctor_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='ADD_USER',
                    target_type='PROCTOR',
                    target_id=proctor_data['employee_id'],
                    details=f'Added proctor: {proctor_data["name"]} ({proctor_data["employee_id"]})',
                    request=request
                )
                flash(f'Proctor {proctor_data["employee_id"]} added successfully!', 'success')
            else:
                flash(f'Failed to add proctor {proctor_data["employee_id"]}', 'error')
            
        elif user_type == 'student':
            student_data = {
                'reg_number': request.form['reg_number'].strip().upper(),
                'name': request.form['name'].strip(),
                'password': request.form['password'],
                'proctor_id': request.form['proctor_id'].strip(),
                'hostel_block': request.form['hostel_block'].strip(),
                'room_number': request.form['room_number'].strip(),
                'phone': request.form['phone'].strip(),
                'parent_phone': request.form['parent_phone'].strip()
            }
            
            required_fields = ['reg_number', 'name', 'password', 'proctor_id', 'hostel_block', 'room_number']
            missing_fields = [field for field in required_fields if not student_data.get(field)]
            
            if missing_fields:
                flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
                return redirect(url_for('admin_users'))
            
            success = AdminModel.add_student(student_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='ADD_USER',
                    target_type='STUDENT',
                    target_id=student_data['reg_number'],
                    details=f'Added student: {student_data["name"]} ({student_data["reg_number"]})',
                    request=request
                )
                flash(f'Student {student_data["reg_number"]} added successfully!', 'success')
            else:
                flash(f'Failed to add student {student_data["reg_number"]}', 'error')
            
        elif user_type == 'supervisor':
            supervisor_data = {
                'supervisor_id': request.form['supervisor_id'].strip(),
                'name': request.form['name'].strip(),
                'password': request.form['password'],
                'hostel_block': request.form['hostel_block'].strip(),
                'email': request.form['email'].strip()
            }
            
            if not all([supervisor_data['supervisor_id'], supervisor_data['name'], 
                       supervisor_data['password'], supervisor_data['hostel_block']]):
                flash('Please fill all required fields for supervisor', 'error')
                return redirect(url_for('admin_users'))
            
            success = AdminModel.add_supervisor(supervisor_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='ADD_USER',
                    target_type='SUPERVISOR',
                    target_id=supervisor_data['supervisor_id'],
                    details=f'Added supervisor: {supervisor_data["name"]} ({supervisor_data["supervisor_id"]})',
                    request=request
                )
                flash(f'Supervisor {supervisor_data["supervisor_id"]} added successfully!', 'success')
            else:
                flash(f'Failed to add supervisor {supervisor_data["supervisor_id"]}', 'error')
        
        else:
            flash('Invalid user type', 'error')
            return redirect(url_for('admin_users'))
        
    except Exception as e:
        flash(f'Error adding user: {str(e)}', 'error')
        print(f"Error in admin_add_user: {e}")
        traceback.print_exc()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/edit-user', methods=['POST'])
@admin_required
def admin_edit_user():
    user_type = request.form.get('user_type')
    
    try:
        if user_type == 'proctor':
            update_data = {
                'name': request.form['name'],
                'email': request.form['email'],
                'department': request.form['department']
            }
            if 'password' in request.form and request.form['password']:
                update_data['password'] = request.form['password']
            
            success = AdminModel.update_proctor(request.form['employee_id'], update_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='EDIT_USER',
                    target_type='PROCTOR',
                    target_id=request.form['employee_id'],
                    details=f'Updated proctor details',
                    request=request
                )
                flash('Proctor updated successfully!', 'success')
            else:
                flash('Failed to update proctor', 'error')
            
        elif user_type == 'student':
            update_data = {
                'name': request.form['name'],
                'proctor_id': request.form['proctor_id'],
                'hostel_block': request.form['hostel_block'],
                'room_number': request.form['room_number'],
                'phone': request.form['phone'],
                'parent_phone': request.form['parent_phone']
            }
            if 'password' in request.form and request.form['password']:
                update_data['password'] = request.form['password']
            
            success = AdminModel.update_student(request.form['reg_number'], update_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='EDIT_USER',
                    target_type='STUDENT',
                    target_id=request.form['reg_number'],
                    details=f'Updated student details',
                    request=request
                )
                flash('Student updated successfully!', 'success')
            else:
                flash('Failed to update student', 'error')
            
        elif user_type == 'supervisor':
            update_data = {
                'name': request.form['name'],
                'hostel_block': request.form['hostel_block'],
                'email': request.form['email']
            }
            if 'password' in request.form and request.form['password']:
                update_data['password'] = request.form['password']
            
            success = AdminModel.update_supervisor(request.form['supervisor_id'], update_data)
            if success:
                AdminModel.log_action(
                    admin_id=session['admin_id'],
                    action_type='EDIT_USER',
                    target_type='SUPERVISOR',
                    target_id=request.form['supervisor_id'],
                    details=f'Updated supervisor details',
                    request=request
                )
                flash('Supervisor updated successfully!', 'success')
            else:
                flash('Failed to update supervisor', 'error')
        
        else:
            flash('Invalid user type', 'error')
            return redirect(url_for('admin_users'))
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        print(f"Error in admin_edit_user: {e}")
        traceback.print_exc()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/get-user/<user_type>/<user_id>')
@admin_required
def admin_get_user(user_type, user_id):
    try:
        user = AdminModel.get_user(user_type, user_id)
        if user:
            return jsonify({
                'success': True,
                'user': user,
                'user_type': user_type
            })
        else:
            return jsonify({'success': False, 'message': 'User not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reset-password', methods=['POST'])
@admin_required
def admin_reset_password():
    user_type = request.form['user_type']
    user_id = request.form['user_id']
    new_password = request.form['new_password']
    
    try:
        success = AdminModel.reset_password(user_type, user_id, new_password)
        if success:
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='RESET_PASSWORD',
                target_type=user_type.upper(),
                target_id=user_id,
                details='Password reset by admin',
                request=request
            )
            flash(f'Password reset successfully for {user_id}', 'success')
        else:
            flash('Failed to reset password', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/flag-suspicious/<int:leave_id>', methods=['POST'])
@admin_required
def admin_flag_suspicious(leave_id):
    reason = request.form['reason']
    
    try:
        success = AdminModel.flag_suspicious(leave_id, session['admin_id'], reason)
        if success:
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='FLAG_LEAVE',
                target_type='LEAVE',
                target_id=leave_id,
                details=f'Flagged as suspicious: {reason}',
                request=request
            )
            flash('Leave flagged as suspicious', 'success')
        else:
            flash('Failed to flag leave', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('admin_leaves'))

@app.route('/admin/remove-flag/<int:leave_id>')
@admin_required
def admin_remove_flag(leave_id):
    try:
        success = AdminModel.remove_flag(leave_id)
        if success:
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='REMOVE_FLAG',
                target_type='LEAVE',
                target_id=leave_id,
                details='Removed suspicious flag',
                request=request
            )
            flash('Suspicious flag removed', 'success')
        else:
            flash('Failed to remove flag', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('admin_leaves'))

@app.route('/admin/delete-user', methods=['POST'])
@admin_required
def admin_delete_user():
    user_type = request.form['user_type']
    user_id = request.form['user_id']
    
    db = Database()
    connection = db.get_connection()
    try:
        with connection.cursor() as cursor:
            table_map = {
                'student': ('students', 'reg_number'),
                'proctor': ('proctors', 'employee_id'),
                'supervisor': ('hostel_supervisors', 'supervisor_id'),
                'admin': ('admins', 'admin_id')
            }
            
            if user_type not in table_map:
                flash('Invalid user type', 'error')
                return redirect(url_for('admin_users'))
            
            table_name, id_column = table_map[user_type]
            
            if user_type == 'proctor':
                cursor.execute("SELECT COUNT(*) FROM students WHERE proctor_id = %s", (user_id,))
                student_count = cursor.fetchone()[0]
                if student_count > 0:
                    flash(f'Cannot delete proctor with {student_count} assigned students', 'error')
                    return redirect(url_for('admin_users'))
            
            cursor.execute(f"DELETE FROM {table_name} WHERE {id_column} = %s", (user_id,))
            connection.commit()
            
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='DELETE_USER',
                target_type=user_type.upper(),
                target_id=user_id,
                details=f'Deleted {user_type} from system',
                request=request
            )
            
            flash(f'{user_type.capitalize()} deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
        print(f"Error: {e}")
    finally:
        if connection:
            connection.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/logout')
def admin_logout():
    if 'admin_id' in session:
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='LOGOUT',
            target_type='SYSTEM',
            target_id=None,
            details='Admin logged out',
            request=request
        )
    
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_role', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/logout/<role>')
def logout(role):
    if role == 'admin' and 'admin_id' in session:
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='LOGOUT',
            target_type='SYSTEM',
            target_id=None,
            details='Admin logged out via logout route',
            request=request
        )
    
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/test')
def test():
    return {
        'status': 'online',
        'database': 'vit_leave_management',
        'message': 'VIT Leave Management System is running',
        'db_connected': db_connected,
        'session_data': dict(session) if session else {}
    }

@app.route('/test/verification')
def test_verification():
    try:
        db = Database()
        connection = db.get_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT qr_token FROM leaves WHERE qr_token IS NOT NULL LIMIT 1")
            result = cursor.fetchone()
        
        if result:
            qr_token = result[0]
            return f"""
                <h1>Test Verification</h1>
                <p>Sample QR Token: {qr_token}</p>
                <form method="POST" action="/hostel/verify">
                    <input type="hidden" name="qr_token" value="{qr_token}">
                    <button type="submit">Test Verify</button>
                </form>
                <p><a href="/hostel/verify">Back to verification</a></p>
            """
        else:
            return "<h1>No test QR tokens available</h1>"
    except Exception as e:
        return f"<h1>Error: {str(e)}</h1>"

@app.route('/clear')
def clear_session():
    session.clear()
    return "Session cleared!"

@app.route('/setup/sample-data')
def setup_sample_data():
    """Manual endpoint to create sample data"""
    try:
        from models import create_sample_data
        create_sample_data()
        flash('Sample data created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating sample data: {str(e)}', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print("\n" + "="*60)
    print("SYSTEM STARTED SUCCESSFULLY!")
    print("="*60)
    print(f"\nDatabase Connected: {'✓ YES' if db_connected else '✗ NO'}")
    print(f"Access the system at: http://0.0.0.0:{port}")
    print("\nDefault Admin Credentials:")
    print("  Admin: ADMIN001")
    print("  Password: Admin@123")
    print("\n" + "="*60)
    app.run(host='0.0.0.0', port=port, debug=False)
