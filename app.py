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

# Initialize database - ONLY creates tables if they don't exist
try:
    db = Database()
    db.init_db()  # This only creates tables if they don't exist
    print("✓ Database initialized successfully!")
    
    # Check if we need to add minimal admin user
    connection = db.get_connection()
    try:
        with connection.cursor() as cursor:
            # Check if any admin exists
            cursor.execute("SELECT COUNT(*) as count FROM admins")
            admin_count = cursor.fetchone()['count']
            
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
        print(f"✗ Error checking admin: {e}")
        traceback.print_exc()
    finally:
        connection.close()
        
except Exception as e:
    print(f"✗ Database initialization failed: {e}")
    traceback.print_exc()
    print("⚠ Continuing in limited mode...")

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        reg_number = request.form['reg_number'].strip().upper()
        password = request.form['password']
        
        print(f"Student login attempt: {reg_number}")
        
        student = Student.login(reg_number, password)
        if student:
            session['student_id'] = student['reg_number']
            session['student_name'] = student['name']
            flash(f'Welcome back, {student["name"]}!', 'success')
            return redirect(url_for('student_dashboard'))
        
        flash('Invalid registration number or password', 'error')
        return render_template('student_login.html', error='Invalid credentials')
    
    return render_template('student_login.html')

@app.route('/student/dashboard')
@login_required('student_id')
def student_dashboard():
    leaves = Student.get_leave_history(session['student_id'])
    return render_template('student_dashboard.html', 
                         leaves=leaves, 
                         student_name=session['student_name'],
                         today=datetime.now().strftime('%Y-%m-%d'))

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
        
        proctor = Proctor.login(employee_id, password)
        if proctor:
            session['proctor_id'] = proctor['employee_id']
            session['proctor_name'] = proctor['name']
            flash(f'Welcome, Dr. {proctor["name"]}!', 'success')
            return redirect(url_for('proctor_dashboard'))
        
        flash('Invalid employee ID or password', 'error')
        return render_template('proctor_login.html', error='Invalid credentials')
    
    return render_template('proctor_login.html')

@app.route('/proctor/dashboard')
@login_required('proctor_id')
def proctor_dashboard():
    pending_leaves = Proctor.get_pending_leaves(session['proctor_id'])
    return render_template('proctor_dashboard.html', 
                         leaves=pending_leaves, 
                         proctor_name=session['proctor_name'])

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
        
        supervisor = HostelSupervisor.login(supervisor_id, password)
        if supervisor:
            session['supervisor_id'] = supervisor['supervisor_id']
            session['supervisor_name'] = supervisor['name']
            session['hostel_block'] = supervisor['hostel_block']
            flash(f'Welcome, {supervisor["name"]}!', 'success')
            return redirect(url_for('hostel_verify'))
        
        flash('Invalid supervisor ID or password', 'error')
        return render_template('hostel_login.html', error='Invalid credentials')
    
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
            leave, message = HostelSupervisor.verify_qr_token(qr_token, session['supervisor_id'])
            
            if leave:
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
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = AdminModel.get_system_stats()
    recent_logs = AdminModel.get_all_logs(limit=20)
    suspicious_leaves = AdminModel.get_all_leaves({'suspicious_only': True})
    
    return render_template('admin_dashboard.html',
                         stats=stats,
                         recent_logs=recent_logs,
                         suspicious_leaves=suspicious_leaves,
                         admin_name=session['admin_name'],
                         admin_role=session['admin_role'])

@app.route('/admin/leaves')
@admin_required
def admin_leaves():
    filters = {
        'status': request.args.get('status'),
        'leave_type': request.args.get('leave_type'),
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'suspicious_only': request.args.get('suspicious_only') == 'true'
    }
    
    leaves = AdminModel.get_all_leaves(filters)
    return render_template('admin_leaves.html',
                         leaves=leaves,
                         filters=filters,
                         admin_name=session['admin_name'])

@app.route('/admin/logs')
@admin_required
def admin_logs():
    logs = AdminModel.get_all_logs(limit=200)
    return render_template('admin_logs.html',
                         logs=logs,
                         admin_name=session['admin_name'])

@app.route('/admin/users')
@admin_required
def admin_users():
    users = AdminModel.get_all_users()
    db = Database()
    connection = db.get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT employee_id, name FROM proctors ORDER BY name")
            proctors = cursor.fetchall()
    finally:
        connection.close()
    
    return render_template('admin_users.html',
                         users=users,
                         proctors=proctors,
                         admin_name=session['admin_name'])

@app.route('/admin/add-user', methods=['POST'])
@admin_required
def admin_add_user():
    user_type = request.form['user_type']
    
    # DEBUG: Print all form data
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
            
            # Validate required fields
            if not all([proctor_data['employee_id'], proctor_data['name'], proctor_data['password']]):
                flash('Please fill all required fields for proctor', 'error')
                return redirect(url_for('admin_users'))
            
            # Call the AdminModel method
            success = AdminModel.add_proctor(proctor_data)
            if success:
                # Log the action
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
            
            # Validate required fields
            required_fields = ['reg_number', 'name', 'password', 'proctor_id', 'hostel_block', 'room_number']
            missing_fields = [field for field in required_fields if not student_data.get(field)]
            
            if missing_fields:
                flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
                return redirect(url_for('admin_users'))
            
            # Call the AdminModel method
            success = AdminModel.add_student(student_data)
            if success:
                # Log the action
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
            
            # Validate required fields
            if not all([supervisor_data['supervisor_id'], supervisor_data['name'], 
                       supervisor_data['password'], supervisor_data['hostel_block']]):
                flash('Please fill all required fields for supervisor', 'error')
                return redirect(url_for('admin_users'))
            
            # Call the AdminModel method
            success = AdminModel.add_supervisor(supervisor_data)
            if success:
                # Log the action
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
                # Log the action
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
                # Log the action
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
                # Log the action
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
    
    success = AdminModel.reset_password(user_type, user_id, new_password)
    if success:
        # Log the action
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
    
    return redirect(url_for('admin_users'))

@app.route('/admin/flag-suspicious/<int:leave_id>', methods=['POST'])
@admin_required
def admin_flag_suspicious(leave_id):
    reason = request.form['reason']
    
    success = AdminModel.flag_suspicious(leave_id, session['admin_id'], reason)
    if success:
        # Log the action
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
    
    return redirect(request.referrer or url_for('admin_leaves'))

@app.route('/admin/remove-flag/<int:leave_id>')
@admin_required
def admin_remove_flag(leave_id):
    success = AdminModel.remove_flag(leave_id)
    if success:
        # Log the action
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
                cursor.execute("SELECT COUNT(*) as count FROM students WHERE proctor_id = %s", (user_id,))
                student_count = cursor.fetchone()['count']
                if student_count > 0:
                    flash(f'Cannot delete proctor with {student_count} assigned students', 'error')
                    return redirect(url_for('admin_users'))
            
            cursor.execute(f"DELETE FROM {table_name} WHERE {id_column} = %s", (user_id,))
            connection.commit()
            
            # Log the action
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
    finally:
        connection.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/logout')
def admin_logout():
    # Log the action before clearing session
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
    # Log admin logout if applicable
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

@app.route('/test/verification')
def test_verification():
    try:
        db = Database()
        connection = db.get_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT qr_token FROM leaves WHERE qr_token IS NOT NULL LIMIT 1")
            result = cursor.fetchone()
        
        if result:
            qr_token = result['qr_token']
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

@app.route('/test')
def test():
    return {
        'status': 'online',
        'database': 'vit_leave_management',
        'message': 'VIT Leave Management System is running',
        'session_data': dict(session) if session else {}
    }

@app.route('/clear')
def clear_session():
    session.clear()
    return "Session cleared!"

@app.route('/setup/sample-data')
def setup_sample_data():
    """Manual endpoint to create sample data - only run when needed"""
    from models import create_sample_data
    try:
        create_sample_data()
        flash('Sample data created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating sample data: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/admin/test-add-proctor')
@admin_required
def test_add_proctor():
    """Test endpoint to add a proctor directly"""
    try:
        from models import UserModel
        
        proctor_data = {
            'employee_id': 'P999',
            'name': 'Test Proctor',
            'password': 'test123456',
            'email': 'test.proctor@vit.ac.in',
            'department': 'TEST'
        }
        
        success = AdminModel.add_proctor(proctor_data)
        if success:
            # Log the action
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='TEST_ADD_USER',
                target_type='PROCTOR',
                target_id=proctor_data['employee_id'],
                details='Test proctor added via test endpoint',
                request=request
            )
        
        return jsonify({
            'success': success,
            'message': 'Proctor added successfully' if success else 'Failed to add proctor',
            'proctor_id': proctor_data['employee_id']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/test-add-supervisor')
@admin_required
def test_add_supervisor():
    """Test endpoint to add a supervisor directly"""
    try:
        from models import UserModel
        
        supervisor_data = {
            'supervisor_id': 'S999',
            'name': 'Test Supervisor',
            'password': 'test123456',
            'hostel_block': 'A',
            'email': 'test.supervisor@vit.ac.in'
        }
        
        success = AdminModel.add_supervisor(supervisor_data)
        if success:
            # Log the action
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='TEST_ADD_USER',
                target_type='SUPERVISOR',
                target_id=supervisor_data['supervisor_id'],
                details='Test supervisor added via test endpoint',
                request=request
            )
        
        return jsonify({
            'success': success,
            'message': 'Supervisor added successfully' if success else 'Failed to add supervisor',
            'supervisor_id': supervisor_data['supervisor_id']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/user-form', methods=['POST'])
def debug_user_form():
    """Debug endpoint to see what form data is being sent"""
    print("\n" + "="*60)
    print("DEBUG USER FORM DATA")
    print(f"Request method: {request.method}")
    print(f"Form data: {dict(request.form)}")
    print(f"Headers: {dict(request.headers)}")
    print("="*60 + "\n")
    
    return jsonify({
        'success': True,
        'form_data': dict(request.form),
        'message': 'Form data received'
    })

@app.route('/admin/test-log')
@admin_required
def test_admin_log():
    """Test admin logging"""
    try:
        success = AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='TEST_LOG',
            target_type='SYSTEM',
            target_id='TEST001',
            details='Test log entry created manually',
            request=request
        )
        
        if success:
            flash('Test log created successfully! Check admin logs.', 'success')
            return redirect(url_for('admin_logs'))
        else:
            flash('Failed to create test log', 'error')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/export-data')
@admin_required
def admin_export_data():
    """Export system data (example)"""
    try:
        # Log the export action
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='EXPORT_DATA',
            target_type='SYSTEM',
            target_id=None,
            details='Exported system data',
            request=request
        )
        
        flash('Data exported successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error exporting data: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/view-log/<int:log_id>')
@admin_required
def admin_view_log(log_id):
    """View specific log details"""
    db = Database()
    connection = db.get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM admin_logs WHERE log_id = %s", (log_id,))
            log = cursor.fetchone()
            
            if log:
                return jsonify({
                    'success': True,
                    'log': log
                })
            else:
                return jsonify({'success': False, 'message': 'Log not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        connection.close()

@app.route('/admin/clear-old-logs')
@admin_required
def admin_clear_old_logs():
    """Clear logs older than 30 days"""
    try:
        db = Database()
        connection = db.get_connection()
        with connection.cursor() as cursor:
            cursor.execute("""
                DELETE FROM admin_logs 
                WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
            """)
            deleted_count = cursor.rowcount
            connection.commit()
            
            # Log the action
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='CLEAR_LOGS',
                target_type='SYSTEM',
                target_id=None,
                details=f'Cleared {deleted_count} old logs (older than 30 days)',
                request=request
            )
            
            flash(f'Cleared {deleted_count} old logs successfully!', 'success')
    except Exception as e:
        flash(f'Error clearing logs: {str(e)}', 'error')
    
    return redirect(url_for('admin_logs'))

@app.route('/admin/log-export', methods=['POST'])
@admin_required
def log_export():
    """Log export action"""
    try:
        data = request.get_json()
        
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='EXPORT_LOGS',
            target_type='SYSTEM',
            target_id=None,
            details=f'Exported {data.get("export_count", 0)} logs to {data.get("filename", "unknown")}',
            request=request
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    

@app.route('/admin/generate-pdf/<report_type>')
@admin_required
def generate_pdf_report(report_type):
    """Generate PDF report"""
    try:
        # Get data based on report type
        leave_data = {}
        
        if report_type == 'monthly_summary':
            monthly_data = ReportData.get_monthly_summary()
            leave_data = {
                'monthly_summary': monthly_data,
                'report_type': 'monthly_summary'
            }
        
        elif report_type == 'leave_statistics':
            filters = {
                'date_from': request.args.get('date_from'),
                'date_to': request.args.get('date_to')
            }
            leaves = AdminModel.get_all_leaves(filters)
            leave_data = {
                'leaves': leaves,
                'report_type': 'leave_statistics'
            }
        
        elif report_type == 'user_activity':
            user_stats = ReportData.get_user_activity_stats()
            leave_data = {
                'user_stats': user_stats,
                'report_type': 'user_activity'
            }
        
        elif report_type == 'suspicious_activity':
            leaves = AdminModel.get_all_leaves({'suspicious_only': True})
            leave_data = {
                'leaves': leaves,
                'report_type': 'suspicious_activity'
            }
        
        else:
            flash('Invalid report type', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Generate PDF
        pdf_base64 = PDFGenerator.generate_leave_report(leave_data, report_type)
        
        # Log the action
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='GENERATE_REPORT',
            target_type='SYSTEM',
            target_id=None,
            details=f'Generated {report_type} PDF report',
            request=request
        )
        
        # Return PDF for download
        from flask import send_file
        import io
        
        pdf_bytes = base64.b64decode(pdf_base64)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'vit_report_{report_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        print(f"Error generating PDF: {e}")
        traceback.print_exc()
        return redirect(url_for('admin_dashboard'))

@app.route('/hostel/download-slip')
@login_required('supervisor_id')
def download_slip():
    """Download verification slip as PDF"""
    try:
        if 'slip_data' not in session:
            flash('No slip data available', 'error')
            return redirect(url_for('hostel_verify'))
        
        slip_data = session['slip_data']
        
        # Generate PDF slip
        pdf_data = PDFGenerator.generate_slip_pdf(slip_data)
        
        # Log the action
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO verification_logs 
                    (leave_id, supervisor_id, action, notes)
                    VALUES (
                        (SELECT leave_id FROM leaves WHERE student_reg = %s ORDER BY applied_at DESC LIMIT 1),
                        %s, 'slip_downloaded', 'Leave slip downloaded as PDF'
                    )
                """, (slip_data['reg_number'], session['supervisor_id']))
                connection.commit()
        finally:
            connection.close()
        
        # Return PDF for download
        from flask import send_file
        import io
        
        return send_file(
            io.BytesIO(pdf_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'leave_slip_{slip_data["reg_number"]}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
    except Exception as e:
        flash(f'Error generating slip: {str(e)}', 'error')
        print(f"Error generating slip: {e}")
        traceback.print_exc()
        return redirect(url_for('hostel_verify'))
    
@app.route('/admin/export-logs-csv')
@admin_required
def export_logs_csv():
    """Export logs as CSV"""
    try:
        import csv
        from io import StringIO
        
        db = Database()
        connection = db.get_connection()
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    DATE(created_at) as date,
                    admin_id,
                    action_type,
                    target_type,
                    target_id,
                    details,
                    ip_address
                FROM admin_logs
                ORDER BY created_at DESC
                LIMIT 1000
            """)
            logs = cursor.fetchall()
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Date', 'Admin ID', 'Action', 'Target Type', 'Target ID', 'Details', 'IP Address'])
        
        # Write rows
        for log in logs:
            writer.writerow([
                log['date'].strftime('%Y-%m-%d') if log['date'] else '',
                log['admin_id'] or '',
                log['action_type'] or '',
                log['target_type'] or '',
                log['target_id'] or '',
                log['details'] or '',
                log['ip_address'] or ''
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        # Log the export
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='EXPORT_LOGS',
            target_type='SYSTEM',
            target_id=None,
            details=f'Exported {len(logs)} logs as CSV',
            request=request
        )
        
        return jsonify({
            'success': True,
            'csv_content': csv_content,
            'count': len(logs)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Add these routes to app.py after the existing routes

@app.route('/admin/leave-details/<int:leave_id>')
@admin_required
def admin_leave_details(leave_id):
    """Get detailed information about a specific leave"""
    try:
        db = Database()
        connection = db.get_connection()
        
        with connection.cursor() as cursor:
            # First, check if the admin_leave_flags table exists
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = 'admin_leave_flags'
            """, (db.database,))
            
            has_admin_leave_flags = cursor.fetchone() is not None
            
            # Build query based on available tables
            if has_admin_leave_flags:
                query = """
                    SELECT 
                        l.*,
                        s.name as student_name,
                        s.reg_number,
                        s.hostel_block,
                        s.room_number,
                        s.phone,
                        s.parent_phone,
                        p.name as proctor_name,
                        p.employee_id as proctor_id,
                        p.email as proctor_email,
                        p.department as proctor_dept,
                        hs.name as supervisor_name,
                        hs.supervisor_id,
                        hs.hostel_block as supervisor_block,
                        alf.flagged_by as flagged_by_admin,
                        al.name as flagged_by_name,
                        alf.reason as flag_reason,
                        alf.created_at as flagged_at
                    FROM leaves l
                    JOIN students s ON l.student_reg = s.reg_number
                    JOIN proctors p ON l.proctor_id = p.employee_id
                    LEFT JOIN hostel_supervisors hs ON s.hostel_block = hs.hostel_block
                    LEFT JOIN admin_leave_flags alf ON l.leave_id = alf.leave_id
                    LEFT JOIN admins al ON alf.flagged_by = al.admin_id
                    WHERE l.leave_id = %s
                """
            else:
                query = """
                    SELECT 
                        l.*,
                        s.name as student_name,
                        s.reg_number,
                        s.hostel_block,
                        s.room_number,
                        s.phone,
                        s.parent_phone,
                        p.name as proctor_name,
                        p.employee_id as proctor_id,
                        p.email as proctor_email,
                        p.department as proctor_dept,
                        hs.name as supervisor_name,
                        hs.supervisor_id,
                        hs.hostel_block as supervisor_block
                    FROM leaves l
                    JOIN students s ON l.student_reg = s.reg_number
                    JOIN proctors p ON l.proctor_id = p.employee_id
                    LEFT JOIN hostel_supervisors hs ON s.hostel_block = hs.hostel_block
                    WHERE l.leave_id = %s
                """
            
            cursor.execute(query, (leave_id,))
            leave = cursor.fetchone()
            
            if not leave:
                return jsonify({'error': 'Leave not found'}), 404
            
            # Check if leave_audit_log table exists
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = 'leave_audit_log'
            """, (db.database,))
            
            has_audit_log = cursor.fetchone() is not None
            
            if has_audit_log:
                # Get approval/verification history
                cursor.execute("""
                    SELECT 
                        action,
                        performed_by,
                        performed_by_type,
                        timestamp,
                        notes
                    FROM leave_audit_log
                    WHERE leave_id = %s
                    ORDER BY timestamp DESC
                """, (leave_id,))
                audit_logs = cursor.fetchall()
            else:
                audit_logs = []
            
            # Check if parent_contacts table exists
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = 'parent_contacts'
            """, (db.database,))
            
            has_parent_contacts = cursor.fetchone() is not None
            
            parent_contacted = leave.get('parent_contacted', False)
            parent_contact = None
            
            if parent_contacted and has_parent_contacts:
                cursor.execute("""
                    SELECT 
                        contact_time,
                        method,
                        confirmation_code,
                        notes
                    FROM parent_contacts
                    WHERE leave_id = %s
                """, (leave_id,))
                parent_contact = cursor.fetchone()
            
            # Get QR verification history
            cursor.execute("""
                SELECT 
                    vl.*,
                    hs.name as supervisor_name
                FROM verification_logs vl
                LEFT JOIN hostel_supervisors hs ON vl.supervisor_id = hs.supervisor_id
                WHERE vl.leave_id = %s
                ORDER BY timestamp DESC
            """, (leave_id,))
            verification_logs = cursor.fetchall()
            
            # Format the response
            response = {
                'leave_id': leave['leave_id'],
                'student': {
                    'name': leave['student_name'],
                    'reg_number': leave['reg_number'],
                    'hostel_block': leave.get('hostel_block', 'N/A'),
                    'room_number': leave.get('room_number', 'N/A'),
                    'phone': leave.get('phone', 'N/A'),
                    'parent_phone': leave.get('parent_phone', 'N/A')
                },
                'leave_details': {
                    'type': leave.get('leave_type', 'regular'),
                    'from_date': str(leave['from_date']) if leave.get('from_date') else 'N/A',
                    'to_date': str(leave['to_date']) if leave.get('to_date') else 'N/A',
                    'from_time': str(leave['from_time']) if leave.get('from_time') else 'N/A',
                    'to_time': str(leave['to_time']) if leave.get('to_time') else 'N/A',
                    'duration_days': (leave['to_date'] - leave['from_date']).days + 1 if leave.get('from_date') and leave.get('to_date') else 1,
                    'reason': leave.get('reason', 'No reason provided'),
                    'destination': leave.get('destination', 'Not specified'),
                    'parent_contacted': parent_contacted,
                    'status': leave.get('status', 'pending'),
                    'applied_at': str(leave['applied_at']) if leave.get('applied_at') else 'N/A'
                },
                'proctor': {
                    'name': leave.get('proctor_name', 'Unknown'),
                    'employee_id': leave.get('proctor_id', 'N/A'),
                    'email': leave.get('proctor_email', 'N/A'),
                    'department': leave.get('proctor_dept', 'N/A')
                },
                'hostel_supervisor': {
                    'name': leave.get('supervisor_name', 'Not Assigned'),
                    'supervisor_id': leave.get('supervisor_id', 'N/A'),
                    'hostel_block': leave.get('supervisor_block', 'N/A')
                },
                'suspicious_flag': {
                    'is_flagged': leave.get('suspicious_flag', False),
                    'flagged_by': leave.get('flagged_by_name') if leave.get('flagged_by_name') else None,
                    'reason': leave.get('flag_reason') if leave.get('flag_reason') else None,
                    'flagged_at': str(leave.get('flagged_at')) if leave.get('flagged_at') else None
                },
                'audit_logs': [
                    {
                        'action': log['action'],
                        'performed_by': log['performed_by'],
                        'performed_by_type': log['performed_by_type'],
                        'timestamp': str(log['timestamp']),
                        'notes': log['notes']
                    }
                    for log in audit_logs
                ],
                'parent_contact': parent_contact,
                'verification_logs': [
                    {
                        'action': log['action'],
                        'supervisor': log['supervisor_name'] or log['supervisor_id'],
                        'timestamp': str(log['timestamp']),
                        'notes': log['notes']
                    }
                    for log in verification_logs
                ],
                'qr_code': {
                    'token': leave.get('qr_token'),
                    'generated_at': str(leave.get('qr_generated_at')) if leave.get('qr_generated_at') else None,
                    'expires_at': str(leave.get('qr_expiry')) if leave.get('qr_expiry') else None,
                    'verified_at': str(leave.get('verified_at')) if leave.get('verified_at') else None
                }
            }
            
            return jsonify(response)
            
    except Exception as e:
        print(f"Error fetching leave details: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        connection.close()

@app.route('/admin/delete-leave/<int:leave_id>', methods=['DELETE', 'POST'])
@admin_required
def admin_delete_leave(leave_id):
    """Delete a leave application (admin only)"""
    try:
        db = Database()
        connection = db.get_connection()
        
        with connection.cursor() as cursor:
            # First, get leave details for logging
            cursor.execute("""
                SELECT l.*, s.name as student_name, s.reg_number 
                FROM leaves l
                JOIN students s ON l.student_reg = s.reg_number
                WHERE l.leave_id = %s
            """, (leave_id,))
            
            leave = cursor.fetchone()
            
            if not leave:
                return jsonify({'error': 'Leave not found'}), 404
            
            # Check if leave can be deleted (only pending or rejected leaves)
            if leave['status'] not in ['pending', 'rejected']:
                return jsonify({
                    'error': 'Cannot delete approved or completed leaves',
                    'status': leave['status']
                }), 400
            
            # Delete related records first
            # 1. Delete from admin_leave_flags
            cursor.execute("DELETE FROM admin_leave_flags WHERE leave_id = %s", (leave_id,))
            
            # 2. Delete from verification_logs
            cursor.execute("DELETE FROM verification_logs WHERE leave_id = %s", (leave_id,))
            
            # 3. Delete from parent_contacts
            cursor.execute("DELETE FROM parent_contacts WHERE leave_id = %s", (leave_id,))
            
            # 4. Delete from leave_audit_log
            cursor.execute("DELETE FROM leave_audit_log WHERE leave_id = %s", (leave_id,))
            
            # 5. Finally delete the leave
            cursor.execute("DELETE FROM leaves WHERE leave_id = %s", (leave_id,))
            
            connection.commit()
            
            # Log the action
            AdminModel.log_action(
                admin_id=session['admin_id'],
                action_type='DELETE_LEAVE',
                target_type='LEAVE',
                target_id=leave_id,
                details=f'Deleted leave #{leave_id} for student {leave["reg_number"]}',
                request=request
            )
            
            return jsonify({
                'success': True,
                'message': f'Leave #{leave_id} deleted successfully',
                'deleted_id': leave_id
            })
            
    except Exception as e:
        connection.rollback()
        print(f"Error deleting leave: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        connection.close()

@app.route('/admin/export/leaves')
@admin_required
def admin_export_leaves():
    """Export leaves data as CSV"""
    try:
        import csv
        from io import StringIO
        import pandas as pd
        
        # Get filters from query parameters
        filters = {
            'status': request.args.get('status'),
            'leave_type': request.args.get('leave_type'),
            'date_from': request.args.get('date_from'),
            'date_to': request.args.get('date_to'),
            'suspicious_only': request.args.get('suspicious_only') == 'true'
        }
        
        # Get leaves data using existing method
        leaves = AdminModel.get_all_leaves(filters)
        
        if not leaves:
            return jsonify({'error': 'No data to export'}), 404
        
        # Convert to DataFrame for easy CSV export
        df_data = []
        for leave in leaves:
            # Safely get values with defaults
            approved_at = leave.get('approved_at')
            verified_at = leave.get('verified_at')
            qr_expiry = leave.get('qr_expiry')
            hostel_block = leave.get('hostel_block', 'N/A')
            room_number = leave.get('room_number', 'N/A')
            parent_contacted = leave.get('parent_contacted', False)
            suspicious_flag = leave.get('suspicious_flag', False)
            qr_token = leave.get('qr_token', '')
            
            df_data.append({
                'Leave ID': leave['leave_id'],
                'Student Name': leave['student_name'],
                'Registration Number': leave['reg_number'],
                'Hostel Block': hostel_block,
                'Room Number': room_number,
                'Leave Type': leave['leave_type'].title() if leave.get('leave_type') else 'N/A',
                'From Date': str(leave['from_date']) if leave.get('from_date') else 'N/A',
                'To Date': str(leave['to_date']) if leave.get('to_date') else 'N/A',
                'From Time': str(leave['from_time']) if leave.get('from_time') else 'N/A',
                'To Time': str(leave['to_time']) if leave.get('to_time') else 'N/A',
                'Destination': leave.get('destination', 'N/A'),
                'Reason': leave.get('reason', 'N/A'),
                'Status': leave['status'].upper() if leave.get('status') else 'N/A',
                'Proctor': leave.get('proctor_name', 'N/A'),
                'Applied At': leave['applied_at'].strftime('%Y-%m-%d %H:%M:%S') if leave.get('applied_at') else 'N/A',
                'Approved At': approved_at.strftime('%Y-%m-%d %H:%M:%S') if approved_at else '',
                'Verified At': verified_at.strftime('%Y-%m-%d %H:%M:%S') if verified_at else '',
                'Parent Contacted': 'Yes' if parent_contacted else 'No',
                'Suspicious Flag': 'Yes' if suspicious_flag else 'No',
                'QR Token': qr_token,
                'QR Expiry': qr_expiry.strftime('%Y-%m-%d %H:%M:%S') if qr_expiry else ''
            })
        
        df = pd.DataFrame(df_data)
        
        # Create CSV
        csv_buffer = StringIO()
        df.to_csv(csv_buffer, index=False, encoding='utf-8')
        csv_content = csv_buffer.getvalue()
        csv_buffer.close()
        
        # Log the export action
        AdminModel.log_action(
            admin_id=session['admin_id'],
            action_type='EXPORT_LEAVES',
            target_type='SYSTEM',
            target_id=None,
            details=f'Exported {len(leaves)} leaves as CSV',
            request=request
        )
        
        # Return CSV file
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=leaves_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        print(f"Error exporting leaves: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/leave-details/<int:leave_id>')
@login_required('student_id')
def get_leave_details(leave_id):
    """Get detailed information about a specific leave for student"""
    try:
        db = Database()
        connection = db.get_connection()
        
        with connection.cursor() as cursor:
            # Get leave details with student verification
            cursor.execute("""
                SELECT 
                    l.*,
                    s.name as student_name,
                    s.reg_number,
                    s.hostel_block,
                    s.room_number,
                    s.phone,
                    s.parent_phone,
                    p.name as proctor_name,
                    p.employee_id as proctor_id,
                    p.email as proctor_email,
                    p.department as proctor_dept
                FROM leaves l
                JOIN students s ON l.student_reg = s.reg_number
                JOIN proctors p ON l.proctor_id = p.employee_id
                WHERE l.leave_id = %s AND l.student_reg = %s
            """, (leave_id, session['student_id']))
            
            leave = cursor.fetchone()
            
            if not leave:
                return jsonify({'error': 'Leave not found or access denied'}), 404
            
            # Get verification logs for this leave
            cursor.execute("""
                SELECT 
                    vl.*,
                    hs.name as supervisor_name
                FROM verification_logs vl
                LEFT JOIN hostel_supervisors hs ON vl.supervisor_id = hs.supervisor_id
                WHERE vl.leave_id = %s
                ORDER BY vl.verified_at DESC
            """, (leave_id,))
            
            verification_logs = cursor.fetchall()
            
            # Format the response
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
            
            response = {
                'leave_id': leave['leave_id'],
                'leave_type': leave.get('leave_type', 'regular'),
                'status': leave.get('status', 'pending'),
                'from_date': format_date(leave['from_date']),
                'to_date': format_date(leave['to_date']),
                'from_time': format_time(leave['from_time']),
                'to_time': format_time(leave['to_time']),
                'reason': leave.get('reason', 'No reason provided'),
                'destination': leave.get('destination', 'Not specified'),
                'parent_contacted': bool(leave.get('parent_contacted', False)),
                'applied_at': str(leave['applied_at']) if leave.get('applied_at') else None,
                'approved_at': str(leave['approved_at']) if leave.get('approved_at') else None,
                'proctor_name': leave.get('proctor_name', 'Unknown'),
                'qr_token': leave.get('qr_token'),
                'qr_expiry': str(leave.get('qr_expiry')) if leave.get('qr_expiry') else None,
                'verification_logs': [
                    {
                        'timestamp': str(log['verified_at']),
                        'action': log['action'],
                        'supervisor': log['supervisor_name'] or log['supervisor_id'],
                        'notes': log['notes']
                    }
                    for log in verification_logs
                ]
            }
            
            return jsonify(response)
            
    except Exception as e:
        print(f"Error fetching leave details: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        connection.close()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("SYSTEM STARTED SUCCESSFULLY!")
    print("="*60)
    print("\nAccess the system at: http://localhost:5000")
    print("\nDefault Admin Credentials:")
    print("  Admin: ADMIN001 / Admin@123")
    print("\nTo create sample data for testing, visit:")
    print("  http://localhost:5000/setup/sample-data")
    print("\nTest URLs:")
    print("  Home: http://localhost:5000")
    print("  Student Dashboard: http://localhost:5000/student/dashboard")
    print("  Proctor Dashboard: http://localhost:5000/proctor/dashboard")
    print("  Hostel Verification: http://localhost:5000/hostel/verify")
    print("  Admin Dashboard: http://localhost:5000/admin/dashboard")
    print("  Admin Logs: http://localhost:5000/admin/logs")
    print("  Test Verification: http://localhost:5000/test/verification")
    print("\nDebug URLs (Admin only):")
    print("  Test Add Proctor: http://localhost:5000/admin/test-add-proctor")
    print("  Test Add Supervisor: http://localhost:5000/admin/test-add-supervisor")
    print("  Test Log: http://localhost:5000/admin/test-log")
    print("  Clear Old Logs: http://localhost:5000/admin/clear-old-logs")
    print("\n" + "="*60)
    
    app.run(debug=True, port=5000)