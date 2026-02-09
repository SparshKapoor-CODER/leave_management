# [file name]: models.py
import secrets
import string
from datetime import datetime, timedelta
import qrcode
from io import BytesIO
import base64
from database import Database

# Don't create db instance here - create in each method when needed
class UserModel:
    @staticmethod
    def hash_password(password):
        return Database.hash_password(password)
    
    @staticmethod
    def check_password(hashed_password, password):
        return Database.check_password(hashed_password, password)
    
    @staticmethod
    def generate_qr_token():
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))

class Student:
    @staticmethod
    def login(reg_number, password):
        db = Database()  # Create new instance
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM students WHERE reg_number = %s",
                    (reg_number,)
                )
                student = cursor.fetchone()
                
                if student and UserModel.check_password(student['password_hash'], password):
                    return student
                return None
        finally:
            connection.close()
    
    @staticmethod
    def apply_leave(student_reg, leave_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT proctor_id FROM students WHERE reg_number = %s",
                    (student_reg,)
                )
                student = cursor.fetchone()
                
                if not student:
                    return None
                
                sql = """
                    INSERT INTO leaves 
                    (student_reg, proctor_id, leave_type, from_date, to_date, 
                     from_time, to_time, reason, destination, parent_contacted)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                cursor.execute(sql, (
                    student_reg,
                    student['proctor_id'],
                    leave_data['leave_type'],
                    leave_data['from_date'],
                    leave_data['to_date'],
                    leave_data['from_time'],
                    leave_data['to_time'],
                    leave_data['reason'],
                    leave_data.get('destination', ''),
                    leave_data.get('parent_contacted', False)
                ))
                
                leave_id = cursor.lastrowid
                connection.commit()
                return leave_id
        finally:
            connection.close()
    
    @staticmethod
    def get_leave_history(student_reg):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT l.*, p.name as proctor_name 
                    FROM leaves l
                    JOIN proctors p ON l.proctor_id = p.employee_id
                    WHERE l.student_reg = %s
                    ORDER BY l.applied_at DESC
                """, (student_reg,))
                return cursor.fetchall()
        finally:
            connection.close()

class Proctor:
    @staticmethod
    def login(employee_id, password):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM proctors WHERE employee_id = %s",
                    (employee_id,)
                )
                proctor = cursor.fetchone()
                
                if proctor and UserModel.check_password(proctor['password_hash'], password):
                    return proctor
                return None
        finally:
            connection.close()
    
    @staticmethod
    def get_pending_leaves(proctor_id):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT l.*, s.name as student_name, s.reg_number,
                           s.hostel_block, s.room_number
                    FROM leaves l
                    JOIN students s ON l.student_reg = s.reg_number
                    WHERE l.proctor_id = %s AND l.status = 'pending'
                    ORDER BY l.applied_at ASC
                """, (proctor_id,))
                return cursor.fetchall()
        finally:
            connection.close()
    
    @staticmethod
    def approve_leave(leave_id, proctor_id):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT proctor_id FROM leaves WHERE leave_id = %s",
                    (leave_id,)
                )
                leave = cursor.fetchone()
                
                if not leave or leave['proctor_id'] != proctor_id:
                    return False
                
                qr_token = UserModel.generate_qr_token()
                qr_expiry = datetime.now() + timedelta(hours=24)
                
                cursor.execute("""
                    UPDATE leaves 
                    SET status = 'approved', 
                        approved_at = NOW(),
                        qr_token = %s,
                        qr_expiry = %s
                    WHERE leave_id = %s
                """, (qr_token, qr_expiry, leave_id))
                
                connection.commit()
                return qr_token
        finally:
            connection.close()
    
    @staticmethod
    def reject_leave(leave_id, proctor_id):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT proctor_id FROM leaves WHERE leave_id = %s",
                    (leave_id,)
                )
                leave = cursor.fetchone()
                
                if not leave or leave['proctor_id'] != proctor_id:
                    return False
                
                cursor.execute("""
                    UPDATE leaves 
                    SET status = 'rejected'
                    WHERE leave_id = %s
                """, (leave_id,))
                
                connection.commit()
                return True
        finally:
            connection.close()

class HostelSupervisor:
    @staticmethod
    def verify_supervisor_block(supervisor_id, block_to_check):
        """Verify if supervisor is assigned to the given block"""
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT hostel_block FROM hostel_supervisors WHERE supervisor_id = %s",
                    (supervisor_id,)
                )
                supervisor = cursor.fetchone()
                
                if supervisor:
                    return supervisor['hostel_block'].upper() == block_to_check.upper()
                return False
        finally:
            connection.close()

    @staticmethod
    def login(supervisor_id, password):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM hostel_supervisors WHERE supervisor_id = %s",
                    (supervisor_id,)
                )
                supervisor = cursor.fetchone()
                
                if supervisor and UserModel.check_password(supervisor['password_hash'], password):
                    return supervisor
                return None
        finally:
            connection.close()
    
    @staticmethod
    def verify_qr_token(qr_token, supervisor_id, supervisor_block=None):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT l.*, s.name as student_name, s.reg_number as student_reg,
                           s.hostel_block, s.room_number, p.name as proctor_name
                    FROM leaves l
                    JOIN students s ON l.student_reg = s.reg_number
                    JOIN proctors p ON l.proctor_id = p.employee_id
                    WHERE l.qr_token = %s 
                    AND l.status = 'approved'
                    AND (l.qr_expiry IS NULL OR l.qr_expiry > NOW())
                """, (qr_token,))
                
                leave = cursor.fetchone()
                
                if not leave:
                    return None, "Invalid or expired QR code"
                
                # Additional security: Verify supervisor's block matches student's block
                if supervisor_block:
                    student_block = leave.get('hostel_block', '')
                    if student_block.upper() != supervisor_block.upper():
                        return None, f"Access denied! You can only verify students from Block {supervisor_block}. This student is from Block {student_block}."
                
                cursor.execute("""
                    INSERT INTO verification_logs 
                    (leave_id, supervisor_id, action, notes)
                    VALUES (%s, %s, 'granted', 'QR code verified successfully')
                """, (leave['leave_id'], supervisor_id))
                
                cursor.execute("""
                    UPDATE leaves 
                    SET verification_count = verification_count + 1
                    WHERE leave_id = %s
                """, (leave['leave_id'],))
                
                connection.commit()
                return leave, "Verification successful"
        finally:
            connection.close()
    
    @staticmethod
    def generate_qr_code(qr_token):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr_data = f"VIT-LEAVE:{qr_token}"
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"

class AdminModel:
    @staticmethod
    def login(admin_id, password):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM admins WHERE admin_id = %s",
                    (admin_id,)
                )
                admin = cursor.fetchone()
                
                if admin and UserModel.check_password(admin['password_hash'], password):
                    return admin
                return None
        finally:
            connection.close()
    
    @staticmethod
    def get_all_logs(limit=100):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM (
                        SELECT 
                            'leave' as log_type,
                            leave_id as id,
                            student_reg as user_id,
                            CONCAT('Leave ', status) as action,
                            applied_at as timestamp,
                            reason as details,
                            NULL as ip_address
                        FROM leaves
                        
                        UNION ALL
                        
                        SELECT 
                            'verification' as log_type,
                            log_id as id,
                            supervisor_id as user_id,
                            action,
                            verified_at as timestamp,
                            notes as details,
                            NULL as ip_address
                        FROM verification_logs
                        
                        UNION ALL
                        
                        SELECT 
                            'admin' as log_type,
                            log_id as id,
                            admin_id as user_id,
                            action_type as action,
                            created_at as timestamp,
                            details,
                            ip_address
                        FROM admin_logs
                    ) as all_logs
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (limit,))
                return cursor.fetchall()
        finally:
            connection.close()
    
    @staticmethod
    def get_all_leaves(filters=None):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                base_query = """
                    SELECT l.*, 
                           s.name as student_name, s.reg_number,
                           p.name as proctor_name,
                           hs.name as supervisor_name
                    FROM leaves l
                    LEFT JOIN students s ON l.student_reg = s.reg_number
                    LEFT JOIN proctors p ON l.proctor_id = p.employee_id
                    LEFT JOIN hostel_supervisors hs ON hs.hostel_block = s.hostel_block
                    WHERE 1=1
                """
                params = []
                
                if filters:
                    if filters.get('status'):
                        base_query += " AND l.status = %s"
                        params.append(filters['status'])
                    if filters.get('leave_type'):
                        base_query += " AND l.leave_type = %s"
                        params.append(filters['leave_type'])
                    if filters.get('date_from'):
                        base_query += " AND DATE(l.applied_at) >= %s"
                        params.append(filters['date_from'])
                    if filters.get('date_to'):
                        base_query += " AND DATE(l.applied_at) <= %s"
                        params.append(filters['date_to'])
                    if filters.get('suspicious_only'):
                        base_query += " AND l.suspicious_flag = TRUE"
                
                base_query += " ORDER BY l.applied_at DESC LIMIT 500"
                cursor.execute(base_query, params)
                return cursor.fetchall()
        finally:
            connection.close()
    
    @staticmethod
    def get_system_stats():
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                stats = {}
                
                cursor.execute("SELECT COUNT(*) as count FROM students")
                stats['total_students'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM proctors")
                stats['total_proctors'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM hostel_supervisors")
                stats['total_supervisors'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM leaves")
                stats['total_leaves'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM leaves WHERE status = 'approved'")
                stats['approved_leaves'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM leaves WHERE status = 'pending'")
                stats['pending_leaves'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM leaves WHERE suspicious_flag = TRUE")
                stats['suspicious_leaves'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM leaves WHERE DATE(applied_at) = CURDATE()")
                stats['today_leaves'] = cursor.fetchone()['count']
                
                return stats
        finally:
            connection.close()
    
    @staticmethod
    def add_proctor(proctor_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                # Check if proctor already exists
                cursor.execute("SELECT * FROM proctors WHERE employee_id = %s", (proctor_data['employee_id'],))
                if cursor.fetchone():
                    print(f"✗ Proctor {proctor_data['employee_id']} already exists")
                    return False
                
                sql = """
                    INSERT INTO proctors 
                    (employee_id, name, password_hash, email, department)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    proctor_data['employee_id'],
                    proctor_data['name'],
                    UserModel.hash_password(proctor_data['password']),
                    proctor_data['email'],
                    proctor_data['department']
                ))
                connection.commit()
                print(f"✓ Proctor {proctor_data['employee_id']} added successfully")
                return True
        except Exception as e:
            print(f"✗ Error adding proctor: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            connection.close()
    
    @staticmethod
    def add_student(student_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                # Check if student already exists
                cursor.execute("SELECT * FROM students WHERE reg_number = %s", (student_data['reg_number'],))
                if cursor.fetchone():
                    print(f"✗ Student {student_data['reg_number']} already exists")
                    return False
                
                # Check if proctor exists
                cursor.execute("SELECT * FROM proctors WHERE employee_id = %s", (student_data['proctor_id'],))
                if not cursor.fetchone():
                    print(f"✗ Proctor {student_data['proctor_id']} not found")
                    return False
                
                sql = """
                    INSERT INTO students 
                    (reg_number, name, password_hash, proctor_id, 
                     hostel_block, room_number, phone, parent_phone)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    student_data['reg_number'],
                    student_data['name'],
                    UserModel.hash_password(student_data['password']),
                    student_data['proctor_id'],
                    student_data['hostel_block'],
                    student_data['room_number'],
                    student_data['phone'],
                    student_data['parent_phone']
                ))
                connection.commit()
                print(f"✓ Student {student_data['reg_number']} added successfully")
                return True
        except Exception as e:
            print(f"✗ Error adding student: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            connection.close()
    
    @staticmethod
    def add_supervisor(supervisor_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                # Check if supervisor already exists
                cursor.execute("SELECT * FROM hostel_supervisors WHERE supervisor_id = %s", (supervisor_data['supervisor_id'],))
                if cursor.fetchone():
                    print(f"✗ Supervisor {supervisor_data['supervisor_id']} already exists")
                    return False
                
                sql = """
                    INSERT INTO hostel_supervisors 
                    (supervisor_id, name, password_hash, hostel_block, email)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    supervisor_data['supervisor_id'],
                    supervisor_data['name'],
                    UserModel.hash_password(supervisor_data['password']),
                    supervisor_data['hostel_block'],
                    supervisor_data['email']
                ))
                connection.commit()
                print(f"✓ Supervisor {supervisor_data['supervisor_id']} added successfully")
                return True
        except Exception as e:
            print(f"✗ Error adding supervisor: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            connection.close()
    
    @staticmethod
    def get_user(user_type, user_id):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                if user_type == 'student':
                    cursor.execute("""
                        SELECT s.*, p.name as proctor_name 
                        FROM students s 
                        LEFT JOIN proctors p ON s.proctor_id = p.employee_id 
                        WHERE s.reg_number = %s
                    """, (user_id,))
                elif user_type == 'proctor':
                    cursor.execute("SELECT * FROM proctors WHERE employee_id = %s", (user_id,))
                elif user_type == 'supervisor':
                    cursor.execute("SELECT * FROM hostel_supervisors WHERE supervisor_id = %s", (user_id,))
                elif user_type == 'admin':
                    cursor.execute("SELECT * FROM admins WHERE admin_id = %s", (user_id,))
                else:
                    return None
                
                return cursor.fetchone()
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
        finally:
            connection.close()
    
    @staticmethod
    def update_proctor(employee_id, update_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                if 'password' in update_data and update_data['password']:
                    sql = """
                        UPDATE proctors 
                        SET name = %s, email = %s, department = %s, password_hash = %s
                        WHERE employee_id = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['email'],
                        update_data['department'],
                        UserModel.hash_password(update_data['password']),
                        employee_id
                    ))
                else:
                    sql = """
                        UPDATE proctors 
                        SET name = %s, email = %s, department = %s
                        WHERE employee_id = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['email'],
                        update_data['department'],
                        employee_id
                    ))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating proctor: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def update_student(reg_number, update_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                if 'password' in update_data and update_data['password']:
                    sql = """
                        UPDATE students 
                        SET name = %s, proctor_id = %s, hostel_block = %s, 
                        room_number = %s, phone = %s, parent_phone = %s, password_hash = %s
                        WHERE reg_number = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['proctor_id'],
                        update_data['hostel_block'],
                        update_data['room_number'],
                        update_data['phone'],
                        update_data['parent_phone'],
                        UserModel.hash_password(update_data['password']),
                        reg_number
                    ))
                else:
                    sql = """
                        UPDATE students 
                        SET name = %s, proctor_id = %s, hostel_block = %s, 
                        room_number = %s, phone = %s, parent_phone = %s
                        WHERE reg_number = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['proctor_id'],
                        update_data['hostel_block'],
                        update_data['room_number'],
                        update_data['phone'],
                        update_data['parent_phone'],
                        reg_number
                    ))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating student: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def update_supervisor(supervisor_id, update_data):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                if 'password' in update_data and update_data['password']:
                    sql = """
                        UPDATE hostel_supervisors 
                        SET name = %s, hostel_block = %s, email = %s, password_hash = %s
                        WHERE supervisor_id = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['hostel_block'],
                        update_data['email'],
                        UserModel.hash_password(update_data['password']),
                        supervisor_id
                    ))
                else:
                    sql = """
                        UPDATE hostel_supervisors 
                        SET name = %s, hostel_block = %s, email = %s
                        WHERE supervisor_id = %s
                    """
                    cursor.execute(sql, (
                        update_data['name'],
                        update_data['hostel_block'],
                        update_data['email'],
                        supervisor_id
                    ))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating supervisor: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def reset_password(user_type, user_id, new_password):
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
                    return False
                
                table_name, id_column = table_map[user_type]
                sql = f"UPDATE {table_name} SET password_hash = %s WHERE {id_column} = %s"
                
                cursor.execute(sql, (UserModel.hash_password(new_password), user_id))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error resetting password: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def flag_suspicious(leave_id, admin_id, reason):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                    UPDATE leaves 
                    SET suspicious_flag = TRUE,
                        flagged_by = %s,
                        flag_reason = %s,
                        flagged_at = NOW()
                    WHERE leave_id = %s
                """
                cursor.execute(sql, (admin_id, reason, leave_id))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error flagging suspicious: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def remove_flag(leave_id):
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                    UPDATE leaves 
                    SET suspicious_flag = FALSE,
                        flagged_by = NULL,
                        flag_reason = NULL,
                        flagged_at = NULL
                    WHERE leave_id = %s
                """
                cursor.execute(sql, (leave_id,))
                connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error removing flag: {e}")
            return False
        finally:
            connection.close()
    
    @staticmethod
    def get_all_users():
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                users = []
                
                cursor.execute("SELECT reg_number as id, name, 'student' as type, hostel_block as location FROM students")
                for student in cursor.fetchall():
                    student['role'] = 'Student'
                    users.append(student)
                
                cursor.execute("SELECT employee_id as id, name, 'proctor' as type, department as location FROM proctors")
                for proctor in cursor.fetchall():
                    proctor['role'] = 'Proctor'
                    users.append(proctor)
                
                cursor.execute("SELECT supervisor_id as id, name, 'supervisor' as type, hostel_block as location FROM hostel_supervisors")
                for supervisor in cursor.fetchall():
                    supervisor['role'] = 'Hostel Supervisor'
                    users.append(supervisor)
                
                cursor.execute("SELECT admin_id as id, name, 'admin' as type, role as location FROM admins")
                for admin in cursor.fetchall():
                    admin['role'] = f'Admin ({admin["location"]})'
                    users.append(admin)
                
                return users
        finally:
            connection.close()
    
    @staticmethod
    def log_action(admin_id, action_type, target_type, target_id=None, details=None, request=None):
        """Log admin actions to admin_logs table"""
        db = Database()
        connection = db.get_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                    INSERT INTO admin_logs 
                    (admin_id, action_type, target_type, target_id, details, ip_address, user_agent)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                
                # Get IP address and user agent from request
                ip_address = None
                user_agent = None
                
                if request:
                    # Try to get real IP from various headers
                    if request.headers.get('X-Forwarded-For'):
                        ip_address = request.headers.get('X-Forwarded-For').split(',')[0]
                    elif request.headers.get('X-Real-IP'):
                        ip_address = request.headers.get('X-Real-IP')
                    else:
                        ip_address = request.remote_addr
                    
                    user_agent = request.headers.get('User-Agent')
                
                cursor.execute(sql, (
                    admin_id,
                    action_type,
                    target_type,
                    target_id,
                    details,
                    ip_address,
                    user_agent
                ))
                connection.commit()
                print(f"✓ Logged admin action: {action_type} on {target_type} {target_id}")
                return True
        except Exception as e:
            print(f"✗ Error logging admin action: {e}")
            return False
        finally:
            connection.close()

def create_sample_data():
    db = Database()
    connection = db.get_connection()
    try:
        with connection.cursor() as cursor:
            proctor_password = UserModel.hash_password("proctor123")
            cursor.execute("""
                INSERT IGNORE INTO proctors 
                (employee_id, name, password_hash, email, department)
                VALUES (%s, %s, %s, %s, %s)
            """, ("P001", "Dr. Rajit Nair", proctor_password, "rajit.nair@vit.ac.in", "CSE"))
            
            student_password = UserModel.hash_password("Sparsh123")
            cursor.execute("""
                INSERT IGNORE INTO students 
                (reg_number, name, password_hash, proctor_id, hostel_block, room_number, phone, parent_phone)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ("24BAI10017", "Sparsh Kapoor", student_password, "P001", "A Block", "417", "9876543210", "9876543211"))
            
            student_password2 = UserModel.hash_password("student123")
            cursor.execute("""
                INSERT IGNORE INTO students 
                (reg_number, name, password_hash, proctor_id, hostel_block, room_number, phone, parent_phone)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ("21BCE1001", "John Doe", student_password2, "P001", "B Block", "101", "9876543212", "9876543213"))
            
            supervisor_password = UserModel.hash_password("supervisor123")
            cursor.execute("""
                INSERT IGNORE INTO hostel_supervisors 
                (supervisor_id, name, password_hash, hostel_block, email)
                VALUES (%s, %s, %s, %s, %s)
            """, ("S001", "Mr. Kumar", supervisor_password, "A Block", "kumar@vit.ac.in"))
            
            cursor.execute("""
                INSERT IGNORE INTO hostel_supervisors 
                (supervisor_id, name, password_hash, hostel_block, email)
                VALUES (%s, %s, %s, %s, %s)
            """, ("S002", "Mrs. Sharma", supervisor_password, "B Block", "sharma@vit.ac.in"))
            
            for i in range(3):
                qr_token_test = UserModel.generate_qr_token()
                qr_expiry_test = datetime.now() + timedelta(hours=24)
                
                cursor.execute("""
                    INSERT IGNORE INTO leaves 
                    (student_reg, proctor_id, leave_type, from_date, to_date, from_time, to_time, 
                     reason, destination, parent_contacted, status, approved_at, qr_token, qr_expiry)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s)
                """, ("24BAI10017", "P001", "regular", 
                      (datetime.now() + timedelta(days=i)).date(), 
                      (datetime.now() + timedelta(days=i+1)).date(),
                      "10:00:00", "18:00:00",
                      f"Test leave {i+1}", f"City {i+1}", True,
                      "approved", qr_token_test, qr_expiry_test))
                
                print(f"✓ Created test leave {i+1} with QR token: {qr_token_test}")
            
            admin_password = UserModel.hash_password("Admin@123")
            cursor.execute("""
                INSERT IGNORE INTO admins 
                (admin_id, name, password_hash, email, role)
                VALUES (%s, %s, %s, %s, %s)
            """, ("ADMIN001", "System Administrator", admin_password, "admin@vit.ac.in", "super_admin"))
            
            cursor.execute("""
                INSERT IGNORE INTO admins 
                (admin_id, name, password_hash, email, role)
                VALUES (%s, %s, %s, %s, %s)
            """, ("ADMIN002", "Hostel Admin", admin_password, "hostel.admin@vit.ac.in", "admin"))
            
            connection.commit()
            print("\n✓ Sample data created successfully!")
            print("✓ Student: 24BAI10017 - Sparsh Kapoor (Password: Sparsh123)")
            print("✓ Proctor: P001 - Dr. Rajit Nair (Password: proctor123)")
            print("✓ Hostel Supervisor: S001 - Mr. Kumar (Password: supervisor123)")
            print("✓ Admin: ADMIN001 / Admin@123")
            print("✓ Admin: ADMIN002 / Admin@123")
            print("\n✓ Multiple test leaves created for testing verification")
    except Exception as e:
        print(f"✗ Error creating sample data: {e}")
        import traceback
        traceback.print_exc()
    finally:
        connection.close()