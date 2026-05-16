import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv
import bcrypt
import traceback

load_dotenv('.env')

class Database:
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.user = os.getenv('DB_USER', 'postgres')
        self.password = os.getenv('DB_PASSWORD', '')
        self.database = os.getenv('DB_NAME', 'vit_leave_management')
        self.port = int(os.getenv('DB_PORT', 5432))
        
        print("\n" + "="*60)
        print("DATABASE CONNECTION DETAILS:")
        print(f"Host: {self.host}")
        print(f"Port: {self.port}")
        print(f"User: {self.user}")
        print(f"Database: {self.database}")
        print("="*60 + "\n")
        
    def get_connection(self):
        """Get PostgreSQL connection"""
        try:
            connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                connect_timeout=10
            )
            connection.set_session(autocommit=True)
            print("✓ Database connection successful!")
            return connection
            
        except psycopg2.OperationalError as e:
            print(f"\n✗ Database connection FAILED!")
            print(f"Error: {e}")
            print(f"\nConnection attempted:")
            print(f"  Host: {self.host}:{self.port}")
            print(f"  User: {self.user}")
            print(f"  Database: {self.database}")
            print("="*60 + "\n")
            raise
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            traceback.print_exc()
            raise
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def check_password(hashed_password, password):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            print(f"Password check error: {e}")
            return False
    
    def init_db(self):
        """Initialize database - create tables if they don't exist"""
        connection = None
        try:
            connection = self.get_connection()
            with connection.cursor() as cursor:
                
                # Create students table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS students (
                        reg_number VARCHAR(20) PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        proctor_id VARCHAR(20) NOT NULL,
                        hostel_block VARCHAR(10) NOT NULL,
                        room_number VARCHAR(10) NOT NULL,
                        phone VARCHAR(15),
                        parent_phone VARCHAR(15)
                    )
                ''')
                print("✓ Created 'students' table")
                
                # Create proctors table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS proctors (
                        employee_id VARCHAR(20) PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        email VARCHAR(100),
                        department VARCHAR(100)
                    )
                ''')
                print("✓ Created 'proctors' table")
                
                # Create leaves table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS leaves (
                        leave_id SERIAL PRIMARY KEY,
                        student_reg VARCHAR(20) NOT NULL,
                        proctor_id VARCHAR(20) NOT NULL,
                        leave_type VARCHAR(20) NOT NULL,
                        from_date DATE NOT NULL,
                        to_date DATE NOT NULL,
                        from_time TIME NOT NULL,
                        to_time TIME NOT NULL,
                        reason TEXT NOT NULL,
                        destination VARCHAR(200),
                        parent_contacted BOOLEAN DEFAULT FALSE,
                        status VARCHAR(20) DEFAULT 'pending',
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        approved_at TIMESTAMP NULL,
                        qr_token VARCHAR(100) UNIQUE,
                        qr_expiry TIMESTAMP NULL,
                        verification_count INT DEFAULT 0,
                        suspicious_flag BOOLEAN DEFAULT FALSE,
                        flagged_by VARCHAR(50),
                        flag_reason TEXT,
                        flagged_at TIMESTAMP NULL
                    )
                ''')
                print("✓ Created 'leaves' table")
                
                # Create hostel_supervisors table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS hostel_supervisors (
                        supervisor_id VARCHAR(20) PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        hostel_block VARCHAR(10) NOT NULL,
                        email VARCHAR(100)
                    )
                ''')
                print("✓ Created 'hostel_supervisors' table")

                # Create admins table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS admins (
                        admin_id VARCHAR(20) PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        email VARCHAR(100),
                        role VARCHAR(50) DEFAULT 'admin',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                print("✓ Created 'admins' table")

                # Create verification_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS verification_logs (
                        log_id SERIAL PRIMARY KEY,
                        leave_id INT,
                        supervisor_id VARCHAR(20),
                        verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        action VARCHAR(50) NOT NULL,
                        notes TEXT
                    )
                ''')
                print("✓ Created 'verification_logs' table")

                # Create admin_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS admin_logs (
                        log_id SERIAL PRIMARY KEY,
                        admin_id VARCHAR(20) NOT NULL,
                        action_type VARCHAR(50) NOT NULL,
                        target_type VARCHAR(50) NOT NULL,
                        target_id VARCHAR(50),
                        details TEXT,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                print("✓ Created 'admin_logs' table")

                # Create admin_leave_flags table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS admin_leave_flags (
                        flag_id SERIAL PRIMARY KEY,
                        leave_id INT NOT NULL,
                        flagged_by VARCHAR(50) NOT NULL,
                        reason TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                print("✓ Created 'admin_leave_flags' table")

                # Create parent_contacts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS parent_contacts (
                        contact_id SERIAL PRIMARY KEY,
                        leave_id INT NOT NULL,
                        contact_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        method VARCHAR(50),
                        confirmation_code VARCHAR(100),
                        notes TEXT
                    )
                ''')
                print("✓ Created 'parent_contacts' table")

                # Create leave_audit_log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS leave_audit_log (
                        log_id SERIAL PRIMARY KEY,
                        leave_id INT NOT NULL,
                        action VARCHAR(50) NOT NULL,
                        performed_by VARCHAR(100) NOT NULL,
                        performed_by_type VARCHAR(50) NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        notes TEXT
                    )
                ''')
                print("✓ Created 'leave_audit_log' table")

                # Create blocked_ips table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        block_id SERIAL PRIMARY KEY,
                        ip_address VARCHAR(45) NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        blocked_by VARCHAR(20) NOT NULL,
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE,
                        unblocked_by VARCHAR(20),
                        unblocked_at TIMESTAMP NULL,
                        notes TEXT
                    )
                ''')
                print("✓ Created 'blocked_ips' table")
                
                print("\n" + "="*60)
                print("ALL TABLES CREATED SUCCESSFULLY!")
                print("="*60 + "\n")
                return True
                
        except Exception as e:
            print(f"✗ Error creating tables: {e}")
            traceback.print_exc()
            return False
        finally:
            if connection:
                connection.close()