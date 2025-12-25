# [file name]: database.py
import pymysql
import os
from dotenv import load_dotenv
import bcrypt

# Load environment variables
load_dotenv('.env')  # Load from DB.env file

class Database:
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.user = os.getenv('DB_USER', 'root')
        self.password = os.getenv('DB_PASSWORD', '')
        self.database = os.getenv('DB_NAME', 'vit_leave_management')
        self.port = int(os.getenv('DB_PORT', 3306))
        
        # Debug: Show connection details
        print("\n" + "="*50)
        print("DATABASE CONNECTION DETAILS:")
        print(f"Host: {self.host}")
        print(f"User: {self.user}")
        print(f"Password: {'*' * len(self.password) if self.password else '(empty)'}")
        print(f"Database: {self.database}")
        print(f"Port: {self.port}")
        print("="*50 + "\n")
        
    def get_connection(self):
        try:
            connection = pymysql.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                port=self.port,
                cursorclass=pymysql.cursors.DictCursor,
                charset='utf8mb4'
            )
            print("✓ Database connection successful!")
            return connection
        except pymysql.err.OperationalError as e:
            print(f"✗ Database connection failed: {e}")
            print("\nTroubleshooting:")
            print("1. Check if MySQL service is running")
            print("2. Verify password in DB.env file")
            print("3. Try connecting with: mysql -u root -p")
            raise
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def check_password(hashed_password, password):
        try:
            # FIXED: bcrypt.checkpw expects (password_to_check, hashed_password)
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            print(f"Password check error: {e}")
            return False
    
    def init_db(self):
        connection = None
        try:
            connection = self.get_connection()
            with connection.cursor() as cursor:
                # Create database if not exists
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
                cursor.execute(f"USE {self.database}")
                
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
                        leave_id INT AUTO_INCREMENT PRIMARY KEY,
                        student_reg VARCHAR(20) NOT NULL,
                        proctor_id VARCHAR(20) NOT NULL,
                        leave_type ENUM('emergency', 'regular', 'medical') NOT NULL,
                        from_date DATE NOT NULL,
                        to_date DATE NOT NULL,
                        from_time TIME NOT NULL,
                        to_time TIME NOT NULL,
                        reason TEXT NOT NULL,
                        destination VARCHAR(200),
                        parent_contacted BOOLEAN DEFAULT FALSE,
                        status ENUM('pending', 'approved', 'rejected', 'completed') DEFAULT 'pending',
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
                        role ENUM('super_admin', 'admin', 'moderator') DEFAULT 'admin',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                print("✓ Created 'admins' table")

                # Create verification_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS verification_logs (
                        log_id INT AUTO_INCREMENT PRIMARY KEY,
                        leave_id INT,
                        supervisor_id VARCHAR(20),
                        verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        action ENUM('granted', 'rejected', 'suspicious', 'flagged') NOT NULL,
                        notes TEXT
                    )
                ''')
                print("✓ Created 'verification_logs' table")

                # Create admin_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS admin_logs (
                        log_id INT AUTO_INCREMENT PRIMARY KEY,
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
                
                connection.commit()
                print("\n" + "="*50)
                print("ALL TABLES CREATED SUCCESSFULLY!")
                print("="*50 + "\n")
                
        except Exception as e:
            print(f"✗ Error creating tables: {e}")
            raise
        finally:
            if connection:
                connection.close()