# [file name]: create_database.py
import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env')

def create_database():
    # Get connection parameters
    host = os.getenv('DB_HOST', 'localhost')
    user = os.getenv('DB_USER', 'root')
    password = os.getenv('DB_PASSWORD', '')
    database = os.getenv('DB_NAME', 'vit_leave_management')
    port = int(os.getenv('DB_PORT', 3306))
    
    print("="*50)
    print("CREATING DATABASE...")
    print(f"Host: {host}")
    print(f"User: {user}")
    print(f"Database: {database}")
    print("="*50)
    
    try:
        # Connect without specifying database (to create it)
        connection = pymysql.connect(
            host=host,
            user=user,
            password=password,
            port=port,
            charset='utf8mb4'
        )
        
        with connection.cursor() as cursor:
            # Create database
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
            cursor.execute(f"USE {database}")
            print(f"✓ Database '{database}' created successfully!")
            
            # Create tables using the schema from database.py
            # First, let's just create the database and basic tables
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
            
            # Add the additional tables that were missing
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
        print("DATABASE AND TABLES CREATED SUCCESSFULLY!")
        print("="*50 + "\n")
        
        return True
        
    except pymysql.err.OperationalError as e:
        print(f"✗ Error: {e}")
        print("\nTroubleshooting steps:")
        print("1. Make sure MySQL is running: mysql -u root -p")
        print("2. Check your password in .env file")
        print("3. Try creating the database manually:")
        print(f"   CREATE DATABASE {database};")
        print(f"   USE {database};")
        return False
    finally:
        if 'connection' in locals():
            connection.close()

if __name__ == '__main__':
    create_database()