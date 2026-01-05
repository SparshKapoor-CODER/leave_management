# db_migration.py
from database import Database
import traceback

def run_migrations():
    print("\n" + "="*60)
    print("RUNNING DATABASE MIGRATIONS")
    print("="*60)
    
    db = Database()
    connection = db.get_connection()
    
    try:
        with connection.cursor() as cursor:
            # Add verified_at column to leaves table if it doesn't exist
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'leaves' 
                AND COLUMN_NAME = 'verified_at'
            """, (db.database,))
            
            if not cursor.fetchone():
                print("Adding 'verified_at' column to leaves table...")
                cursor.execute("ALTER TABLE leaves ADD COLUMN verified_at TIMESTAMP NULL DEFAULT NULL")
                print("✓ Added 'verified_at' column")
            
            # Add suspicious_flag column to leaves table if it doesn't exist
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'leaves' 
                AND COLUMN_NAME = 'suspicious_flag'
            """, (db.database,))
            
            if not cursor.fetchone():
                print("Adding 'suspicious_flag' column to leaves table...")
                cursor.execute("ALTER TABLE leaves ADD COLUMN suspicious_flag BOOLEAN DEFAULT FALSE")
                print("✓ Added 'suspicious_flag' column")
            
            # Add parent_contacted column to leaves table if it doesn't exist
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'leaves' 
                AND COLUMN_NAME = 'parent_contacted'
            """, (db.database,))
            
            if not cursor.fetchone():
                print("Adding 'parent_contacted' column to leaves table...")
                cursor.execute("ALTER TABLE leaves ADD COLUMN parent_contacted BOOLEAN DEFAULT FALSE")
                print("✓ Added 'parent_contacted' column")
            
            # Create missing tables
            tables_sql = [
                """
                CREATE TABLE IF NOT EXISTS admin_leave_flags (
                    flag_id INT AUTO_INCREMENT PRIMARY KEY,
                    leave_id INT NOT NULL,
                    flagged_by VARCHAR(50) NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (leave_id) REFERENCES leaves(leave_id) ON DELETE CASCADE,
                    FOREIGN KEY (flagged_by) REFERENCES admins(admin_id) ON DELETE CASCADE
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS parent_contacts (
                    contact_id INT AUTO_INCREMENT PRIMARY KEY,
                    leave_id INT NOT NULL,
                    contact_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    method VARCHAR(50),
                    confirmation_code VARCHAR(100),
                    notes TEXT,
                    FOREIGN KEY (leave_id) REFERENCES leaves(leave_id) ON DELETE CASCADE
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS leave_audit_log (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    leave_id INT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    performed_by VARCHAR(100) NOT NULL,
                    performed_by_type VARCHAR(50) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    FOREIGN KEY (leave_id) REFERENCES leaves(leave_id) ON DELETE CASCADE
                )
                """
            ]
            
            for sql in tables_sql:
                cursor.execute(sql)
            
            connection.commit()
            print("\n" + "="*60)
            print("✓ ALL MIGRATIONS COMPLETED SUCCESSFULLY!")
            print("="*60)
            
    except Exception as e:
        print(f"✗ Error running migrations: {e}")
        traceback.print_exc()
        connection.rollback()
    finally:
        connection.close()

if __name__ == "__main__":
    run_migrations()