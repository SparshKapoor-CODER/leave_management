# VIT Leave Management System

A comprehensive web-based leave management system for VIT (Vellore Institute of Technology) that enables students to apply for leaves, proctors to approve them, and hostel supervisors to verify leaves using QR codes.

## Features

### 🎓 Student Portal
- Apply for regular and emergency leaves
- View leave history and status
- Receive QR codes for approved leaves
- Track leave applications in real-time

### 👨‍🏫 Proctor Portal
- Review pending leave applications
- Approve or reject student leaves
- View student details and leave history
- Generate secure QR codes for approved leaves

### 🏨 Hostel Supervisor Portal
- Verify student leaves using QR code scanning
- View student and leave details upon verification
- Track verification logs
- Manage hostel block permissions

### 🔧 Admin Portal
- Comprehensive dashboard with system statistics
- User management (students, proctors, supervisors)
- Leave monitoring and filtering
- Flag suspicious activities
- System-wide logs and audit trails
- Password reset functionality

## Tech Stack

- **Backend**: Python Flask
- **Database**: MySQL
- **Authentication**: Bcrypt password hashing
- **QR Code**: Python qrcode library
- **Frontend**: HTML, CSS (Bootstrap), JavaScript
- **PDF Generation**: Custom PDF generator for permission slips

## Installation

### Prerequisites
- Python 3.7+
- MySQL Server 8.0+
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd leave_management
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure database connection**
   
   Edit `database.py` and update the MySQL connection details:
   ```python
   'host': 'localhost',
   'user': 'your_mysql_username',
   'password': 'your_mysql_password',
   'database': 'leave_management'
   ```

4. **Initialize the database**
   ```bash
   python init_db.py
   ```
   This will:
   - Create all required tables
   - Set up proper schema
   - Insert sample data

5. **Run the application**
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:5000`

## Default Login Credentials

### Student
- Registration Number: `24BAI10017`
- Password: `Sparsh123`

### Proctor
- Employee ID: `P001`
- Password: `proctor123`

### Hostel Supervisor
- Supervisor ID: `S001`
- Password: `supervisor123`

### Admin
- Admin ID: `ADMIN001`
- Password: `Admin@123`

> **⚠️ Important**: Change these default passwords after first login in a production environment.

## Project Structure

```
leave_management/
├── app.py                      # Main Flask application
├── models.py                   # Database models and business logic
├── database.py                 # Database connection handler
├── db_migration.py             # Database migration and schema versioning utility
├── pdf_generator.py            # Permission slip PDF generator
├── init_db.py                  # Database initialization script
├── create_database.py          # Database creation utility
├── generate_key.py             # Secret key generator
├── requirements.txt            # Python dependencies
├── templates/                  # HTML templates
│   ├── admin_dashboard.html
│   ├── admin_leaves.html
│   ├── admin_login.html
│   ├── admin_logs.html
│   ├── admin_users.html
│   ├── apply_leave.html
│   ├── base.html
│   ├── hostel_login.html
│   ├── hostel_verify.html
│   ├── index.html
│   ├── permission_slip.html
│   ├── proctor_dashboard.html
│   ├── proctor_login.html
│   ├── student_dashboard.html
│   └── student_login.html
├── static/
    ├── download.jpg
    ├── File_VIT_Bhopal_logo.png
    └── images.jpg
└── __pycache__/                # Python cache files
```

## Database Schema

### Tables
- **students**: Student information and credentials
- **proctors**: Proctor/faculty information
- **hostel_supervisors**: Hostel supervisor details
- **admins**: System administrator accounts
- **leaves**: Leave applications and approvals
- **verification_logs**: QR code verification history
- **admin_logs**: Admin action audit trail

## Usage

### Student Workflow
1. Login with registration number and password
2. Navigate to "Apply for Leave"
3. Fill in leave details (type, dates, reason, destination)
4. Submit application
5. Wait for proctor approval
6. Download QR code and permission slip once approved
7. Show QR code to hostel supervisor when leaving

### Proctor Workflow
1. Login with employee ID and password
2. View pending leave requests
3. Review student details and leave information
4. Approve or reject applications
5. System generates QR code for approved leaves

### Hostel Supervisor Workflow
1. Login with supervisor ID and password
2. Scan or enter QR code from student's permission slip
3. Verify leave details and validity
4. Grant or deny exit based on verification

### Admin Workflow
1. Login with admin credentials
2. Monitor system statistics on dashboard
3. Manage users (add, edit, delete, reset passwords)
4. Review and filter leave applications
5. Flag suspicious activities
6. View comprehensive system logs

## Security Features

- Bcrypt password hashing
- Session-based authentication
- QR code expiry (24 hours default)
- Verification count tracking
- Suspicious activity flagging
- Admin action logging with IP tracking
- Protected routes with role-based access

## Development

### Running Tests
```bash
python test_login.py
python test_admin_features.py
python test_mysql.py
```

### Database Updates
If schema changes are needed:
```bash
python update_schema.py
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is developed for VIT internal use.

## Support

For issues or questions, please contact the system administrator.

---

**Note**: This system is designed specifically for VIT's leave management requirements and may need customization for other institutions.
