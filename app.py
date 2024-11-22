from flask import Flask, request, redirect, url_for, session
import bcrypt
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Set, Dict, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import jwt

app = Flask(__name__)
app.secret_key = os.urandom(24)

import bcrypt

users_db = {
    "john_doe": {
        "username": "john_doe",
        "password": bcrypt.hashpw("password_123".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "super_admin",
        "department": "Computer Science"
    },
    "jane_smith": {
        "username": "jane_smith",
        "password": bcrypt.hashpw("password_456".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "chair_csm",
        "department": "Computer Science"
    },
    "prof_james": {
        "username": "prof_james",
        "password": bcrypt.hashpw("password_789".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "professor_csm",
        "department": "Computer Science"
    },
    "assoc_prof_anna": {
        "username": "assoc_prof_anna",
        "password": bcrypt.hashpw("password_101".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "assoc_prof_csm",
        "department": "Computer Science"
    },
    "ta_luke": {
        "username": "ta_luke",
        "password": bcrypt.hashpw("password_112".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "ta_csm",
        "department": "Computer Science"
    },
    "ra_emily": {
        "username": "ra_emily",
        "password": bcrypt.hashpw("password_131".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "ra_csm",
        "department": "Computer Science"
    },
    "student_mike": {
        "username": "student_mike",
        "password": bcrypt.hashpw("password_415".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "student_csm",
        "department": "Computer Science"
    },
    "student_anna": {
        "username": "student_anna",
        "password": bcrypt.hashpw("password_161".encode('utf-8'), bcrypt.gensalt()),  # Storing hashed password as bytes
        "role": "student_eng",
        "department": "Engineering"
    }
}


failed_attempts = {}
lockout_duration = timedelta(minutes=15)
temp_passwords = {}  # Store temporary passwords for first-time logins

# RBAC Implementation
class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    APPROVE = "approve"
    ADMIN = "admin"
    GRADE = "grade"
    ENROLL = "enroll"
    TEACH = "teach"
    RESEARCH = "research"
    PUBLISH = "publish"

class Department(Enum):
    CSM = "Computer Science and Mathematics"
    ENG = "Engineering"
    BUS = "Business"
    SCI = "Sciences"
    HUM = "Humanities"

class Role:
    def __init__(self, name: str, permissions: Set[Permission], department: Department = None):
        self.name = name
        self.permissions = permissions
        self.department = department
        self.parent = None
        self.children = []

    def add_child(self, child_role):
        self.children.append(child_role)
        child_role.parent = self

    def has_permission(self, permission: Permission) -> bool:
        if permission in self.permissions:
            return True
        if self.parent:
            return self.parent.has_permission(permission)
        return False

class RBACSystem:
    def __init__(self):
        self.roles = {}
        self.setup_roles()

    def setup_roles(self):
        # Top level roles
        self.roles['super_admin'] = Role('super_admin', {p for p in Permission})

        # Department Chairs
        self.roles['chair_csm'] = Role('chair_csm',
            {Permission.APPROVE, Permission.ADMIN, Permission.RESEARCH}, Department.CSM)
        self.roles['chair_eng'] = Role('chair_eng',
            {Permission.APPROVE, Permission.ADMIN, Permission.RESEARCH}, Department.ENG)

        # Professors
        self.roles['professor_csm'] = Role('professor_csm',
            {Permission.TEACH, Permission.GRADE, Permission.RESEARCH}, Department.CSM)
        self.roles['professor_eng'] = Role('professor_eng',
            {Permission.TEACH, Permission.GRADE, Permission.RESEARCH}, Department.ENG)

        # Associate Professors
        self.roles['assoc_prof_csm'] = Role('assoc_prof_csm',
            {Permission.TEACH, Permission.GRADE}, Department.CSM)
        self.roles['assoc_prof_eng'] = Role('assoc_prof_eng',
            {Permission.TEACH, Permission.GRADE}, Department.ENG)

        # Teaching Assistants
        self.roles['ta_csm'] = Role('ta_csm',
            {Permission.GRADE}, Department.CSM)
        self.roles['ta_eng'] = Role('ta_eng',
            {Permission.GRADE}, Department.ENG)

        # Research Assistants
        self.roles['ra_csm'] = Role('ra_csm',
            {Permission.RESEARCH}, Department.CSM)
        self.roles['ra_eng'] = Role('ra_eng',
            {Permission.RESEARCH}, Department.ENG)

        # Students
        self.roles['student_csm'] = Role('student_csm',
            {Permission.ENROLL}, Department.CSM)
        self.roles['student_eng'] = Role('student_eng',
            {Permission.ENROLL}, Department.ENG)

        # Set up hierarchy
        self.roles['super_admin'].add_child(self.roles['chair_csm'])
        self.roles['super_admin'].add_child(self.roles['chair_eng'])

        self.roles['chair_csm'].add_child(self.roles['professor_csm'])
        self.roles['chair_eng'].add_child(self.roles['professor_eng'])

        self.roles['professor_csm'].add_child(self.roles['assoc_prof_csm'])
        self.roles['professor_eng'].add_child(self.roles['assoc_prof_eng'])

        self.roles['assoc_prof_csm'].add_child(self.roles['ta_csm'])
        self.roles['assoc_prof_eng'].add_child(self.roles['ta_eng'])

        self.roles['ta_csm'].add_child(self.roles['ra_csm'])
        self.roles['ta_eng'].add_child(self.roles['ra_eng'])

        self.roles['ra_csm'].add_child(self.roles['student_csm'])
        self.roles['ra_eng'].add_child(self.roles['student_eng'])

# Cryptographic implementations
class AESCipher:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt(self, data: str) -> bytes:
        return self.cipher_suite.encrypt(data.encode())

    def decrypt(self, encrypted_data: bytes) -> str:
        return self.cipher_suite.decrypt(encrypted_data).decode()

class RSACipher:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message: bytes) -> bytes:
        encrypted = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt(self, encrypted_message: bytes) -> bytes:
        original_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message

# Initialize the systems
rbac_system = RBACSystem()
aes_cipher = AESCipher()
rsa_cipher = RSACipher()

# Create default super admin account
default_admin_password = "SuperAdmin123!@#"
hashed_admin_password = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt())
users_db['admin'] = {
    'password': hashed_admin_password,
    'role': 'super_admin',
    'department': None  # Super admin isn't restricted to a department
}

def is_account_locked(username):
    if username in failed_attempts:
        attempts, lockout_time = failed_attempts[username]
        if attempts >= 3 and datetime.now() < lockout_time:
            return True
    return False

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>Secure App</title>
            <style>
                body {
                    font-family: Arial;
                    margin: 40px;
                    background: #f0f0f0;
                }
                .container {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    max-width: 600px;
                    margin: 0 auto;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                }
                input, select {
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    background: #007bff;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                button:hover {
                    background: #0056b3;
                }
                .error {
                    color: red;
                    margin-bottom: 10px;
                }
                .success {
                    color: green;
                    margin-bottom: 10px;
                }
                .nav {
                    margin-bottom: 20px;
                }
                .nav a {
                    color: #007bff;
                    text-decoration: none;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="nav">
                    <a href="/login">Login</a> |
                    <a href="/register">Register</a>
                </div>
                <h1>Welcome to Secure App</h1>
                <p>Please login or register to continue.</p>
            </div>
        </body>
    </html>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users_db:
            if is_account_locked(username):
                return "Account is locked. Please try again later."

            stored_password = users_db[username]['password']

            # Check if user needs to change password
            if username in temp_passwords:
                if password == temp_passwords[username]:
                    return redirect(url_for('change_password', username=username))

            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['username'] = username
                session['role'] = users_db[username]['role']
                session['department'] = users_db[username].get('department', 'None')

                if username in failed_attempts:
                    del failed_attempts[username]

                return redirect('/dashboard')
            else:
                if username not in failed_attempts:
                    failed_attempts[username] = [1, datetime.now() + lockout_duration]
                else:
                    attempts, lockout_time = failed_attempts[username]
                    failed_attempts[username] = [attempts + 1, datetime.now() + lockout_duration]

                return "Invalid credentials"
        return "Invalid credentials"

    return """
    <html>
        <head>
            <title>Login - Secure App</title>
            <style>
                body {
                    font-family: Arial;
                    margin: 40px;
                    background: #f0f0f0;
                }
                .container {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    max-width: 400px;
                    margin: 0 auto;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                }
                input {
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    background: #007bff;
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                }
                button:hover {
                    background: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Login</h1>
                <form method="POST">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
    </html>
    """

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    username = request.args.get('username')

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return "Passwords do not match!"

        if len(new_password) < 12:
            return "Password must be at least 12 characters long!"

        # Update the password in the database
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users_db[username]['password'] = hashed

        # Remove temporary password
        if username in temp_passwords:
            del temp_passwords[username]

        # Log the user in
        session['username'] = username
        session['role'] = users_db[username]['role']
        session['department'] = users_db[username].get('department', 'None')

        return redirect('/dashboard')

    return """
    <html>
        <head>
            <title>Change Password - Secure App</title>
            <style>
                /* ... (same styles as login page) ... */
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Change Password</h1>
                <p>Please set your new password</p>
                <form method="POST">
                    <div class="form-group">
                        <label>New Password:</label>
                        <input type="password" name="new_password" required>
                    </div>
                    <div class="form-group">
                        <label>Confirm Password:</label>
                        <input type="password" name="confirm_password" required>
                    </div>
                    <button type="submit">Change Password</button>
                </form>
            </div>
        </body>
    </html>
    """

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')

        if username in users_db:
            return """
                <html>
                    <head><title>Error</title></head>
                    <body>
                        <div class="container">
                            <p class="error">Username already exists</p>
                            <a href="/register">Try Again</a>
                        </div>
                    </body>
                </html>
            """

        # Password strength check
        if len(password) < 12:
            return """
                <html>
                    <head><title>Error</title></head>
                    <body>
                        <div class="container">
                            <p class="error">Password must be at least 12 characters long</p>
                            <a href="/register">Try Again</a>
                        </div>
                    </body>
                </html>
            """

        # Hash password with bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create role key based on department
        role_key = f"{role}_{department.lower()}"
        if role_key not in rbac_system.roles:
            return """
                <html>
                    <head><title>Error</title></head>
                    <body>
                        <div class="container">
                            <p class="error">Invalid role/department combination</p>
                            <a href="/register">Try Again</a>
                        </div>
                    </body>
                </html>
            """

        users_db[username] = {
            'password': hashed,
            'role': role_key,
            'department': department
        }

        return redirect('/login')

    return """
    <html>
        <head>
            <title>Register - Secure App</title>
            <style>
                body {
                    font-family: Arial;
                    margin: 40px;
                    background: #f0f0f0;
                }
                .container {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    max-width: 600px;
                    margin: 0 auto;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                }
                input, select {
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    background: #007bff;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                button:hover {
                    background: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Register</h1>
                <form method="POST" action="/register">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" name="password" required>
                        <small>Password must be at least 12 characters long</small>
                    </div>
                    <div class="form-group">
                        <label>Department:</label>
                        <select name="department" required>
                            <option value="CSM">Computer Science and Mathematics</option>
                            <option value="ENG">Engineering</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Role:</label>
                        <select name="role" required>
                            <option value="student">Student</option>
                            <option value="professor">Professor</option>
                            <option value="chair">Department Chair</option>
                        </select>
                    </div>
                    <button type="submit">Register</button>
                </form>
                <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
        </body>
    </html>
    """

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    username = session.get('username')
    role = session.get('role')
    department = session.get('department')

    return f"""
    <html>
        <head>
            <title>Dashboard - {role}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f0f2f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .user-info {{
                    display: flex;
                    flex-direction: column;
                    gap: 5px;
                }}
                .role-badge {{
                    background: #e3f2fd;
                    color: #1976d2;
                    padding: 5px 10px;
                    border-radius: 4px;
                    font-size: 0.9em;
                    display: inline-block;
                }}
                .department-badge {{
                    background: #e8f5e9;
                    color: #2e7d32;
                    padding: 5px 10px;
                    border-radius: 4px;
                    font-size: 0.9em;
                    display: inline-block;
                }}
                .feature-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    padding: 20px 0;
                }}
                .feature-card {{
                    background: white;
                    border-radius: 8px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }}
                .feature-card:hover {{
                    transform: translateY(-5px);
                }}
                .feature-card h3 {{
                    margin: 0 0 10px 0;
                    color: #1a237e;
                }}
                .feature-card p {{
                    color: #666;
                    margin: 0 0 15px 0;
                }}
                .button {{
                    display: inline-block;
                    background: #1976d2;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 4px;
                    text-decoration: none;
                    transition: background 0.2s;
                }}
                .button:hover {{
                    background: #1565c0;
                }}
                .logout-button {{
                    background: #dc3545;
                }}
                .logout-button:hover {{
                    background: #c82333;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="user-info">
                        <h1>Welcome, {username}</h1>
                        <div>
                            <span class="role-badge">Role: {role}</span>
                            <span class="department-badge">Department: {department}</span>
                        </div>
                    </div>
                    <a href="/logout" class="button logout-button">Logout</a>
                </div>
                <div class="feature-grid">
                    {generate_role_features(role, department)}
                </div>
            </div>
        </body>
    </html>
    """

def generate_role_features(role: str, department: str) -> str:
    features = []

    # Super Admin
    if role == 'super_admin':
        features = [
            ("User Management", "Manage all users and their roles", "/users"),
            ("System Logs", "View security and access logs", "/logs"),
            ("Role Management", "Modify role permissions", "/roles"),
            ("Department Overview", "View all department statistics", "/departments"),
            ("Security Settings", "Configure system security", "/security"),
            ("Audit Trail", "View system audit logs", "/audit"),
            ("Database Backup", "Manage database backups", "/database/backup"),
            ("System Configuration", "Configure global system settings", "/system/config")
        ]

    # Department Chairs (Chair CSM and Chair ENG)
    elif role.startswith('chair'):
        features = [
            ("Department Staff", f"Manage {department} faculty", "/staff"),
            ("Course Approval", f"Review and approve {department} courses", "/courses/approve"),
            ("Budget Management", f"Manage {department} budget", "/budget"),
            ("Faculty Evaluation", f"Review {department} faculty performance", "/evaluations"),
            ("Department Reports", f"View {department} statistics", "/reports"),
            ("Research Projects", f"Oversee {department} research", "/research")
        ]

    # Professors (Professor CSM and Professor ENG)
    elif role.startswith('professor'):
        features = [
            ("Classroom Dashboard", "View and manage class information", "/dashboard"),
            ("Student Grades", "Enter and review student grades", "/grades"),
            ("Assignments", "Create and grade assignments", "/assignments"),
            ("Course Materials", "Upload and manage course materials", "/materials"),
            ("Student Attendance", "Track and manage student attendance", "/attendance"),
            ("Communication Tools", "Send announcements and communicate with students", "/communication"),
            ("Exam Scheduling", "Schedule and manage exams", "/exams")
        ]

    # Associate Professors (Assoc Prof CSM and Assoc Prof ENG)
    elif role.startswith('assoc_prof'):
        features = [
            ("Classroom Dashboard", "View and manage class information", "/dashboard"),
            ("Student Grades", "Enter and review student grades", "/grades"),
            ("Assignments", "Create and grade assignments", "/assignments"),
            ("Course Materials", "Upload and manage course materials", "/materials"),
            ("Student Attendance", "Track and manage student attendance", "/attendance"),
            ("Communication Tools", "Send announcements and communicate with students", "/communication")
        ]

    # Teaching Assistants (TA CSM and TA ENG)
    elif role.startswith('ta'):
        features = [
            ("Grading Dashboard", "Assist with grading student assignments", "/grades"),
            ("Student Communication", "Communicate with students regarding assignments", "/communication"),
            ("Course Materials", "Access and review course materials", "/materials"),
            ("Assignment Submissions", "Review student submissions and provide feedback", "/assignments/review")
        ]

    # Research Assistants (RA CSM and RA ENG)
    elif role.startswith('ra'):
        features = [
            ("Research Projects", "Assist with ongoing research projects", "/research"),
            ("Data Collection", "Collect and manage research data", "/research/data"),
            ("Research Collaboration", "Collaborate with other researchers", "/research/collaboration"),
            ("Research Reports", "Prepare and submit research findings", "/research/reports")
        ]

    # Students (Student CSM and Student ENG)
    elif role.startswith('student'):
        features = [
            ("Course Enrollment", "Enroll in available courses", "/enroll"),
            ("View Grades", "View your grades and performance", "/grades/view"),
            ("Assignments", "View and submit assignments", "/assignments/view"),
            ("Course Materials", "Access course materials uploaded by instructors", "/materials/view"),
            ("Course Calendar", "Check your course schedule and deadlines", "/calendar"),
            ("Communication", "Communicate with professors and peers", "/communication"),
            ("Exams", "View and take exams", "/exams/take")
        ]

    # Generate HTML output for features
    return "".join([f"""
        <div class="feature-card">
            <h3>{title}</h3>
            <p>{description}</p>
            <a href="{link}" class="button">Access</a>
        </div>
    """ for title, description, link in features])


# Add example feature routes
@app.route('/courses')
def view_courses():
    if 'username' not in session:
        return redirect('/login')

    role = session.get('role')
    department = session.get('department')

    # Different course views based on role
    courses_data = get_courses_by_role(role, department)

    return f"""
    <html>
        <head>
            <title>Courses - {department}</title>
            <style>
                /* ... (same styles as dashboard) ... */
                .course-card {{
                    background: white;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .course-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                }}
                .status-badge {{
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                }}
                .status-active {{
                    background: #e8f5e9;
                    color: #2e7d32;
                }}
                .status-pending {{
                    background: #fff3e0;
                    color: #e65100;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Courses - {department}</h1>
                    <a href="/dashboard" class="button">Back to Dashboard</a>
                </div>
                <div class="course-grid">
                    {courses_data}
                </div>
            </div>
        </body>
    </html>
    """

@app.route('/grades')
def manage_grades():
    if 'username' not in session:
        return redirect('/login')

    role = session.get('role')
    department = session.get('department')

    # Different grade views based on role
    grades_data = get_grades_by_role(role, department)

    return f"""
    <html>
        <head>
            <title>Grade Management</title>
            <style>
                /* ... (same styles as dashboard) ... */
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #f8f9fa;
                }}
                .grade-input {{
                    width: 60px;
                    padding: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Grade Management</h1>
                    <a href="/dashboard" class="button">Back to Dashboard</a>
                </div>
                {grades_data}
            </div>
        </body>
    </html>
    """

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    return redirect('/login')

@app.route('/users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session.get('role') != 'super_admin':
        return "Access Denied", 403

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_role = request.form.get('role')
        new_department = request.form.get('department')

        if new_username and new_role:
            if new_username in users_db:
                return "Username already exists!"

            # Generate temporary password
            temp_password = os.urandom(8).hex()
            temp_passwords[new_username] = temp_password

            # Store empty password hash initially
            users_db[new_username] = {
                'password': bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt()),
                'role': new_role,
                'department': new_department
            }

            return f"""
            <html>
                <body>
                    <div class="container">
                        <h1>User Created</h1>
                        <p>Username: {new_username}</p>
                        <p>Temporary Password: {temp_password}</p>
                        <p>Please provide these credentials to the user.</p>
                        <a href="/users">Back to User Management</a>
                    </div>
                </body>
            </html>
            """

    # Generate current users table
    users_table = ""
    for username, data in users_db.items():
        users_table += f"""
            <tr>
                <td>{username}</td>
                <td>{data['role']}</td>
                <td>{data.get('department', 'N/A')}</td>
                <td>
                    <form method="POST" action="/delete_user" style="display: inline;">
                        <input type="hidden" name="username" value="{username}">
                        <button type="submit" class="delete-btn">Delete</button>
                    </form>
                </td>
            </tr>
        """

    return f"""
    <html>
        <head>
            <title>User Management - Secure App</title>
            <style>
                body {{
                    font-family: Arial;
                    margin: 40px;
                    background: #f0f0f0;
                }}
                .container {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    max-width: 800px;
                    margin: 0 auto;
                }}
                .form-group {{
                    margin-bottom: 15px;
                }}
                label {{
                    display: block;
                    margin-bottom: 5px;
                }}
                input, select {{
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }}
                button {{
                    background: #007bff;
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                button:hover {{
                    background: #0056b3;
                }}
                .delete-btn {{
                    background: #dc3545;
                }}
                .delete-btn:hover {{
                    background: #c82333;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #f8f9fa;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>User Management</h1>
                <h2>Add New User</h2>
                <form method="POST">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Role:</label>
                        <select name="role" required>
                            <option value="student_csm">Student (CSM)</option>
                            <option value="student_eng">Student (ENG)</option>
                            <option value="professor_csm">Professor (CSM)</option>
                            <option value="professor_eng">Professor (ENG)</option>
                            <option value="chair_csm">Department Chair (CSM)</option>
                            <option value="chair_eng">Department Chair (ENG)</option>
                            <option value="ta_csm">Teaching Assistant (CSM)</option>
                            <option value="ta_eng">Teaching Assistant (ENG)</option>
                            <option value="ra_csm">Research Assistant (CSM)</option>
                            <option value="ra_eng">Research Assistant (ENG)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Department:</label>
                        <select name="department" required>
                            <option value="CSM">Computer Science and Mathematics</option>
                            <option value="ENG">Engineering</option>
                            <option value="BUS">Business</option>
                            <option value="SCI">Sciences</option>
                            <option value="HUM">Humanities</option>
                        </select>
                    </div>
                    <button type="submit">Add User</button>
                </form>

                <h2>Current Users</h2>
                <table>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Department</th>
                        <th>Actions</th>
                    </tr>
                    {users_table}
                </table>
                <div style="margin-top: 20px;">
                    <a href="/dashboard" class="button">Back to Dashboard</a>
                </div>
            </div>
        </body>
    </html>
    """

@app.route('/delete_user', methods=['POST'])
def delete_user():
    # Check if user is logged in and is admin
    if 'username' not in session or session.get('role') != 'super_admin':
        return "Access Denied", 403

    username = request.form.get('username')

    # Prevent admin from deleting themselves
    if username == session.get('username'):
        return "Cannot delete your own account!", 400

    if username in users_db:
        del users_db[username]

    return redirect('/users')

# Helper functions to generate content based on role
def get_courses_by_role(role: str, department: str) -> str:
    courses = []

    if role == 'super_admin':
        courses = [
            ("CS101", "Introduction to Programming", "Active", "All Departments"),
            ("CS201", "Data Structures", "Active", "CSM"),
            ("ENG101", "Engineering Basics", "Pending", "ENG")
        ]
    elif role.startswith('chair'):
        courses = [
            (f"{department}101", f"Intro to {department}", "Active", department),
            (f"{department}201", f"Advanced {department}", "Pending", department),
            (f"{department}301", f"Special Topics in {department}", "Active", department)
        ]
    elif role.startswith('professor') or role.startswith('assoc_prof'):
        courses = [
            (f"{department}101", f"Intro to {department}", "Active", "Teaching"),
            (f"{department}201", f"Advanced {department}", "Active", "Teaching")
        ]
    elif role.startswith('student'):
        courses = [
            (f"{department}101", f"Intro to {department}", "Enrolled", "In Progress"),
            (f"{department}201", f"Advanced {department}", "Enrolled", "In Progress")
        ]

    html = ""
    for code, name, status, info in courses:
        html += f"""
            <div class="course-card">
                <h3>{code}: {name}</h3>
                <span class="status-badge status-{'active' if status == 'Active' else 'pending'}">{status}</span>
                <p>{info}</p>
                <div style="margin-top: 15px;">
                    <a href="/course/{code}" class="button">View Details</a>
                    {'<a href="/course/edit/' + code + '" class="button">Edit Course</a>' if role.startswith(('chair', 'professor')) else ''}
                </div>
            </div>
        """
    return html

def get_grades_by_role(role: str, department: str) -> str:
    if role.startswith(('professor', 'assoc_prof', 'ta')):
        return f"""
            <form method="POST" action="/update_grades">
                <table>
                    <tr>
                        <th>Student</th>
                        <th>Course</th>
                        <th>Current Grade</th>
                        <th>Action</th>
                    </tr>
                    <tr>
                        <td>John Doe</td>
                        <td>{department}101</td>
                        <td><input type="text" class="grade-input" value="A" name="grade_1"></td>
                        <td><button type="submit" class="button">Update</button></td>
                    </tr>
                    <tr>
                        <td>Jane Smith</td>
                        <td>{department}101</td>
                        <td><input type="text" class="grade-input" value="B+" name="grade_2"></td>
                        <td><button type="submit" class="button">Update</button></td>
                    </tr>
                </table>
            </form>
        """
    elif role.startswith('student'):
        return f"""
            <table>
                <tr>
                    <th>Course</th>
                    <th>Grade</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>{department}101</td>
                    <td>A</td>
                    <td>Final</td>
                </tr>
                <tr>
                    <td>{department}201</td>
                    <td>B+</td>
                    <td>In Progress</td>
                </tr>
            </table>
        """
    return "<p>No grades available.</p>"

if __name__ == '__main__':
    print("Starting Flask application...")
    print("Visit http://127.0.0.1:8080 in your browser")
    app.run(debug=True, host='127.0.0.1', port=8080)
