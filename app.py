from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError
import sqlite3
import os
import uuid
import zipfile
import fitz      # PyMuPDF
from docx import Document
import nbformat

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'ahmedkhan0300'

# Database setup
DB_NAME = 'users.db'

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        conn.commit()

init_db()

# Flask-Mail Config
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='your_email@gmail.com',
    MAIL_PASSWORD='your_app_password'
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# User helper functions
def get_user_by_email(email):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        return c.fetchone()

def get_user_by_username(username):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        return c.fetchone()

def create_user(username, email, password_hash):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                  (username, email, password_hash))
        conn.commit()

def update_password(email, new_password_hash):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE email = ?", (new_password_hash, email))
        conn.commit()

# File paths
UPLOAD_FOLDER = 'uploads'
CONVERTED_FOLDER = 'converted'
TEMP_FOLDER = 'converter_temp'
for folder in (UPLOAD_FOLDER, CONVERTED_FOLDER, TEMP_FOLDER):
    os.makedirs(folder, exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def home():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not username or not email or not password or not confirm:
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            flash(str(e), 'error')
            return redirect(url_for('signup'))

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        if get_user_by_username(username):
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))
        if get_user_by_email(email):
            flash('Email already registered.', 'error')
            return redirect(url_for('signup'))

        hashed = generate_password_hash(password)
        create_user(username, email, hashed)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['email_or_username'].strip()
        password = request.form['password']
        user = get_user_by_email(identifier) or get_user_by_username(identifier)
        if user and check_password_hash(user[3], password):
            session['username'] = user[1]
            flash('Welcome, ' + user[1] + '!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = get_user_by_email(email)
        if user:
            token = serializer.dumps(email, salt='reset-salt')
            link = url_for('reset_token', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender='your_email@gmail.com',
                          recipients=[email])
            msg.body = f'Click the link to reset your password: {link}'
            mail.send(msg)
            flash('Reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'error')
        return redirect(url_for('login'))

    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = serializer.loads(token, salt='reset-salt', max_age=3600)
    except Exception:
        flash('Invalid or expired link.', 'error')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_token', token=token))

        hashed = generate_password_hash(password)
        update_password(email, hashed)
        flash('Password updated successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('username'):
        flash('Please log in to access the converter.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part.', 'error')
            return redirect(url_for('dashboard'))
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file.', 'error')
            return redirect(url_for('dashboard'))

        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        upload_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_{filename}")
        file.save(upload_path)

        conv_type = request.form.get('conversion_type')
        try:
            if conv_type == 'pdf_to_word':
                return send_file(pdf_to_word(upload_path, unique_id), as_attachment=True)
            elif conv_type == 'pdf_to_jpg':
                return send_file(pdf_to_jpg_zip(upload_path, unique_id), as_attachment=True)
            elif conv_type == 'pdf_to_ipynb':
                return send_file(pdf_to_ipynb(upload_path, unique_id), as_attachment=True)
            else:
                flash('Invalid conversion type.', 'error')
        except Exception as e:
            flash(f'Conversion failed: {str(e)}', 'error')

    return render_template('dashboard.html', username=session.get('username'))

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            flash('Welcome, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        flash('Admin access required.', 'error')
        return redirect(url_for('admin_login'))

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, email FROM users")
        users = c.fetchall()

    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('admin_login'))

# PDF Conversion Functions
def pdf_to_word(pdf_path, unique_id):
    doc = Document()
    doc.add_heading('Converted from PDF', level=1)
    pdf = fitz.open(pdf_path)
    for page in pdf:
        doc.add_paragraph(page.get_text())
    output_path = os.path.join(CONVERTED_FOLDER, f"{unique_id}_converted.docx")
    doc.save(output_path)
    return output_path

def pdf_to_jpg_zip(pdf_path, unique_id):
    pdf = fitz.open(pdf_path)
    image_folder = os.path.join(TEMP_FOLDER, unique_id)
    os.makedirs(image_folder, exist_ok=True)
    image_paths = []
    for i, page in enumerate(pdf):
        pix = page.get_pixmap(dpi=150)
        img_path = os.path.join(image_folder, f"page_{i+1}.jpg")
        pix.save(img_path)
        image_paths.append(img_path)
    zip_path = os.path.join(CONVERTED_FOLDER, f"{unique_id}_pages.zip")
    with zipfile.ZipFile(zip_path, 'w') as z:
        for img in image_paths:
            z.write(img, arcname=os.path.basename(img))
    for img in image_paths:
        os.remove(img)
    os.rmdir(image_folder)
    return zip_path

def pdf_to_ipynb(pdf_path, unique_id):
    pdf = fitz.open(pdf_path)
    full_text = "\n\n".join([page.get_text() for page in pdf])
    nb = nbformat.v4.new_notebook()
    nb.cells = [nbformat.v4.new_markdown_cell(f"# Extracted from PDF\n\n```\n{full_text}\n```")]
    output_path = os.path.join(CONVERTED_FOLDER, f"{unique_id}_converted.ipynb")
    with open(output_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)
    return output_path

if __name__ == '__main__':
    app.run(debug=True)
