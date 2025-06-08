from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename         # ← Add this line
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
app.secret_key = 'your_super_secret_key'  # ← Change this to a random secret in production

# ----- Database Setup -----
DB_NAME = 'users.db'

def init_db():
    """Initialize SQLite database and create 'users' table if it doesn't exist."""
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


# ----- Flask-Mail Config (for Password Reset) -----
app.config.update(
    MAIL_SERVER='smtp.gmail.com',       # e.g., Gmail SMTP
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='your_email@gmail.com',      # ← Replace with your email
    MAIL_PASSWORD='your_app_password'          # ← Replace with your email's app-password
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)


# ----- Helper Functions for User CRUD -----
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


# ----- File Conversion Folders -----
UPLOAD_FOLDER = 'uploads'
CONVERTED_FOLDER = 'converted'
TEMP_FOLDER = 'converter_temp'
for folder in (UPLOAD_FOLDER, CONVERTED_FOLDER, TEMP_FOLDER):
    os.makedirs(folder, exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ====== Routes: Authentication ======

@app.route('/')
def home():
    """Home page: if logged in, redirect to dashboard, else show generic home."""
    if session.get('username'):
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration. Validate input, hash password, save to SQLite."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        # Basic server-side validation
        if not username or not email or not password or not confirm:
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))

        # Validate email format
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            flash(str(e), 'error')
            return redirect(url_for('signup'))

        # Check password match
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        # Check username/email uniqueness
        if get_user_by_username(username):
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))
        if get_user_by_email(email):
            flash('Email already registered.', 'error')
            return redirect(url_for('signup'))

        # Hash password and insert new user
        hashed = generate_password_hash(password)
        create_user(username, email, hashed)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login. Accept either email or username as identifier."""
    if request.method == 'POST':
        identifier = request.form['email_or_username'].strip()
        password = request.form['password']

        user = get_user_by_email(identifier) or get_user_by_username(identifier)
        if user and check_password_hash(user[3], password):
            session['username'] = user[1]  # store username in session
            flash('Welcome, ' + user[1] + '!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Log out the user by clearing session."""
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    """
    Step 1 of password reset:
    - GET: show form to enter email
    - POST: if user exists, send an email with a time-limited token link
    """
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = get_user_by_email(email)
        if user:
            token = serializer.dumps(email, salt='reset-salt')
            link = url_for('reset_token', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender='your_email@gmail.com',
                          recipients=[email])
            msg.body = f'Click the link below to reset your password (valid for 1 hour):\n{link}\n\nIf you did not request this, please ignore.'
            mail.send(msg)
            flash('Reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'error')
        return redirect(url_for('login'))

    return render_template('reset_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    """
    Step 2 of password reset:
    - Validate token <=> email, expires in 3600s
    - GET: show form to enter new password
    - POST: update the user's password in DB
    """
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
        flash('Password updated successfully. You can log in now.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html')


# ====== Routes: PDF Converter (Protected) ======

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Main converter page. User must be logged in to see and use."""
    if not session.get('username'):
        flash('Please log in to access the converter.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 1. Validate file upload
        if 'file' not in request.files:
            flash('No file part.', 'error')
            return redirect(url_for('dashboard'))
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Please upload a valid PDF file.', 'error')
            return redirect(url_for('dashboard'))

        # 2. Save uploaded PDF
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        upload_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_{filename}")
        file.save(upload_path)

        # 3. Determine requested conversion
        conv_type = request.form.get('conversion_type')
        try:
            if conv_type == 'pdf_to_word':
                output_path = pdf_to_word(upload_path, unique_id)
                return send_file(output_path, as_attachment=True)

            elif conv_type == 'pdf_to_jpg':
                zip_path = pdf_to_jpg_zip(upload_path, unique_id)
                return send_file(zip_path, as_attachment=True)

            elif conv_type == 'pdf_to_ipynb':
                ipynb_path = pdf_to_ipynb(upload_path, unique_id)
                return send_file(ipynb_path, as_attachment=True)

            else:
                flash('Invalid conversion type selected.', 'error')
                return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f'Conversion failed: {str(e)}', 'error')
            return redirect(url_for('dashboard'))

    # GET request: just render the dashboard form
    return render_template('dashboard.html', username=session.get('username'))


# ----- Converter Helper Functions -----

def pdf_to_word(pdf_path, unique_id):
    """Extract all PDF text and write it into a .docx file."""
    doc = Document()
    doc.add_heading('Converted from PDF', level=1)
    pdf = fitz.open(pdf_path)
    for page in pdf:
        text = page.get_text()
        doc.add_paragraph(text)

    output_filename = f"{unique_id}_converted.docx"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    doc.save(output_path)
    return output_path


def pdf_to_jpg_zip(pdf_path, unique_id):
    """
    Render every PDF page as a JPG, then zip all images into one .zip file.
    """
    pdf = fitz.open(pdf_path)
    image_folder = os.path.join(TEMP_FOLDER, unique_id)
    os.makedirs(image_folder, exist_ok=True)

    image_paths = []
    for page_index in range(len(pdf)):
        page = pdf[page_index]
        pix = page.get_pixmap(dpi=150)
        img_filename = f"page_{page_index + 1}.jpg"
        img_path = os.path.join(image_folder, img_filename)
        pix.save(img_path)
        image_paths.append(img_path)

    zip_filename = f"{unique_id}_pages.zip"
    zip_path = os.path.join(CONVERTED_FOLDER, zip_filename)
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for img_path in image_paths:
            zf.write(img_path, arcname=os.path.basename(img_path))

    # Cleanup intermediate JPGs
    for img_path in image_paths:
        os.remove(img_path)
    os.rmdir(image_folder)

    return zip_path


def pdf_to_ipynb(pdf_path, unique_id):
    """
    Extract PDF text and write it into a simple Jupyter Notebook (.ipynb),
    with one Markdown cell containing all the text.
    """
    pdf = fitz.open(pdf_path)
    full_text = ""
    for page in pdf:
        full_text += page.get_text() + "\n\n"

    nb = nbformat.v4.new_notebook()
    cell = nbformat.v4.new_markdown_cell(f"# Text extracted from PDF\n\n```\n{full_text}\n```")
    nb['cells'] = [cell]

    output_filename = f"{unique_id}_converted.ipynb"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)

    return output_path


if __name__ == '__main__':
    app.run(debug=True)
