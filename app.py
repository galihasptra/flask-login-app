from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = 'rahasia123'
app.permanent_session_lifetime = timedelta(minutes=5)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# Cek ekstensi file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nama = db.Column(db.String(100))
    email = db.Column(db.String(100))
    foto = db.Column(db.String(100))

# Buat DB dan user admin default
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('1234'),
            nama='Admin',
            email='admin@example.com'
        )
        db.session.add(admin)
        db.session.commit()
        print("===> DATABASE dibuat dan user admin ditambahkan")

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = "Username atau password salah."
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        nama = request.form.get('nama', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(username) < 3:
            error = "Username minimal 3 karakter."
        elif len(password) < 6:
            error = "Password minimal 6 karakter."
        elif password != confirm_password:
            error = "Password dan konfirmasi tidak cocok."
        elif User.query.filter_by(username=username).first():
            error = "Username sudah digunakan."
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, nama=nama, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Berhasil daftar! Silakan login.")
            return redirect(url_for('login'))

    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"""
            <h2>Selamat datang, {session['username']}!</h2>
            <a href='/profile'>Profil Saya</a> |
            <a href='/edit-profile'>Edit Profil</a> |
            <a href='/logout'>Logout</a>
        """
    else:
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    return render_template('profile.html', user=user)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    error = None
    success = None

    if request.method == 'POST':
        nama = request.form.get('nama', '').strip()
        email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')
        file = request.files.get('foto')

        if not check_password_hash(user.password, current_password):
            error = "Password lama salah."
        elif new_password and len(new_password) < 6:
            error = "Password baru minimal 6 karakter."
        elif new_password and new_password != confirm_new_password:
            error = "Konfirmasi password tidak cocok."
        else:
            user.nama = nama
            user.email = email
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.foto = filename
            if new_password:
                user.password = generate_password_hash(new_password)
            db.session.commit()
            success = "Profil berhasil diperbarui."

    return render_template('edit_profile.html', user=user, error=error, success=success)

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    db.session.delete(user)
    db.session.commit()
    session.pop('username', None)
    flash("Akun berhasil dihapus.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logout berhasil.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
