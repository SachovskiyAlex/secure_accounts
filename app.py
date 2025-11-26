from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
import sqlite3
import os
import random
import string
from datetime import datetime, timedelta
import requests
import smtplib
from email.message import EmailMessage
import requests

app = Flask(__name__)

# ===== CONFIG =====
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_change_me')
app.config['DATABASE'] = os.environ.get('DATABASE_PATH', 'database.db')

app.config['GMAIL_USER'] = os.environ.get('GMAIL_USER', '')
app.config['GMAIL_APP_PASSWORD'] = os.environ.get('GMAIL_APP_PASSWORD', '')

app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', '')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', '')

app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')
app.config['GOOGLE_DISCOVERY_URL'] = 'https://accounts.google.com/.well-known/openid-configuration'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

oauth = OAuth(app)
if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={'scope': 'openid email profile'}
    )
else:
    google = None

# ===== DB HELPERS =====
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, row):
        self.id = row['id']
        self.email = row['email']
        self.username = row['username']
        self.password_hash = row['password_hash']
        self.is_active_flag = row['is_active']
        self.is_2fa_enabled = row['is_2fa_enabled']
        self.failed_logins = row['failed_logins']
        self.lock_until = row['lock_until']

    @property
    def is_active(self):
        return bool(self.is_active_flag)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(row)
    return None

# ===== HELPERS =====
def password_valid(password: str) -> bool:
    if len(password) < 8:
        return False
    return (
        any(c.islower() for c in password) and
        any(c.isupper() for c in password) and
        any(c.isdigit() for c in password) and
        any(not c.isalnum() for c in password)
    )

def generate_random_token(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def send_email(to, subject, body):
    api_key = os.environ.get("SENDGRID_API_KEY")
    from_email = os.environ.get("FROM_EMAIL")

    if not api_key or not from_email:
        print("=== EMAIL (mock) ===")
        print("TO:", to)
        print("SUBJECT:", subject)
        print("BODY:", body)
        print("====================")
        return

    data = {
        "personalizations": [{
            "to": [{"email": to}]
        }],
        "from": {"email": from_email},
        "subject": subject,
        "content": [{
            "type": "text/plain",
            "value": body
        }]
    }

    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        json=data,
        headers={"Authorization": f"Bearer {api_key}"}
    )

    if response.status_code >= 400:
        print("SENDGRID ERROR:", response.text)

def log_login_attempt(user_id, username_or_email, ip, success):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO login_attempts (user_id, username_or_email, ip_address, timestamp, success)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, username_or_email, ip, datetime.now().isoformat(timespec='seconds'), 1 if success else 0))
    conn.commit()
    conn.close()

def parse_datetime(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        return None

def verify_recaptcha(token, remote_ip):
    secret = app.config['RECAPTCHA_SECRET_KEY']
    if not secret:
        # Якщо не налаштовано — вважаємо, що reCAPTCHA пройдена (для локальної розробки)
        return True
    resp = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": secret, "response": token, "remoteip": remote_ip}
    )
    data = resp.json()
    return data.get("success", False)

# ===== ROUTES =====
@app.route("/")
def index():
    return render_template("index.html")

# ----------------------- REGISTER -----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    recaptcha_response = request.form.get("g-recaptcha-response", "")

    if not verify_recaptcha(recaptcha_response, request.remote_addr):
        flash("Підтвердіть, що ви не робот (reCAPTCHA).", "danger")
        return render_template("register.html",
                               recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'],
                               email=email, username=username)

    if password != confirm:
        flash("Паролі не співпадають.", "danger")
        return render_template("register.html",
                               recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'],
                               email=email, username=username)

    if not password_valid(password):
        flash("Пароль не відповідає політиці безпеки.", "danger")
        return render_template("register.html",
                               recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'],
                               email=email, username=username)

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    activation_token = generate_random_token()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, username, password_hash, is_active, is_2fa_enabled,
                               failed_logins, lock_until, activation_token)
            VALUES (?, ?, ?, 0, 0, 0, NULL, ?)
        """, (email, username, password_hash, activation_token))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        flash("Користувач з таким email або username вже існує.", "danger")
        return render_template("register.html",
                               recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'],
                               email=email, username=username)

    conn.close()

    activation_link = url_for("activate", token=activation_token, _external=True)
    send_email(email, "Активація облікового запису", f"Для активації акаунта перейдіть за посиланням: {activation_link}")

    flash("Реєстрація успішна. Перевірте email для активації акаунта.", "success")
    return redirect(url_for("login"))

# ----------------------- ACTIVATE -----------------------
@app.route("/activate")
def activate():
    token = request.args.get("token", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE activation_token = ?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return render_template("activate.html", success=False)
    cur.execute("UPDATE users SET is_active = 1, activation_token = NULL WHERE id = ?", (row['id'],))
    conn.commit()
    conn.close()
    return render_template("activate.html", success=True)

# ----------------------- LOGIN -----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username_or_email = request.form.get("username_or_email", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ? OR username = ?", (username_or_email, username_or_email))
    row = cur.fetchone()
    ip = request.remote_addr or "unknown"

    if not row:
        log_login_attempt(None, username_or_email, ip, False)
        conn.close()
        flash("Користувача не знайдено. Зареєструйтесь.", "danger")
        return render_template("login.html", username_or_email=username_or_email)

    user = User(row)

    if not user.is_active:
        log_login_attempt(user.id, username_or_email, ip, False)
        conn.close()
        flash("Акаунт не активований. Перевірте email.", "warning")
        return render_template("login.html", username_or_email=username_or_email)

    lock_until_dt = parse_datetime(user.lock_until)
    if lock_until_dt and lock_until_dt > datetime.now():
        log_login_attempt(user.id, username_or_email, ip, False)
        conn.close()
        flash(f"Акаунт заблоковано до {lock_until_dt}.", "danger")
        return render_template("login.html", username_or_email=username_or_email)

    if not bcrypt.check_password_hash(user.password_hash, password):
        new_failed = user.failed_logins + 1
        lock_until_str = None
        if new_failed >= 5:
            lock_until_str = (datetime.now() + timedelta(minutes=15)).isoformat(timespec='seconds')
        cur.execute("UPDATE users SET failed_logins = ?, lock_until = ? WHERE id = ?",
                    (new_failed, lock_until_str, user.id))
        conn.commit()
        conn.close()
        log_login_attempt(user.id, username_or_email, ip, False)
        flash("Невірний пароль.", "danger")
        return render_template("login.html", username_or_email=username_or_email)

    # reset failed logins
    cur.execute("UPDATE users SET failed_logins = 0, lock_until = NULL WHERE id = ?", (user.id,))
    conn.commit()
    conn.close()

    if user.is_2fa_enabled:
        code = random.randint(100000, 999999)
        session['2fa_user_id'] = user.id
        session['2fa_code'] = str(code)
        session['2fa_expires'] = (datetime.now() + timedelta(minutes=5)).isoformat(timespec='seconds')
        send_email(user.email, "Ваш 2FA код", f"Ваш код: {code}")
        flash("Введіть 2FA код, надісланий на ваш email.", "info")
        return redirect(url_for("two_factor"))

    login_user(user)
    log_login_attempt(user.id, username_or_email, ip, True)
    flash("Вхід успішний.", "success")
    return redirect(url_for("index"))

# ----------------------- 2FA -----------------------
@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if '2fa_user_id' not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("two_factor.html")

    code = request.form.get("code", "").strip()
    expected = session.get("2fa_code")
    expires_str = session.get("2fa_expires")
    expires_dt = parse_datetime(expires_str)

    if not expected or not expires_dt or expires_dt < datetime.now():
        flash("2FA код недійсний або прострочений. Увійдіть ще раз.", "danger")
        session.pop('2fa_user_id', None)
        session.pop('2fa_code', None)
        session.pop('2fa_expires', None)
        return redirect(url_for("login"))

    if code != expected:
        flash("Невірний 2FA код.", "danger")
        return render_template("two_factor.html")

    user_id = session['2fa_user_id']
    user = load_user(user_id)
    if not user:
        flash("Помилка користувача. Увійдіть ще раз.", "danger")
        return redirect(url_for("login"))

    login_user(user)
    session.pop('2fa_user_id', None)
    session.pop('2fa_code', None)
    session.pop('2fa_expires', None)
    flash("2FA підтверджено. Вхід успішний.", "success")
    return redirect(url_for("index"))

# ----------------------- PROFILE -----------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        enabled = 1 if request.form.get("twofa") == "on" else 0
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_2fa_enabled = ? WHERE id = ?", (enabled, current_user.id))
        conn.commit()
        conn.close()
        flash("Налаштування профілю збережені.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html")

# ----------------------- FORGOT PASSWORD -----------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    if row:
        reset_token = generate_random_token()
        expires_at = (datetime.now() + timedelta(minutes=30)).isoformat(timespec='seconds')
        cur.execute("""
            UPDATE users SET reset_token = ?, reset_token_expires_at = ?
            WHERE id = ?
        """, (reset_token, expires_at, row['id']))
        conn.commit()
        reset_link = url_for("reset_password", token=reset_token, _external=True)
        send_email(email, "Скидання пароля", f"Для скидання пароля перейдіть за посиланням: {reset_link}")

    conn.close()
    flash("Якщо такий email існує, інструкції були надіслані.", "info")
    return redirect(url_for("login"))

# ----------------------- RESET PASSWORD -----------------------
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") if request.method == "GET" else request.form.get("token")

    if request.method == "GET":
        return render_template("reset_password.html", token=token)

    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if password != confirm:
        flash("Паролі не співпадають.", "danger")
        return render_template("reset_password.html", token=token)

    if not password_valid(password):
        flash("Пароль не відповідає політиці безпеки.", "danger")
        return render_template("reset_password.html", token=token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("Невірний токен скидання пароля.", "danger")
        return redirect(url_for("login"))

    expires_dt = parse_datetime(row['reset_token_expires_at'])
    if not expires_dt or expires_dt < datetime.now():
        conn.close()
        flash("Токен скидання пароля прострочений.", "danger")
        return redirect(url_for("login"))

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    cur.execute("""
        UPDATE users
        SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL
        WHERE id = ?
    """, (password_hash, row['id']))
    conn.commit()
    conn.close()

    flash("Пароль успішно змінено. Увійдіть з новим паролем.", "success")
    return redirect(url_for("login"))

# ----------------------- GOOGLE OAUTH -----------------------
@app.route("/login/google")
def login_google():
    if not google:
        flash("Google OAuth не налаштовано.", "warning")
        return redirect(url_for("login"))
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/login/google/callback")
def google_callback():
    if not google:
        flash("Google OAuth не налаштовано.", "warning")
        return redirect(url_for("login"))
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    email = user_info.get("email")
    sub = user_info.get("sub")
    username = email.split("@")[0] if email else f"user_{sub}"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE oauth_provider = 'google' AND oauth_id = ?", (sub,))
    row = cur.fetchone()

    if not row:
        dummy_password = generate_random_token()
        password_hash = bcrypt.generate_password_hash(dummy_password).decode("utf-8")
        cur.execute("""
            INSERT INTO users (email, username, password_hash, is_active, is_2fa_enabled,
                               failed_logins, lock_until, activation_token, oauth_provider, oauth_id)
            VALUES (?, ?, ?, 1, 0, 0, NULL, NULL, 'google', ?)
        """, (email, username, password_hash, sub))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE oauth_provider = 'google' AND oauth_id = ?", (sub,))
        row = cur.fetchone()

    user = User(row)
    login_user(user)
    conn.close()
    flash("Вхід через Google успішний.", "success")
    return redirect(url_for("index"))

# ----------------------- ADMIN LOGS -----------------------
@app.route("/admin/logins")
@login_required
def admin_logins():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT la.id, la.username_or_email, la.ip_address, la.timestamp, la.success, u.email
        FROM login_attempts la
        LEFT JOIN users u ON la.user_id = u.id
        ORDER BY la.id DESC
        LIMIT 100
    """)
    logs = cur.fetchall()
    conn.close()
    return render_template("admin_logins.html", logs=logs)

# ----------------------- LOGOUT -----------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Ви вийшли з акаунта.", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
