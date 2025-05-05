from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from models import db, User, Credential
from forms import RegisterForm, LoginForm, AddCredentialForm, MFAForm
from encryption_mech import encrypt, decrypt, generate_key
import random
import time

# MFA temp storage
otp_dict = {}

# Load configs
app = Flask(__name__)
app.config.from_object('config.Config')
mail = Mail(app)

# Initialize app
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email, otp):
    msg = Message('Your MFA OTP', recipients=[email])
    msg.body = f'Your One-Time Password (OTP) is: {otp}'
    mail.send(msg)

# User manager
@login_manager.user_loader
def load_user(user_id):
    #return User.query.get(int(user_id))
    return db.session.get(User, int(user_id))

# Make sure HTTPS is in use and not HTTP
@app.before_request
def before_request():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))

# Set up a CSP header (Control sources from where content can load)
@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    return response

# The default page (home)
@app.route('/')
def home():
    return render_template('home.html')

# The register page and functions
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        encryption_key = generate_key()
        user = User(username=form.username.data, 
                    email=form.email.data, 
                    password=hashed_pw, 
                    key=encryption_key, 
                    mfa_enabled=form.mfa_enabled.data)
        db.session.add(user)
        try:
            db.session.commit()
        except Exception:
            flash('Username or email is already taken, log in?')
            return render_template('register.html', form=form)
        flash('Account created! You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# The login page and functions
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('credentials'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.mfa_enabled:
                otp = generate_otp()
                # Storing the OTP with time
                otp_dict[user.id] = (otp, time.time())  
                send_otp(user.email, otp)
                flash('OTP sent to your email. Please verify.')
                session['user_id'] = user.id
                return redirect(url_for('mfa'))
            else:
                login_user(user)
                return redirect(url_for('credentials'))
        flash('Invalid username or password!')
    return render_template('login.html', form=form)

# The credentials page and functions
@app.route('/credentials', methods=['GET', 'POST'])
@login_required
def credentials():
    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    form = AddCredentialForm()
    if form.validate_on_submit():
        encrypted_password = encrypt(form.password.data, current_user.key)
        credential = Credential(user_id=current_user.id, 
                                website=form.website.data,
                                username=form.username.data, 
                                password=encrypted_password)
        db.session.add(credential)
        db.session.commit()
        flash('Credential added successfully to database!')
        return redirect(url_for('credentials'))
    return render_template('credentials.html', form=form, credentials=credentials)

# The de_credentials page and functions
@app.route('/de_credentials', methods=['GET', 'POST'])
@login_required
def de_credentials():
    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    decrypted_credentials = []
    for credential in credentials:
        try:
            decrypted_password = decrypt(credential.password, current_user.key)
            decrypted_credentials.append({
                'website': credential.website,
                'username': credential.username,
                'password': decrypted_password
            })
        except Exception:
            decrypted_credentials.append({
                'website': credential.website,
                'username': credential.username,
                'password': "Error decrypting password"
            })

    form = AddCredentialForm()
    if form.validate_on_submit():
        encrypted_password = encrypt(form.password.data, current_user.key)
        credential = Credential(user_id=current_user.id, website=form.website.data,
                                username=form.username.data, password=encrypted_password)
        db.session.add(credential)
        db.session.commit()
        flash('Credential added successfully to database!')
        return redirect(url_for('de_credentials'))
    return render_template('de_credentials.html', form=form, credentials=decrypted_credentials)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    user_id = session.get('user_id')
    form = MFAForm()
    if not user_id:
        flash('Session expired. Please log in again.')
        return redirect(url_for('login'))

    if form.validate_on_submit():
        otp, timestamp = otp_dict.get(user_id, (None, None))
        if otp and form.otp.data == otp and time.time() - timestamp < 300:
            user = db.session.get(User, int(user_id))#User.query.get(user_id)
            login_user(user)
            #flash('MFA verified successfully.')
            return redirect(url_for('credentials'))
        flash('Invalid or expired OTP.')
    return render_template('mfa.html', form=form)#, user=user)

# The logout function and send to home page
@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(ssl_context=('C:/Users/Primea/Desktop/Python_things/.venv/Web-Application Security Project/ssl.crt', 'C:/Users/Primea/Desktop/Python_things/.venv/Web-Application Security Project/ssl.key'))
    #app.run(debug=True, host='127.0.0.1', port=8080, ssl_context=('ssl.crt', 'ssl.key'))