from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, validators
from wtforms.validators import DataRequired, Email, Length, InputRequired, Regexp
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
app.config['SECRET_KEY'] = 'a_very_secure_secret_key' 
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize the database and Bcrypt
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Bcrypt for password hashing

# Session Management Configuration
app.config['SESSION_COOKIE_SECURE'] = True   # Ensure cookies are only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF in cross-site contexts
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Session expires after 1 hour

@app.before_request
def make_session_permanent():
    """Make session permanent (expires after specified time)"""
    session.permanent = True

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords

# Contact Model
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    website = db.Column(db.String(100), nullable=True)
    message = db.Column(db.Text, nullable=False)

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', [DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', [DataRequired(), Length(min=6)])

# Contact form
class ContactForm(FlaskForm):
    name = StringField('Name', [DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', [DataRequired(), Email()])
    phone = StringField('Phone (Optional)', [validators.Optional(), Length(min=10, max=15)])
    website = StringField('Website (Optional)', [validators.Optional(), Length(max=100)])
    message = TextAreaField('Message', [DataRequired(), Length(min=10)])

# Registration form with proper input validation to prevent SQL Injection
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(),
        Length(min=4, max=25),
        Regexp('^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, or underscores")
    ])
    email = StringField('Email', validators=[
        InputRequired(),
        Email(message='Invalid email address'),
        Length(max=50)
    ])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=6, message='Password should be at least 6 characters long')
    ])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():  # Input is validated here
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Hashing the password for storage
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # SQLAlchemy handles SQL injection by using parameterized queries
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!")
            return redirect('/login')
        except Exception as e:
            db.session.rollback()
            flash("Error: Username or Email already exists.")
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('contact_form'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)

@app.route('/contact', methods=['GET', 'POST'])
def contact_form():
    form = ContactForm()
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if form.validate_on_submit():
        contact = Contact(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            website=form.website.data,
            message=form.message.data
        )
        db.session.add(contact)
        db.session.commit()
        flash("Contact details submitted successfully!", "success")
        return redirect(url_for('contact_form'))

    return render_template('contact.html', form=form)

# Custom error handler for 404 error
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Custom error handler for 500 error
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)
