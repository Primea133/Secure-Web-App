from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email

# Register form for register.html
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=32)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    mfa_enabled = BooleanField('Enable MFA')
    submit = SubmitField('Register')

# Login form for login.html
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=32)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=128)])
    submit = SubmitField('Login')

# Adding credentials form for credentials.html and de_credentials.html
class AddCredentialForm(FlaskForm):
    website = StringField('Website', validators=[DataRequired(), Length(max=64)])
    username = StringField('Username', validators=[DataRequired(), Length(max=32)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Add Credential')

class MFAForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')