from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, TextAreaField
from wtforms.validators import EqualTo, Length, Email, DataRequired, ValidationError
from project1.models import User

class RegisterForm(FlaskForm):

    def validate_username(self, username_check):
        user = User.query.filter_by(username=username_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_check):
        email_address = User.query.filter_by(email_address=email_address_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')


    username = StringField(label='User Name', validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(label='Email Address', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):

    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')

class NoteForm(FlaskForm):
    data = TextAreaField(label='Name')
    submit = SubmitField(label='Add Note')

class DeleteForm(FlaskForm):
    delete = SubmitField(label='Delete')

