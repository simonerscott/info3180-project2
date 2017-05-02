from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, TextField, TextAreaField, SubmitField
from wtforms.validators import InputRequired, Email
from flask_wtf.file import FileAllowed, FileRequired, FileField




class Registration(FlaskForm):
    firstname = StringField("First Name", validators = [InputRequired()])
    lastname = StringField("Last Name", validators = [InputRequired()])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    username = StringField("Username", validators = [InputRequired()])
    password = PasswordField("New Password", [validators.DataRequired(), validators.EqualTo("confirmPassword", message = "Passwords Must Match")])
    confirmPassword = PasswordField("Repeat Password")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class WishListForm(FlaskForm):
    title = TextField('Title', validators = [InputRequired()])
    description = TextField('Description', validators = [InputRequired()])
    wish_url = TextField('wish_url', validators = [InputRequired()])

class AddItemForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired()])
    description = StringField('Description', validators=[InputRequired()])
    url = StringField('URL', validators=[InputRequired()])
    submit = SubmitField('Add to Wishlist') 
    
class ContactForm(FlaskForm):
    name = TextField('Name')
    email = TextField('E-Mail', validators=[InputRequired(), Email()])
    #subject = TextField('Subject',validators=[Required()])
    emailpass = PasswordField("Email Password",validators=[InputRequired])
    
    
    