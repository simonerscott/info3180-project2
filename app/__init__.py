from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
#from flask.ext.bcrypt import Bcrypt


# Config Values
# location where file uploads will be stored
UPLOAD_FOLDER = 'app/static/uploads'


app = Flask(__name__)
app.config['SECRET_KEY'] = "supersecretkeyproject2"
app.config['TOKEN_SECRET'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://aymnjtnotqsssv:d9dd497e5b33a3510c5d641eccbd056bb787b15d4d8e89aedaabd50eb8a7a390@ec2-23-23-223-2.compute-1.amazonaws.com:5432/dbp92hm8ppeple'
#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://project2:project2@localhost/project2"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True # added just to suppress a warning


db = SQLAlchemy(app)
#bcrypt = Bcrypt(app)

# Flask-Login login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config.from_object(__name__)
from app import views, models
