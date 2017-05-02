"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

from app import app, db, login_manager
from flask import render_template, request, redirect, url_for, flash, _request_ctx_stack, jsonify, g
from flask_login import login_user, logout_user, current_user, login_required
from forms import Registration, LoginForm
from werkzeug.utils import secure_filename
from models import User
from functools import wraps
from sqlalchemy.sql import exists
from datetime import datetime, timedelta
import random
import base64
import jwt
import os





# This decorator can be used to denote that a specific route should check
# for a valid JWT token before displaying the contents of that route.
def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    auth = request.headers.get('Authorization', None)
    if not auth:
      return jsonify({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}), 401

    parts = auth.split()

    if parts[0].lower() != 'bearer':
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}), 401
    elif len(parts) == 1:
      return jsonify({'code': 'invalid_header', 'description': 'Token not found'}), 401
    elif len(parts) > 2:
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}), 401

    token = parts[1]
    try:
         payload = jwt.decode(token, 'some-secret')

    except jwt.ExpiredSignature:
        return jsonify({'code': 'token_expired', 'description': 'token is expired'}), 401
    except jwt.DecodeError:
        return jsonify({'code': 'token_invalid_signature', 'description': 'Token signature is invalid'}), 401

    g.current_user = user = payload
    return f(*args, **kwargs)

  return decorated




#token should be generated when user logs in
def create_token(user):
    payload = {
        'sub': user.username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(payload, app.config['TOKEN_SECRET'], )
    token = jwt.encode(payload, app.config['TOKEN_SECRET'], algorithm='HS256')
    return token.decode('unicode_escape')


def parse_token(req):
    token = req.headers.get('Authorization').split()[1]
    return jwt.decode(token, app.config['TOKEN_SECRET'])




###
# Routing for your application.
###

@app.route('/')
def home():
    """Render website's home page."""
    return render_template('home.html')

@app.route('/about/')
def about():
    """Render the website's about page."""
    return render_template('about.html')




@app.route("/api/users/register", methods = ["POST", "GET"])
def register():
    form = Registration()
    
    if request.method == "POST" and form.validate_on_submit():

        firstname = request.form['firstname']
        lastname = request.form["lastname"]
        email = request.form["email"]
        username = request.form["username"]
        
        
        while True:
            userid = random.randint(620000000, 620099999) 
            if not db.session.query(exists().where(User.userid == str(userid))).scalar():
                break

            
        #getting the data that was entered from the form. Then adding and commiting it to the db
        user = User(userid, firstname, lastname, email, username)
        db.session.add(user)
        db.session.commit()
        
        token = create_token(user)
        payload = jwt.decode(token, app.config['TOKEN_SECRET'], algorithm=['HS256']) 
        
        # jsonify(userid = user.userid, username = user.username)
        
        response = jsonify(token = token, information = {"error":"null", "data":{'token':token, 'expires': payload['exp'],\
        'user':{'id':user.userid,'email': user.email,'username':user.username},"message":"Success"}})
        
        
        flash("User Added!", category = 'success')
        return redirect(url_for('register')) #profiles is where it will display all the users
    
    flash_errors(form)
    return render_template('register.html', form = form)

    


@app.route("/api/users/login", methods = ["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return "redirect(url_for('secure_page'))"
    
    form = LoginForm()
    if request.method == "POST"  and form.validate_on_submit():
        # change this to actually validate the entire form submission
        # and not just one field
        # if form.username.data:
        # Get the username and password values from the form.
        username = form.username.data
        password = form.password.data
        
        
        # using your model, query database for a user based on the username
        # and password submitted
        # store the result of that query to a `user` variable so it can be
        # passed to the login_user() method.
        user = User.query.filter_by(username = username, password = password).first()
        
        
        if user is not None:
            # get user id, load into session
            login_user(user)
            flash('Logged in Successfully.', 'success')
            next = request.args.get('next')
            return "redirect(url_for('secure_page'))"
        else:
            flash('Username or Password is Incorrect.', 'danger')


            # # get user id, load into session
            # login_user(user)

            # # remember to flash a message to the user
            # return redirect(url_for("home")) # they should be redirected to a secure-page route instead
    return render_template("login.html", form = form)



# user_loader callback. This callback is used to reload the user object from
# the user ID stored in the session
@login_manager.user_loader
def load_user(id):
    return UserProfile.query.get(int(id))
    
    

#login required decorator    
@app.route("/api/users/{userid}/wishlist", methods = ["POST", "GET"])
@login_required
def wishlist(userid):
    return render_template("wishlist.html")
    
    

@app.route("/api/thumbnails", methods = ["GET"])
@login_required
def thumbnails():
    return ""



@app.route("/api/users/{userid}/wishlist/{itemid})", methods = ["DELETE"])
@login_required
def deleteItem(userid,itemid):
    return ""




@app.route("/logout")    
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'danger')
    return redirect(url_for('home'))



# Flash errors from the form if validation fails
def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % ( getattr(form, field).label.text, error))   
            
###
# The functions below should be applicable to all Flask apps.
###

@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port="8080")
