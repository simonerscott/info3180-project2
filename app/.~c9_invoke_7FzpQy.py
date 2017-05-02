"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

from app import app, db, login_manager
from flask import render_template, request, redirect, url_for, flash, _request_ctx_stack, jsonify, g, make_response
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from forms import Registration, LoginForm
from werkzeug.utils import secure_filename
from models import User
from functools import wraps
from sqlalchemy.sql import exists
from datetime import datetime, timedelta
from scrape import imgGet
import uuid
import hashlib
import time
from random import randint
import base64
import jwt
import os



def hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt


def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()



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


@app.route("/login", methods=["GET"])
def loginpage():
    form = LoginForm()
    return render_template("login.html", form=form)
    
@app.route("/register/", methods=["GET"])
def registerpage():
    form = Registration()
    return render_template("register.html",form=form)

@app.route("/api/users/register", methods = ["POST"])
def register():
    json_data = request.json
    user = User(
         userid = randint(620000000,620099999),
         firstname=json_data['firstname'],
         lastname=json_data['lastname'],
         username=json_data['username'],
         email=json_data['email'],
         password=hash_password(json_data['password']))
    if user:
        db.session.add(user)
        db.session.commit()
        token = create_token(user)
        payload = jwt.decode(token,app.config['TOKEN_SECRET'], algorithm=['HS256']) 
        response = jsonify(token=token,information={"error":"null","data":{'token':token,'expires': timeinfo(payload['exp']),'user':{'id':user.userid,'email': user.email,'name':user.username},"message":"Success"}})
    else:
        response = jsonify({"error":"1","data":{},"message":'failed'})
    return response
        #token = AuthToken()
        #response = token.__repr__()
        #return jsonify(response)
    


@app.route("/api/users/login", methods = ["POST"])
def login():
    json_data = request.json
    user = User.query.filter_by(username=json_data['username']).first()
    if not user or not check_password_hash(user.password,request.json['password']):
        response = jsonify({"error":"1","data":{},"message":'failed'})
        response.status_code = 401
    else:
        token = create_token(user)
        payload = jwt.decode(token,app.config['TOKEN_SECRET'], algorithm=['HS256']) 
        response = jsonify(token=token,information={"error":"null","data":{'token':token,'expires': timeinfo(payload['exp']),'user':{'id':user.userid,'email': user.email,'name':user.display_name},"message":"Success"}})
    return response
    
    

#login required decorator    
@app.route("/api/thumbnails", methods = ["GET"])
@login_required
def thumbnails():
    """Get Data"""
    data = request.get_json(force = True)
    url = data["url"]
    
    """Send requested data"""
    imgList = urlList(url)
    
    if imgList:
        output = {'error': None, "data":{"thumbnails": imgList}, "message":"Success"}
    else:
        output = {'error': True, "data":{}, "message":"Unable to extract thumbnails"}
    return jsonify(output)

#Displaying wishlist
@app.route("/api/users/{userid}/wishlist")
@login_required
def wishlist(userid):
    if user.is_authenticated:
        #FlaskForm = WishListForm()
        #user_var= {'id'=User.userid, 'firstname': User.firstname, 'lastname':User.lastname, 'username':User.username, 'email':User.email, 'password':User.password}
        
        return render_template("wishlist.html")


@app.route("/api/users/{userid}/wishlist", methods = ["GET", "POST"])
@login_required
def additem(userid, itemid):
    user_file= User.query.filter_by(userid).first()
    user_var= {'id':User.userid, 'firstname': User.firstname, 'lastname':User.lastname, 'username':User.username, 'email':User.email, 'password':User.password}
    FlaskForm = WishListForm()
    if request.method == "POST":
        #json object
        title = request.FlaskForm['title']
        description = request.FlaskForm['description']
        url = request.FlaskForm['site_url']
        #newwish= Wishlist(wish_url= request.json ['url'], userid= userid, description = request.json['description'], thumbnail_img= request.json['image]'])
        n
        # Add wish to wishlist
        db.session.add(newwish)
        db.session.commit()
        
    
        #check if item was added
        temp = db.session.query(wishlist.query.filter_by(id=itemid).first())
        if temp == itemid:
            flash ('Item successfully added to your wishlist', 'success')
        else:
            
            # Flash user that error occurred
            flash ('Error! Item could not be added to wishlist. Please try again', 'fail')
            
            #Returns user to wishlist after error
            return redirect(url_for("wishlist", userid=current_user.get_id()))
            
	        
        #Return user to wishlist after successfully adding wish to wishlist
        return redirect(url_for("wishlist", userid=current_user.get_id())) 
        
    #Return user's wishlist if method = GET    
    elif request.method == "GET":
        return redirect(url_for("wishlist", userid=current_user.get_id())) 
        
    else:
        return redirect(url_for("wishlist", userid=current_user.get_id())) 


@app.route("/api/users/<int:userid>/wishlist/<int:itemid>", methods=["DELETE"])
@login_required
def removeitem(userid, itemid):
    if request.method == "DELETE":
        # remove item from wishlist
        db.session.delete(wishlist.query.filter_by(id=itemid).first())
        db.session.commit()

	# query again to make sure it was deleted 
	temp = db.session.query(wishlist.query.filter_by(id=itemid).first())
	if temp == None:
		# flash user for successful delete
        	flash('Item deleted','success')
		return redirect(url_for("wishlist", userid=current_user.get_id()))
	else:
		# flash user for unsuccessful delete
        	flash('Item not deleted', 'fail')

		# redirect user to their wishlist page
        	return redirect(url_for("wishlist", userid=current_user.get_id()))

    else:
        # flash user for successful delete
        flash('Please try again', 'fail')

        return redirect(url_for("wishlist", userid=current_user.get_id()))    
   
   
   
@app.route("/logout")    
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'danger')
    return redirect(url_for('home'))

def timeinfo(entry):
    day = time.strftime("%a")
    date = time.strftime("%d")
    if (date <10):
        date = date.lstrip('0')
    month = time.strftime("%b")
    year = time.strftime("%Y")
    return day + ", " + date + " " + month + " " + year

# Flash errors from the form if validation fails
def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % ( getattr(form, field).label.text, error))   
   
            
###.l
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
    app.run(debug=True, host="0.0.0.0",port="8080")
