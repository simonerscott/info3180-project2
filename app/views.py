"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

from app import app, db, login_manager
from flask import render_template, request, redirect, url_for, flash, _request_ctx_stack, jsonify, g, make_response,session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from forms import Registration, LoginForm, WishListForm, AddItemForm, ContactForm
from werkzeug.utils import secure_filename
from models import *
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
import smtplib


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
    
@app.route("/wishlist", methods=["GET"])
def wishlistpage():
    form = AddItemForm()
    formShare = ContactForm()
    return render_template("wishlist.html", form=form, formShare = formShare)
    
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
    uname = request.get_json()["username"]
    pwrd = request.get_json()["password"]
    user = db.session.query(User).filter_by(username=uname).first()
    if not user:
        response = jsonify({"error":"1","data":{},"message":'failed'})
        response.status_code = 401
    else:
        login_user(user)
        session["logged_in"] = True
        session["userid"] = user.userid
        token = create_token(user)
        payload = jwt.decode(token,app.config['TOKEN_SECRET'], algorithm=['HS256']) 
        response = jsonify(token=token,information={"error":"null","data":{'token':token,'expires': timeinfo(payload['exp']),'user':{'id':user.userid,'email': user.email,'name':user.username},"message":"Success"}})
        return redirect(url_for('wishlistpage', next=request.url, userid=current_user.get_id()))
    return response
    

#login required decorator    
@app.route("/api/thumbnails", methods = ["GET"])
@login_required
def thumbnails():
    """Get Data"""
    # get url from form
    url = request.args.get('url')
    print "#"
    print url
    return jsonify({'error': None, 'message': 'Success', 'thumbnails': imgGet(url)})

    
# #Displaying wishlist
# @app.route("/api/users/{userid}/wishlist")
# @login_required
# def wishlist(userid):
#     if user.is_authenticated:
#         #FlaskForm = WishListForm()
#         #user_var= {'id'=User.userid, 'firstname': User.firstname, 'lastname':User.lastname, 'username':User.username, 'email':User.email, 'password':User.password}
        
#         return render_template("wishlist.html")


@app.route("/api/users/<int:userid>/wishlist", methods = ["GET", "POST"])
@login_required
def additem(userid):
    print"\n\n\n\n\nn\\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
    form = AddItemForm()
    if request.method == "POST":
        if form.validate_on_submit():
            userid = userid
            title = form.data.title
            description = form.data.description
            url = form.data.url
            thumbnails = request.form['thumbnails'] #thumbnailed checked
            itemid = randint(1,5000)
            new_wish= Wishlist(itemid=itemid,title=title,description=description,thumbnail_img=thumbnails,wish_url=url,userid=userid)
            # Add wish to wishlist
            if new_wish:
                db.session.add(new_wish)
                db.session.commit()
                flash(''+title+' was successfully added.', 'Success')
                response = jsonify({"error":"null","data":{'title': new_wish.title,'description': new_wish.description,'url': new_wish.url},"message":"Success"})
            else:
                flash(''+title+' is already on your list', 'Add Error')
                response = jsonify({"error":"1","data":{'title': new_wish.title,'description': new_wish.description,'url': new_wish.url},"message":"Error"})
            return response
        
    if request.method == "GET":
        wishes = db.session.query(Wishlist).filter_by(userid = userid).all()
        wishlist = []
        for wish in wishes:
            wishlist.append({'id':wish.itemid,'title': wish.title,'description':wish.description,'url':wish.url})
        if(len(wishlist)>0):
            response = jsonify({"error":"null","data":{"wishes":wishlist},"message":"Success"})
        else:
            response = jsonify({"error":"1","data":{},"message":"No such wishlist exists"})
        return response
        

@app.route("/api/users/<int:userid>/wishlist/<int:itemid>", methods=["POST"])
@login_required
def removeitem(userid, itemid):
    if request.method == "POST":
        wish = db.session.query(Wishlist).filter_by(itemid=itemid,userid=userid).first()
        db.session.delete(wish)
        db.session.commit()
        response = jsonify({'error':'null','message':"Success"})
        return response
    else:
        response = jsonify({'error':'1','message':"Failed"})
        return response  
   
@app.route("/api/users/<int:userid>/wishlist/share", methods=["GET","POST"])
@login_required
def contact(userid):
    form = ContactForm()
    if request.method == "POST":
        if form.validate_on_submit():
            fromemail = current_user.email
            fromname = current_user.first_name+' '+current_user.last_name
            name = form.name.data
            email = form.email.data
            subject = current_user.first_name+' '+current_user.last_name + "'s Wishlist "
            
            
            items = WishlistItem.query.filter_by(owner=current_user.get_id()).all()
            msg = ""
            for item in items:
                msg += "\n"+"*"*20+"\n"+item
            
            sendemail(fromname=fromname,fromemail=fromemail,fromsubject=subject,msg=msg,toname=name,toaddr=email)
            flash("Message sent.","Success")
            return redirect(url_for('wishlist', userid=current_user.get_id()))
    
    def sendemail(fromname,fromemail,fromsubject,msg,toname,toaddr):
        message = """From: {} <{}>\nTo: {} <{}>\nSubject: {}\n\n{}"""
        
        messagetosend = message.format(
                                     fromname,
                                     fromemail,
                                     toname,
                                     toaddr,
                                     #fromsubject,
                                     msg)
        
        # Credentials (if needed)
        username = ''
        password = ''
        
        # The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(username,password)
        server.sendmail(fromemail, toaddr, messagetosend)
        server.quit()
        return
    
    return redirect(url_for('wishlist', userid=current_user.get_id()))
        
   
@app.route("/logout")    
@login_required
def logout():
    logout_user()
    session.pop('userid', None)
    session.pop('logged_in', None)
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

@login_manager.user_loader
def load_user(id):
    return db.session.query(User).get(int(id))

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
