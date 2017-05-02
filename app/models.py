from . import db

class User(db.Model):
    userid = db.Column(db.Integer, primary_key = True)
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(255), unique = True)
    password = db.Column(db.String(255))
   
    
    def __init__(self, userid, firstname, lastname, email, username, password):
        self.userid = userid
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.email = email
        self.password = password


    def is_authenticated(self):
        return True

    def is_active(self):
        return True


    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.userid)  # python 2 support
        except NameError:
            return str(self.userid)  # python 3 support

    def __repr__(self):
        return '<User %r>' % (self.username)
        
        
class Wishlist(db.Model):
    itemid = db.Column(db.Integer, primary_key= True)
    title = db.Column(db.String(80))
    description = db.Column(db.String(80))
    #address = db.Column(db.String(80))
    wish_url = db.Column(db.String(120))
    userid = db.Column(db.Integer, db.ForeignKey("user.userid"))
    thumbnail_img = db.Column()
  
    
    def __init__(self, itemid, title, description, wish_url,userid,thumbnail_img):
        self.itemid = itemid
        self.title = title
        self.description = description
        self.wish_url = wish_url
        self.userid = userid
        self.thumbnail_img = thumbnail_img        
        
        
        
