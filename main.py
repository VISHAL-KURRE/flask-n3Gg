import flask
from flask import Flask, flash, jsonify, current_app, render_template, request, redirect, url_for, session, json
import re
from flask_login import LoginManager, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_marshmallow import Marshmallow

# flask alkamy
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.inspection import inspect
from sqlalchemy import create_engine
from sqlalchemy.sql import func
import psycopg2
import os

# Fprm packages
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import DataRequired, Email

# ----------------------------------------- DB --------------------------------
# https://python.plainenglish.io/implementing-flask-login-with-hash-password-888731c88a99
# load_dotenv()
# PostgreSQL Database credentials loaded from the .env file
DATABASE = os.getenv('DATABASE')
DATABASE_USERNAME = os.getenv('DATABASE_USERNAME')
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
from psycopg2.extras import RealDictCursor
from sqlalchemy import TIMESTAMP

app = Flask(__name__ , template_folder='templates', static_folder='static')
template_folder='templates'
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(app)
# app.config['SECRET_KEY'] = 'any secret string'


try:
    conn = psycopg2.connect(host = 'containers-us-west-118.railway.app', dbname = 'railway', user="postgres",
    password = "WqBHil3xK73OBr8HXaM3" , cursor_factory = RealDictCursor)
    cursor = conn.cursor()
    print("databsde connedcted")
except Exception as error:
    print("Connection to datatbase failed")
    print(" Error.  ", error)

with app.app_context():
    # within this block, current_app points to app.
    print(current_app.name)
# CORS implemented so that we don't get errors when trying to access the server from a different server location
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:WqBHil3xK73OBr8HXaM3@containers-us-west-118.railway.app:7674/railway'

# app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:shanthi007@localhost/flaskmovies'
# https://github.com/Lumary2/Python/blob/master/Python_HTML_flask/app.py
db=SQLAlchemy(app)
# ----------------------------------------- login--------------------------------
from flask_login import LoginManager, logout_user, login_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
login_manager = LoginManager(app)

# ----------------------------------------- Schema--------------------------------
# Init ma
ma = Marshmallow(app)

# Product Schema
class UserSchema(ma.Schema):
  class Meta:
    fields = ('id', 'name', 'username', 'email', 'password')

# Init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# products_schema = ProductSchema(many=True, strict=True)

# ----------------------------------------- Form --------------------------------
class RegisterForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    name = StringField("name")
    email = StringField("email", validators=[validators.DataRequired(), validators.Email()])

class Serializer(object):

    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]

# ----------------------------------------- Models--------------------------------
class User(db.Model):
  __tablename__='User'
  id=db.Column(db.Integer,primary_key=True)
  name=db.Column(db.String(40))
  username=db.Column(db.String(40))
  email=db.Column(db.String(40))
  password = db.Column(db.String(40))
  createdDate =  db.Column(TIMESTAMP, nullable=False, server_default=func.now())

  def __init__(self,  username, password, name, email):
      # self.id = id
      self.username = username
      self.password = generate_password_hash(password)
      self.name = name
      self.email = email

  def is_authenticated(self):
      return True

  def is_active(self):
      return True

  def is_anonymous(self):
      return False

  def get_id(self):
      return str(self.id)

  def __repr__(self):
      return '<User %r>' % self.username
      # return f'<User {self.username}'

  def verify_password(self, pwd):
      return check_password_hash(self.password, pwd)



# ----------------------------------------- routes --------------------------------
@app.route('/')
def index():
    # return jsonify({"Choo Choo": "Welcome to your Flask app 🚅"})
    return render_template("index.html")

@app.route('/signup')
def signup():
    return render_template('signup.html')
        # return user_schema.jsonify(user)

# @login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

@app.route("/loginpage", methods=["GET", "POST"])
def loginpage():
    print('asdcszxcvbnzxcvbzxcvbzxcvb')
    return render_template('login.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    print('aaaaaaaaaa')
    data = request.get_json()
    username = data['username']
    password = data['password']
    # if data.validate():
    user = User.query.filter_by(username=username).first()

    if user and user.verify_password(password):

        print(user)
        login_user(user)
        # store user data in session
        session['user_id'] = user.id
        session['username'] = user.username

        print("Logged in successful")
        # return render_template('dashboard.html', user=User)
        # return render_template('dashboard.html')
        return user_schema.jsonify(user)
    else:

        flash("Login ivalido!")
        print("unsucessfull login")
        return render_template('loginpage.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    print("cvasdvzdvsdvsdvsdvs")
    data = request.get_json()
    name = data['name']
    print(name)
    username = data['username']
    print(username)
    email = data['email']
    print(email)
    password = data['password']
    print(password)
    confirm_password = data['cpassword']
    print(confirm_password  )
    if password == confirm_password:
        user = User(username, password, name, email)
        print(user)
        db.session.add(user)
        db.session.commit()
        # return user_schema.jsonify(user)
    # else:
    #     error = "Passwords do not match."
    return user_schema.jsonify(user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('loginpage'))




# example dashboard route
@app.route('/dashboard',methods=['GET'])
@login_required
def dashboard():
    print("in dashboard ")
    # Check if the user is logged in
    # if 'username' not in session:
    #     return redirect(url_for('login'))

    # get user data from session
    user_id = session.get('user_id')
    username = session.get('username')
    user = db.get_or_404(User, user_id)

    # Render the dashboard template with the user data
    return render_template('dashboard.html' , user=user, username = username)
    # return redirect(url_for('dashboard'))


@app.route("/user/<id>", methods=["DELETE"])
@login_required
def user_delete(id):
    print("user")
    user = db.get_or_404(User, id)

    user = User.query.get(id)
    print(user)
    db.session.delete(user)
    db.session.commit()
    return  user_schema.jsonify(user)
    # return render_template("index.html", user=user)

# @app.route('/user')
# def getuser():
#     users = User.query.first()
#     return jsonify({'in ': 'progress'})

# Get All Products
@app.route('/user', methods=['GET'])
@login_required
def get_products():
  print("dfvdfdfvf")
  all_userss = User.query.all()
  print(all_userss)
  # result = user_schema.dump(all_userss)
  return users_schema.jsonify(all_userss)
      # json.loads(all_userss)
      # ([dict(r) for r in all_userss], default=alchemyencoder)
  # return  jsonify(json_list = all_userss.all())
      # json.dumps(User.serialize_list(all_userss))?

# Get Single Products
@app.route('/user/<id>', methods=['GET'])
@login_required
def get_product(id):
  user = db.get_or_404(User, id)
  print(user.email)
  return user_schema.jsonify(user)

@app.route("/user/<username>")
@login_required
def user_by_username(username):
    user = db.one_or_404(db.select(User).filter_by(username=username))
    return render_template("index.html", user=user)


# Update a Product
@app.route('/users/<id>', methods=['PUT'])
@login_required
def update_product(id):
  user = db.get_or_404(User, id)
  print(user)

  name = request.json['name']
  password = request.json['password']
  email = request.json['email']
  username = request.json['username']

  User.name = name
  User.username = username
  User.email = email
  User.password = password
  print(User.username)
  user.verified = True
  db.session.commit()
  return user_schema.jsonify(user)

@app.route('/usersprofile', methods=['GET', 'PUT'])
@login_required
def usersprofile():
    print("   usersprofile     usersprofile")
    id = session.get('user_id')
    user = User.query.get(id)
    username = session.get('username')
    return render_template("userpage.html", user=user)

if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))