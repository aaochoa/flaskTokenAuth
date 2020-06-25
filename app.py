from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy 
from flask_marshmallow import Marshmallow 
import yaml
import psycopg2
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# Variables YAML and setting up postgres URL
conf = yaml.load(open('application.yml'), Loader=yaml.BaseLoader)
POSTGRES_URL = conf['development']['host']
POSTGRES_USER = conf['development']['user']
POSTGRES_PW = conf['development']['password']
POSTGRES_DB = conf['development']['database']
DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB)

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = conf['general']['secret_key']

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLite database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')

# Init db
db = SQLAlchemy(app)

# Init ma
ma = Marshmallow(app)

# User Class/Model
class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.String(50), unique=True)
  name = db.Column(db.String(50))
  password = db.Column(db.String(80))
  admin = db.Column(db.Boolean)
  products = db.relationship('Product', backref='user', lazy=True)

# User Schema
class UserSchema(ma.Schema):
  class Meta:
    fields = ('public_id', 'name', 'password', 'admin')

# Product Class/Model
class Product(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(100), unique=True)
  description = db.Column(db.String(200))
  price = db.Column(db.Float)
  qty = db.Column(db.Integer)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Product Schema
class ProductSchema(ma.Schema):
  class Meta:
    fields = ('id', 'name', 'description', 'price', 'qty')

# Init schema
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Token authentication
def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None
    if 'x-access-token' in request.headers:
      token = request.headers['x-access-token']
    if not token:
      return jsonify({'message' : 'Token is missing!'}), 401
    try: 
      data = jwt.decode(token, app.config['SECRET_KEY'])
      current_user = User.query.filter_by(public_id=data['public_id']).first()
    except:
      return jsonify({'message' : 'Token is invalid!'}), 401
    return f(current_user, *args, **kwargs)
  return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})
  users = User.query.all()
  result = users_schema.dump(users)
  return jsonify(result)

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})
  user = User.query.filter_by(public_id=public_id).first()
  if not user:
    return jsonify({'message' : 'No user found!'})
  user_data = {}
  user_data['public_id'] = user.public_id
  user_data['name'] = user.name
  user_data['password'] = user.password
  user_data['admin'] = user.admin
  return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})
  data = request.get_json()
  hashed_password = generate_password_hash(data['password'], method='sha256')
  new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
  db.session.add(new_user)
  db.session.commit()
  return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})
  user = User.query.filter_by(public_id=public_id).first()
  if not user:
    return jsonify({'message' : 'No user found!'})
  user.admin = True
  db.session.commit()
  return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})
  user = User.query.filter_by(public_id=public_id).first()
  if not user:
    return jsonify({'message' : 'No user found!'})
  db.session.delete(user)
  db.session.commit()
  return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
  auth = request.authorization
  if not auth or not auth.username or not auth.password:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
  user = User.query.filter_by(name=auth.username).first()
  if not user:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
  if check_password_hash(user.password, auth.password):
    token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token' : token.decode('UTF-8')})
  return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# Create a Product
@app.route('/product', methods=['POST'])
@token_required
def add_product(current_user):
  name = request.json['name']
  description = request.json['description']
  price = request.json['price']
  qty = request.json['qty']
  user = current_user
  new_product = Product(name, description, price, qty, user)
  db.session.add(new_product)
  db.session.commit()
  return product_schema.jsonify(new_product)

# Get All Products
@app.route('/product', methods=['GET'])
@token_required
def get_products(current_user):
  all_products = Product.query.all()
  result = products_schema.dump(all_products)
  return jsonify(result)

# Get Single Products
@app.route('/product/<id>', methods=['GET'])
@token_required
def get_product(current_user, id):
  product = Product.query.get(id)
  return product_schema.jsonify(product)

# Update a Product
@app.route('/product/<id>', methods=['PUT'])
@token_required
def update_product(current_user, id):
  product = Product.query.get(id)
  name = request.json['name']
  description = request.json['description']
  price = request.json['price']
  qty = request.json['qty']
  product.name = name
  product.description = description
  product.price = price
  product.qty = qty
  db.session.commit()
  return product_schema.jsonify(product)

# Delete Product
@app.route('/product/<id>', methods=['DELETE'])
@token_required
def delete_product(current_user, id):
  product = Product.query.get(id)
  db.session.delete(product)
  db.session.commit()
  return product_schema.jsonify(product)

# Run Server
if __name__ == '__main__':
  app.run(debug=True)