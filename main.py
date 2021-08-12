from typing import final

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime


from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///relationship.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token,   options={"verify_signature": False}, algorithms=['HS256', ])
            dt=datetime.datetime.now()
            x=dt.timestamp()
            if data['exp'] > x:
                current_user = User.query.filter_by(public_id=data['public_id']).first()
            else:
                return jsonify({
                    'message': 'Token is expired !!'
                })


        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})


# route for loging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        d=datetime.datetime.now() + datetime.timedelta(minutes=2)
        f=d.timestamp()
        token = jwt.encode({
            'public_id': user.public_id,

            'exp': f

        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    user = User.query \
        .filter_by(email=email) \
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#
#         if 'x-access-token' in request.headers:
#             token = request.headers['x-access-token']
#
#         if not token:
#             return jsonify({'message' : 'Token is missing!'}), 401
#
#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'])
#             current_user = User.query.filter_by(public_id=data['public_id']).first()
#         except:
#             return jsonify({'message' : 'Token is invalid!'}), 401
#
#         return f(current_user, *args, **kwargs)
#
#     return decorated
#
# @app.route('/user', methods=['GET'])
# @token_required
# def get_all_users(current_user):
#
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})
#
#     users = User.query.all()
#
#     output = []
#
#     for user in users:
#         user_data = {}
#         user_data['public_id'] = user.public_id
#         user_data['name'] = user.name
#         user_data['password'] = user.password
#         user_data['admin'] = user.admin
#         output.append(user_data)
#
#     return jsonify({'users' : output})
#
# @app.route('/user/<public_id>', methods=['GET'])
# @token_required
# def get_one_user(current_user, public_id):
#
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})
#
#     user = User.query.filter_by(public_id=public_id).first()
#
#     if not user:
#         return jsonify({'message' : 'No user found!'})
#
#     user_data = {}
#     user_data['public_id'] = user.public_id
#     user_data['name'] = user.name
#     user_data['password'] = user.password
#     user_data['admin'] = user.admin
#
#     return jsonify({'user' : user_data})
#
# @app.route('/user', methods=['POST'])
# @token_required
# def create_user(current_user):
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})
#
#     data = request.get_json()
#
#     hashed_password = generate_password_hash(data['password'], method='sha256')
#
#     new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
#     db.session.add(new_user)
#     db.session.commit()
#
#     return jsonify({'message' : 'New user created!'})
#
# @app.route('/user/<public_id>', methods=['PUT'])
# @token_required
# def promote_user(current_user, public_id):
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})
#
#     user = User.query.filter_by(public_id=public_id).first()
#
#     if not user:
#         return jsonify({'message' : 'No user found!'})
#
#     user.admin = True
#     db.session.commit()
#
#     return jsonify({'message' : 'The user has been promoted!'})
#
# @app.route('/user/<public_id>', methods=['DELETE'])
# @token_required
# def delete_user(current_user, public_id):
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})
#
#     user = User.query.filter_by(public_id=public_id).first()
#
#     if not user:
#         return jsonify({'message' : 'No user found!'})
#
#     db.session.delete(user)
#     db.session.commit()
#
#     return jsonify({'message' : 'The user has been deleted!'})
#
# @app.route('/login')
# def login():
#     auth = request.authorization
#
#     if not auth or not auth.username or not auth.password:
#         return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
#
#     user = User.query.filter_by(name=auth.username).first()
#
#     if not user:
#         return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
#
#     if check_password_hash(user.password, auth.password):
#         token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
#
#         return jsonify({'token' : token.decode('UTF-8')})
#
#     return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
#
#
# @app.route('/signup', methods=['POST'])
# def signup():
#     # creates a dictionary of the form data
#     data = request.form
#
#     # gets name, email and password
#     name, email = data.get('name'), data.get('email')
#     password = data.get('password')
#
#     # checking for existing user
#     user = User.query.filter_by(email=email)
#     if not user:
#         # database ORM object
#         user = User(
#             public_id=str(uuid.uuid4()),
#             name=name,
#             email=email,
#             password=generate_password_hash(password)
#         )
#         # insert user
#         db.session.add(user)
#         db.session.commit()
#
#         return make_response('Successfully registered.', 201)
#     else:
#         # returns 202 if user already exists
#         return make_response('User already exists. Please Log in.', 202)
#
@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos': output})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify(todo_data)


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': "Todo created!"})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message': 'Todo item has been completed!'})


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message': 'Todo item deleted!'})


if __name__ == '__main__':
    app.run(debug=True)
