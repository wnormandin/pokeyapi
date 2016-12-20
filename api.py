from flask import Flask, send_from_directory, jsonify, make_response
from flask import request, url_for, Response, abort
from passlib.apps import custom_app_context as password_context
from flask_sqlalchemy import SQLAlchemy

import os,sys
from datetime import datetime, timedelta
import time
from functools import wraps


api = Flask(__name__)
api.config['SQLALCHEMY_DATABASE_URI']='sqlite:////home/pokeybill/api/db/test.db'
db = SQLAlchemy(api)

# Decorators
def require_token(func):
    @wraps(func)
    def check_token(*args, **kwargs):
        #with api.app_context():
        try:
            token_result = verify_token(request.json.get('api_token'))
        except AttributeError:
            token_result = None
        if not token_result or token_result is None:
            abort(401)
            return
        elif token_result == "expired":
            return make_response(jsonify(
                                {'error':
                                    {
                                    'message':'Expired session token'
                                    }
                                }), 401
                            )
        else:
            return func(*args, **kwargs)
    return check_token


class Base(db.Model):
    """ Base class for other database objects """
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, default=datetime.utcnow())
    modified = db.Column(db.DateTime, default=datetime.utcnow(),
                         onupdate=datetime.utcnow())


class Token(Base):
    """ Authentication Token Table """
    token = db.Column(db.String(128))
    ipaddr = db.Column(db.String(16))

    def generate(self):
        salt = 'Hy7XXxjhsKSUjem993kSjQQaWslfcuUhSDHgu8S=='
        self.token = password_context.encrypt(
                    '{}{}'.format(salt,time.time())
                    )
        db.session.commit()

def verify_token(token):
    if token is None: return None
    t = Token.query.filter_by(token=token).first()
    try:
        if (datetime.today() - timedelta(days=1)) > t.created:
            return 'expired'
        if t.ipaddr != request.environ.get('HTTP_X_REAL_IP',request.remote_addr):
            abort(401)
            return False
    except:
        return False
    return t

# User Functions
class User(Base):
    """ API User Functions: {register,auth,delete} """
    username = db.Column(db.String(50),unique=True)
    pass_hash = db.Column(db.String(128))
    email = db.Column(db.String(50),unique=True)
    ipaddr = db.Column(db.String(16))
    active = db.Column(db.Boolean(), default=True)
    last_login = db.Column(db.DateTime(timezone=False))
    current_login = db.Column(db.DateTime(timezone=False))
    current_login_ipaddr = db.Column(db.String(16))
    security_group = db.Column(db.String(10), default='Users')
    login_count = db.Column(db.Integer, default=1)

    field_list = ['username','email','ipaddr','active',
                  'last_login','current_login','current_login_ipaddr',
                  'security_group','created','modified']

    def __init__(self, username):
        self.username = username

    def hash_password(self, passwd):
        self.pass_hash = password_context.encrypt(passwd)

    def verify_password(self, passwd):
        return password_context.verify(passwd, self.pass_hash)

    def do_logon(self,passwd):
        payload = {}
        if self.verify_password(passwd):
            payload['last'] = self.last_login
            self.last_login = self.current_login
            self.current_login = datetime.utcnow()
            self.current_login_ipaddr = request.environ.get(
                                        'HTTP_X_REAL_IP',
                                        request.remote_addr
                                        )
            self.login_count += 1
            payload['result']=True

            # Create api_token
            token = Token()
            token.generate()
            token.ipaddr = request.environ.get('HTTP_X_REAL_IP',
                                        request.remote_addr
                                        )
            payload['api_token']=token.token
            payload['valid_ip']=token.ipaddr
            db.session.add(token)
        else:
            payload['result']=False

        db.session.commit()
        return payload


# API Logging
class ApiLog(Base):
    """ API Logging Functions: {generate,write,refresh} """

    log_level = db.Column(db.String(10))
    log_message = db.Column(db.String(79))

    def __init__(self, level, msg):
        self.log_level = level
        self.log_message = msg
        self.execute()

    def execute(self):
        db.session.add(self)
        db.session.commit()

# Routes
# Default route, provide basic usage
@api.route('/')
def api_usage():
    """ Provides an API usage URL (https://pokeybill.us/api) """
    return jsonify({
                    'api':'PokeyDev Entry Point - pokeybill.us/api',
                    'usage':'/usage',
                    'users':'/users',
                    'login':'/login',
                    'details':{
                        'user registration':'POST {username,password,email} to /users',
                        'login':'POST {username,password} to /login, returns a token',
                        'tokens':'authentication tokens are required as POST {api_token}',
                        'user details':'POST {api_token} to /users/USERNAME',
                        'email':'validation is required before API usage',
                        }
                    })

# Favicon for browser connectivity
@api.route('/favicon.ico', methods=['GET'])
def favicon():
    """ Delivers favicon.ico for browser compatibility """
    return send_from_directory(
                os.path.join(
                    api.root_path,
                    'static'),
                'favicon.ico')

# Function-specific usage messages (stored in docstrings)
@api.route('/usage/', methods=['GET'])
@api.route('/usage/<func_name>', methods=['GET'])
def function_usage(func_name=None):
    """
    For all other functions, function_usage(func) returns
    the __doc__ field value for that function.

    If the passed func_name is not in globals(), a usage
    message is returned
    """

    usage="Display function-specific usage: /usage/function_name"

    try:
        return jsonify({func_name:globals()[func_name].__doc__})
    except KeyError:
        # When the key isn't found, return the function_usage() docstring
        retval = "'{}' not found".format(func_name)
        payload = {'usage':usage,'error':retval}
        return jsonify(payload)

# API User Functions
@api.route('/users/', methods=['GET'])
def users():
    """ User authentication, registration, and other requests """
    return function_usage('users')

@api.route('/users/<username>', methods=['POST'])
@require_token
def user_info(username):

    payload = {'username':username}
    u = User.query.filter_by(username=username).first()

    if u is None:
        payload['result']='User "{}" not found'.format(username)
    else:
        payload['result']=True
        payload[username]={}
        for attr in User.field_list:
            payload[username][attr]=getattr(u,attr)

    return jsonify(payload)

@api.route('/users/', methods=['POST'])
def register_user():
    """ User registration functions {username:<username>, password:<password>, email:<email>} """

    required_attributes = 'username','password','email'

    if not request.json or not all([j in request.json for j in required_attributes]):
        if not request.json:
            missing='No data received'
        else:
            missing=[]
            for attr in required_attributes:
                if attr not in request.json:
                    missing.append(attr)

        return make_response(jsonify({'error':{
                                'message':'Missing value(s) in POST data',
                                'value':'{}'.format(missing)
                                }}), 400)

    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    u = User(request.json.get('username'))
    u.hash_password(request.json.get('password'))
    u.email = request.json.get('email')
    u.ipaddr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    u.last_login = datetime.utcnow()
    u.current_login = datetime.utcnow()
    u.current_login_ipaddr = ip

    db.session.add(u)
    db.session.commit()

    return jsonify({'username':u.username,'action':'register','result':True})

@api.route('/login',methods=['GET','POST'])
def do_login():
    """ User login portal - POST credentials for an API token {username,password} """
    if request.method != 'POST':
        return function_usage('login_details')
    else:
    # Registers an API token which expires in 24 hours
        required_attributes = 'username','password'

        if not request.json or not all([j in request.json for j in required_attributes]):
            if not request.json:
                missing='No data received'
            else:
                missing=[]
                for attr in required_attributes:
                    if attr not in request.json:
                        missing.append(attr)

            return make_response(jsonify({'error':{
                            'message':'Missing value(s) in POST data',
                            'value(s)':'{}'.format(missing)
                            }}), 400)

        u = User.query.filter_by(username=request.json.get('username')).first()
        if u is None:
            abort(404)
            return
        else:
            return jsonify(u.do_logon(request.json.get('password')))

# Error Responses
@api.errorhandler(400)
def invalid(error):
    return make_response(jsonify({'error':'Invalid Request'}),400)

@api.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error':'Access Denied'}),401)

@api.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error':'Not found'}), 404)
