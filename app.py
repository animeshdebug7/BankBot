#create a flask app
from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from datetime import datetime
from threading import Thread
import os


app = Flask(__name__)
app.secret_key = os.urandom(24)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf=CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['Secret_Key'] = 'apple'
app.config['WTF_CSRF_SECRET_KEY'] = "secretkey"
# app.config['WTF_CSRF_SECRET_KEY'] = "apple"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    bank_id = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Registerform(FlaskForm):
    bank_id = StringField('Bank ID', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Bank ID"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_bank_id(self, bank_id):
        user = User.query.filter_by(bank_id=bank_id.data).first()
        if user:
            raise ValidationError('Bank ID already exists')

class Loginform(FlaskForm):
    bank_id = StringField('Bank ID', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Bank ID"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    return render_template('login.html' ,form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()
    return render_template('register.html', form = form)

@app.route('/index')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)