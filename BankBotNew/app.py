#create a flask app
from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, Length, Email, EqualTo, ValidationError
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from datetime import datetime
from threading import Thread
import os
import cgi, cgitb


app = Flask(__name__)
app.secret_key = os.urandom(24)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bcrypt = Bcrypt(app)
csrf=CSRFProtect(app)
app.config['Secret_Key'] = 'apple'
app.config['WTF_CSRF_SECRET_KEY'] = "secretkey"
app.config['TESTING'] = False
# app.config['WTF_CSRF_SECRET_KEY'] = "apple"

x = cgi.FieldStorage()

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
    submit = SubmitField('REGISTER')

    def validate_bank_id(self, bank_id):
        user = User.query.filter_by(bank_id=bank_id.data).first()
        if user:
            raise ValidationError('Bank ID already exists')

class Loginform(FlaskForm):
    bank_id = StringField('Bank ID', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Bank ID"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('LOGIN')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    print('0')
    print(form.errors)
    if request.method == 'POST' and form.validate_on_submit():
        y = request.form.get('bank_id')
        # session['bank_id'] = 'bank_id'
        print('1')
        user = User.query.filter_by(bank_id=form.bank_id.data).first()
        print('2')
        if user:
            print('3')
            if bcrypt.check_password_hash(user.password, form.password.data):
                print('4')
                login_user(user)
                # return render_template('index.html', y=y)
                return redirect(url_for('index', y=y))
            else:
                print('5')
                return redirect(url_for('login'))
        else:
            print('6')
            return redirect(url_for('login'))
    return render_template('login.html' ,form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(bank_id=form.bank_id.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    # y = session.get('bank_id', None)
    y = request.args.get('y')
    print('hello')
    # y = session["y"]
    # y = request.args.get('y')
    # y = request.form['bank_id']
    print(y)
    # b_id = x.getvalue('bank_id')
    # print(b_id)
    return render_template('index.html', y = y)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    print('bye')
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)