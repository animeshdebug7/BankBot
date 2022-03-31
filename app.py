#create a flask app
from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, InputRequired, Length, Email, EqualTo, ValidationError
from flask_login import login_user, login_required, logout_user, current_user
# from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from datetime import datetime
from chat import get_response
from flask import Flask
from flask import render_template, jsonify, request
from threading import Thread
import os
from flask_cors import CORS, cross_origin
import pandas as pd, numpy as np
import logging
import matplotlib.pyplot as plt, seaborn as sns
import warnings;warnings.filterwarnings("ignore")
import cgi, cgitb
import sqlite3

# setup logging 
log_format = "%(levelname)s %(asctime)s -> %(message)s"
logging.basicConfig(filename='User_summary.log', level=logging.DEBUG, format=log_format)
logger = logging.getLogger()

df = pd.read_csv('Transaction_Data2.csv')
df.Date = pd.to_datetime(df.Date)

app = Flask(__name__)
CORS(app)

def connect_db():
    sql = sqlite3.connect('./Details_new.db')
    sql.row_factory = sqlite3.Row
    return sql

def get_db():
    #Check if DB is there
    if not hasattr(g, 'sqlite3'):
        g.sqlite3_db = connect_db()
    return g.sqlite3_db

#close the connection to the database automatically
@app.teardown_appcontext
def close_db(error):
    #if global object has a sqlite database then close it. If u leave it open noone can access it and gets lost in memory causing leaks.
    if hasattr(g, 'sqlite_db'):
        g.sqlite3_db.close()

app.secret_key = os.urandom(24)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bcrypt = Bcrypt(app)
# csrf=CSRFProtect(app)
app.config['Secret_Key'] = 'apple'
# app.config['WTF_CSRF_SECRET_KEY'] = "secretkey"
app.config['TESTING'] = False

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

# class Registerform(FlaskForm):
#     bank_id = StringField('Bank ID', validators=[DataRequired(), Length(min=9, max=9)], render_kw={"placeholder": "Bank ID"})
#     password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
#     submit = SubmitField('REGISTER')

#     def validate_bank_id(self, bank_id):
#         user = User.query.filter_by(bank_id=bank_id.data).first()
#         if user:
#             raise ValidationError('Bank ID already exists')

class Loginform(FlaskForm):
    bank_id = StringField('Bank ID', validators=[InputRequired(), Length(min=9, max=9)], render_kw={"placeholder": "Bank ID"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('LOGIN')

def plot_chart(usr_df:pd.DataFrame, yr:list='all', mnt:list='all'):
    """
    This functions plots a brief analytical overview of the account.
    PARAMETER:
    -----------------------------------------
    usr_df: it is a dataframe consisting all transactional records of a particual user
    yr: it is year for which the graph should be plotted, it will be only used on graph title
    """
    sns.set(rc={'axes.facecolor':'cornflowerblue', 'figure.facecolor':'cornflowerblue'})
    fig, axs = plt.subplots(2, 2, figsize=(16,12))
    msg = f"""Account Summary for {'all years' if yr=='all' else f'year {yr}'} 
    {'' if mnt=='all' else f"and month {mnt}"}"""
    fig.suptitle(msg, fontsize=16, fontweight=0.6, y=0.93, color='black')

    # Graph 1: Pie Chart: Account Deposit history over time
    # ----------------------------------------------
    colors = sns.color_palette('bright')
   
    data_D = usr_df[usr_df.Transaction_Type=='D'].groupby('Transaction')['Transaction_amount'].sum()
    label_D= usr_df[usr_df.Transaction_Type=='D'].groupby('Transaction')['Transaction_amount'].sum().index

    axs[1][0].pie(data_D, labels=label_D, colors = colors, autopct='%.0f%%')
    axs[1][0].set_title('Deposit summary')

    # Graph 2: Pie Chart: Account Withdrawl history over time
    # ----------------------------------------------
    colors = sns.color_palette('bright')
   
    data_W = usr_df[usr_df.Transaction_Type=='W'].groupby('Transaction')['Transaction_amount'].sum()
    label_W= usr_df[usr_df.Transaction_Type=='W'].groupby('Transaction')['Transaction_amount'].sum().index

    axs[1][1].pie(data_W, labels=label_W, colors = colors, autopct='%.0f%%')
    axs[1][1].set_title('Withdrawal summary')
    

    # Graph 3: Line Chart: Account's balance status over time
    # -----------------------------------------------
    sns.lineplot(usr_df.Date, usr_df.Balance, linewidth=2, color='purple', ax=axs[0][0])
    axs[0][0].set_title('Balance summary')
    # if user is filterd data for only one year then 
    # it will plot transactional status month by month
    if yr!='all' and len(yr)==1:
        usr_df.Date = usr_df.Date.dt.month
    else: usr_df.Date = usr_df.Date.dt.year

    # Graph 4: Stacked Bar Chart: Account's Transactional status over time
    # -------------------------------------------------
    usr_df[['Date', 'Transaction_Type', 'Transaction_amount']] \
    .groupby(['Date', 'Transaction_Type']).sum().unstack() \
    .plot(kind='bar', stacked=True, color=['green', 'red'], ax=axs[0][1])
    axs[0][1].legend(labels=['Deposit', 'Withdrawal'])
    axs[0][1].set_title('Transaction summary')
    axs[0][1].ticklabel_format(style='plain', axis='y')
    axs[0][1].tick_params(labelrotation=0)

    return fig

def usr_summary(ac:int, df_trnx:pd.DataFrame=df, yr:list='all', mnt:list='all') -> pd.DataFrame:
    """
    DESCRIPTION:
    ----------------------------------------------
    This functions extract all data of specified account holder with specified
    year and month filters, plot account summary and save it 

    PARAMETER:
    ----------------------------------------------
    df_trnx: dataframe consisting all users transactional records

    ac: Account number of user

    yr: Year of which the data to be filtered out
    * {* by default it's value is 0 which means all available year data
       * possible arguments can be any other available year eg 2018, 2019
       * must be passed in list, even it is a single year}

    mnt: Month of which the data to be filtered out 
    * {* by default it's value is 0 which means all available month data
       * possible arguments can be any other available month eg 7, 9
       * must be passed in list, even it is a single month}  

    RETURN:
    -----------------------------------------------
    usr_df: a pandas dataframe consisting all transactional records of
    specified user.
    """
    # adding log 
    logger.info(f"func called: 'usr_summary', args passed: ac {ac}, yr {yr}, mnt {mnt}")

    df_trnx['Date'] = pd.to_datetime(df_trnx['Date']) # convert Date column to datetime type
    temp = df_trnx[df.Ac == ac] # usr data

    all_yr = list(set(temp.Date.dt.year)) # all years in which a user made any transaction
    all_mn = list(set(temp.Date.dt.month)) # all months in which a user made any transaction

    # configuring filters
    yr_ = all_yr if yr=='all' else yr
    mnt_ = all_mn if mnt=='all' else mnt

    # adding log 
    logger.info(f"configured filter: yr {yr_}, mnt_ {mnt_}")

    # filtering user data
    data = temp[(temp.Date.dt.year.isin(yr_)) & (temp.Date.dt.month.isin(mnt_))]

    # plot graph
    fig = plot_chart(data.drop('Ac', axis=1), yr, mnt)
    fig.savefig('static/chart.jpg')

    # update log
    logger.debug(f"func: usr_summary -> graph saved without any error")

@app.route('/')
def home():
    return render_template('home.html')

@app.route("/predict", methods = ['POST','GET'])
@cross_origin()
def predict():
    text = request.get_json().get("message")
    response = get_response(text)
    message = {"answer":response}
    return jsonify(message)
#     response = get_response(text)
#     message = {"answer":response}
#     final_message = jsonify(message)
#     final_message.headers.add("Access-Control-Allow-Origin", "*")
#     return final_message
#     return jsonify(message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    print(form.errors)
    if request.method == 'POST' and form.validate_on_submit():
        y = request.form.get('bank_id')
        user = User.query.filter_by(bank_id=form.bank_id.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index', y=y)) 
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
    return render_template('login.html' ,form = form)

@app.route('/site', methods =['GET', 'POST'])
def site():
    return render_template('site.html')

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    y = request.args.get('y')
    db1 = get_db()
    cursor = db1.execute("SELECT bankID,TName,Age,Gender,Email FROM Personal_new WHERE bankID = " + y)
    cursor2 = db1.execute("SELECT TDate,Trans,Amount,Trans_Type,Balance FROM Transaction_new WHERE bankID = " + y)
    results = cursor.fetchall()
    results2 = cursor2.fetchall()
    usr_summary(int(y))
    result0 = f"{results[0]['TName']}"
    return render_template('index.html',y=y, R_index0 = result0, results2 = results2, balance = results2[0]['balance'])

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
