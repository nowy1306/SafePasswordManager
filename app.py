from flask import Flask, request, render_template, make_response, session, redirect, url_for, g
import redis
from redis.exceptions import ConnectionError
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
from flask_session import Session
import bcrypt
import mysql.connector
import random
import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import re

add_account = (
    "INSERT INTO accounts "
    "(login, password, firstname, lastname, email) "
    "VALUES (%s, %s, %s, %s, %s)"
)
               
add_password = (
    "INSERT INTO passwords "
    "(description, password, tag, nonce, account_id) "
    "VALUES (%s, %s, %s, %s, (SELECT id FROM accounts WHERE login=%s))"
)
                
update_login_attempt = (
    "UPDATE accounts "
    "SET failed_login_attempts=failed_login_attempts+1 "
    "WHERE login=%s"
)
                        
reset_login_attempt = (
    "UPDATE accounts "
    "SET failed_login_attempts=0 "
    "WHERE login=%s"
)
                       
login_attempt_query = (
    "SELECT failed_login_attempts FROM accounts "
    "WHERE login=%s"
)
                
delete_password = (
    "DELETE FROM passwords "
    "WHERE id=%s AND account_id=(SELECT id FROM accounts where login=%s)"
)
               
register_query = (
    "SELECT login FROM accounts "
    "WHERE login=%s"
)
                  
login_query = (
    "SELECT password FROM accounts "
    "WHERE login=%s"
)
               
passwords_query = (
    "SELECT p.id, p.description, p.password FROM accounts a, passwords p "
    "WHERE a.id=p.account_id AND a.login=%s"
)
                   
password_enc_data_query = (
    "SELECT p.password, p.nonce, p.tag FROM accounts a, passwords p "
    "WHERE a.id=p.account_id AND a.login=%s AND p.id=%s"
)

load_dotenv()
MAX_FAILED_LOGIN_ATTEMPT_NUMBER = 5
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_NAME = os.getenv("DB_NAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
SALT = os.getenv("SALT")
SESSION_DB_HOST = os.getenv("SESSION_DB_HOST")
SESSION_DB_PASSWORD = os.getenv("SESSION_DB_PASSWORD")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SESSION_TYPE'] = "redis"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_REDIS'] = redis.Redis(
    host=SESSION_DB_HOST,
    password=SESSION_DB_PASSWORD,
    port=6379,
    db=0)

s = Session()
s.init_app(app)

@app.before_request
def before():
    g.is_logged = (session.get("uid") != None)

@app.route('/')
def home():
    return render_template("home.html", is_logged=g.is_logged)

@app.route('/register', methods=['get'])
def register():
    return render_template("register.html", is_logged=g.is_logged)

@app.route('/register', methods=['post'])
def registered():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    email = request.form.get('email')
    
    if(
        login == "" or 
        login == None or 
        password == "" or
        password == None or 
        password2 == "" or
        password2 == None or 
        firstname == "" or
        firstname == None or 
        lastname == "" or
        lastname == None or 
        email == "" or
        email == None
    ):
        return "Pola nie moga byc puste", 400
    
    if(password != password2):
        return "Hasla nie moga byc rozne", 400
            
    if(
        validate_with_regex(login, "^([A-Z]|[a-z]|[_.-]|[\d])+$") == None or
        validate_with_regex(password, "^([A-Z]|[a-z]|[_\.\-~!@#$^*,?=+|\/\{\}]|[\d])+$") == None or
        validate_with_regex(firstname, "^([A-Z]|[a-z])+$") == None or
        validate_with_regex(lastname, "^([A-Z]|[a-z])+$") == None or
        validate_with_regex(email, "^([A-Z]|[a-z]|[_\.\-~!#$^*,?=+|\/\{\}]|[\d])+[@]([A-Z]|[a-z]|[0-9]|[\.])+$") == None
    ):
        return "Niepoprawne dane rejestracji", 400
            
    
    
    hashed_password = hash_password(password)
    
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad", 503
        
    try:
        cursor = cnx.cursor()
        cursor.execute(register_query, (login,))
        res = cursor.fetchall()
        if(len(res) != 0):
            cursor.close()
            cnx.close()
            return "Uzytkownik istnieje", 400
        
        cursor.execute(add_account, (login, hashed_password, firstname, lastname, email))
        cnx.commit()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad", 503
    
    cursor.close()
    cnx.close()
    return "Zarejestrowano pomyślnie"
    
@app.route('/login', methods=['get'])
def login():
    session["attempt"] = 0
    return render_template("login.html", is_logged=g.is_logged)
    
@app.route('/login', methods=['post'])
def logged():
    login = request.form.get('login')
    input_password = request.form.get('password')
    
    if(login == None or input_password == None):
        return "Blad logowania", 400
        
    if(
        validate_with_regex(login, "^([A-Z]|[a-z]|[_.-]|[\d])+$") == None or
        validate_with_regex(input_password, "^([A-Z]|[a-z]|[_\.\-~!#@$^*,?=+|\/\{\}]|[\d])+$") == None
    ):
        return "Blad logowania", 400
        
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad", 503
    
    try:
        cursor = cnx.cursor()
        cursor.execute(login_query, (login,))
        res = cursor.fetchone()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad", 503
        
    
    if(res == None):
        random_delay(300, 500)
        cursor.close()
        cnx.close()
        return "Blad logowania", 400
        
    password = res[0]
    
    try:
        if(not check_password(input_password, password)):
            random_delay(0, 200)
            cursor.execute(update_login_attempt, (login,))
            cnx.commit()
            
            cursor.execute(login_attempt_query, (login,))
            res = cursor.fetchone()
            failed_login_attempt_number = res[0]
            if(failed_login_attempt_number > MAX_FAILED_LOGIN_ATTEMPT_NUMBER):
                cursor.close()
                cnx.close()
                return "Przekroczono limit nieudanych prob logowania", 403
            
            cursor.close()
            cnx.close()
            return "Blad logowania", 400
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad", 503
    
    session["uid"] = uuid.uuid4()
    session["date"] = (str)(datetime.now())
    session["login"] = login
    
    try:
        cursor.execute(reset_login_attempt, (login,))
        cnx.commit()
        cursor.close()
        cnx.close()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad", 503
    
    random_delay(0, 200)
    return redirect(url_for("home"))
    

@app.route('/logout', methods=['get'])
def logout():
    response = make_response(redirect(url_for("home")))
    
    session.pop('uid', None)
    session.pop('date', None)
    session.pop('login', None)
    return response

@app.route('/dashboard', methods=['get'])
def show_dashboard():
     
    if(not g.is_logged):
        return "Nie masz uprawnien", 401
    
    login = session.get("login")
    
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad serwisu", 503
    
    try:
        cursor = cnx.cursor()
        cursor.execute(passwords_query, (login,))
        res = cursor.fetchall()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad serwisu", 503
    
    cursor.close()
    cnx.close()
    
    formatted_res = res
    return render_template("dashboard.html", is_logged=True, list=formatted_res)

@app.route('/dashboard/new', methods=['get'])
def add_to_dashboard():
        
    if(not g.is_logged):
        return "Nie masz uprawnien", 401
    return render_template("dashboard_new.html", is_logged=True)

@app.route('/dashboard', methods=['post'])
def added_to_dashboard():
    if(not g.is_logged):
        return "Nie masz uprawnien", 401
    login = session.get("login")
    
    description = request.form.get('description')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    
    if(
        description == "" or 
        password == "" or
        password2 == "" or
        description == None or 
        password == None or
        password2 == None
    ):
        return "Pola nie moga byc puste", 400
            
    if(password != password2):
        return "Hasla nie moga byc rozne", 400
        
    if(
        validate_with_regex(description, "^([A-Z]|[a-z]|[_\.\-~!#$^*,?=+|\/\{\}]|[\d])+$") == None or
        validate_with_regex(password, "^([A-Z]|[a-z]|[_\.\-~!#$@^*,?=+|\/\{\}]|[\d])+$") == None
    ):
        return "Niepoprawne dane", 400
    
    (ciphertext, tag, nonce) = encrypt_password(password)
    
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad serwisu", 503
    
    try:
        cursor = cnx.cursor()
        cursor.execute(add_password, (description, ciphertext, tag, nonce, login))
        cnx.commit()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad serwisu", 503

    cursor.close()
    cnx.close()
    
    return redirect(url_for("show_dashboard"))
    
@app.route('/dashboard/<pid>', methods=['delete'])
def removed_from_dashboard(pid):
    if(not g.is_logged):
        return "Nie masz uprawnien", 401
    login = session.get("login")
        
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad serwisu", 503
    
    try:
        cursor = cnx.cursor()
        cursor.execute(delete_password, (pid, login))
        cnx.commit()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad"

    cursor.close()
    cnx.close()
    
    return "", 204
    
@app.route('/dashboard/<pid>', methods=['get'])
def get_password(pid):
    encode = request.args.get("encode", "true")
    
    if(not g.is_logged):
            return "Nie masz uprawnien", 401
            
    login = session.get("login")
    
    try:
        cnx = get_db()
    except Exception as err:
        return "Blad serwisu", 503
    
    try:
        cursor = cnx.cursor()
        cursor.execute(password_enc_data_query, (login, pid))
        #passwords = cursor.fetchall()
        password_entity = cursor.fetchone()
    except mysql.connector.Error as err:
        cursor.close()
        cnx.close()
        return "Blad serwisu", 503
    
    if(password_entity == None):
        cursor.close()
        cnx.close()
        return "Blad", 400
    
    password = password_entity[0]
    nonce = password_entity[1]
    tag = password_entity[2]
    res = "Blad"
    if(encode == "true"):
        res = password
        
    if(encode == "false"):
        res = decrypt_password(password, nonce, tag)
    
    cursor.close()
    cnx.close()
    return res

def get_db():
    cnx = mysql.connector.connect(
    host=DB_HOST,
    user=DB_USER, 
    database=DB_NAME, 
    password=DB_PASSWORD)
    return cnx
    
def validate_with_regex(text, regex):
    return re.fullmatch(regex, text)
    
def hash_password(plaintext):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plaintext.encode(), salt)
    return hashed.decode()
    
def encrypt_password(password):
    key = PBKDF2(app.config["SECRET_KEY"], SALT)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    (ciphertext, tag) = cipher.encrypt_and_digest(password.encode())
    return (ciphertext.hex(), tag.hex(), nonce.hex())

def decrypt_password(ciphertext, nonce, tag):
    key = PBKDF2(app.config["SECRET_KEY"], SALT)
    cipher = AES.new(key, AES.MODE_EAX, bytes.fromhex(nonce))
    password = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
    return password.decode()
 
def check_password(input_password, hashed_password):
    return bcrypt.checkpw(input_password.encode(), hashed_password.encode())
    
def random_delay(_from, to):
    ms_delay = random.randint(_from, to)
    time.sleep(ms_delay/1000)

    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")