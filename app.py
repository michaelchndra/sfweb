from flask import Flask, request, jsonify, url_for, redirect, render_template, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
import os
import requests
import string
import random
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# Configure the SQLAlchemy part of the app instance
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MYSQL_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create the SQLAlchemy db instance
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define the Script model
class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.String(80), nullable=False)
    update_date = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120))

# Define the Application model
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(120), nullable=False)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Helper functions and routes...

def shorten_url(long_url):
    api_url = f"https://earnow.online/api?api={os.environ.get('EARNOW_API_TOKEN')}&url={long_url}&format=text"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.text.strip()
    return long_url

def generate_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    scripts = Script.query.all()
    applications = Application.query.all()
    return render_template('index.html', scripts=scripts, applications=applications)

@app.route('/list-applications')
def list_applications():
    applications = Application.query.all()
    return render_template('list_applications.html', applications=applications)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/api/create-shortlink/<int:id>', methods=['GET'])
def create_shortlink(id):
    password = generate_password()
    script = Script.query.get(id)
    script.password = password
    db.session.commit()

    long_url = url_for('show_password', id=id, _external=True)
    short_url = shorten_url(long_url)

    return jsonify({'shortlink': short_url})

@app.route('/api/get-password/<int:id>', methods=['GET'])
def get_password(id):
    script = Script.query.get(id)

    if script.status == 'Offline':
        return jsonify({'status': 'error', 'message': 'Script is offline'}), 403

    return jsonify({'status': 'success', 'password': script.password})

@app.route('/password/<int:id>', methods=['GET'])
def show_password(id):
    script = Script.query.get(id)

    if script:
        return render_template('password.html', password=script.password)
    else:
        return "Script not found", 404

@app.route('/admin')
@login_required
def admin_panel():
    scripts = Script.query.all()
    applications = Application.query.all()
    return render_template('admin.html', scripts=scripts, applications=applications)

@app.route('/admin/update_status/<int:id>', methods=['POST'])
@login_required
def update_status(id):
    status = request.form['status']
    script = Script.query.get(id)
    script.status = status
    db.session.commit()
    return redirect('/admin')

@app.route('/admin/add_script', methods=['POST'])
@login_required
def add_script():
    name = request.form['name']
    status = request.form['status']
    update_date = request.form['update_date']
    new_script = Script(name=name, status=status, update_date=update_date)
    db.session.add(new_script)
    db.session.commit()
    return redirect('/admin')

@app.route('/admin/delete_script/<int:id>', methods=['POST'])
@login_required
def delete_script(id):
    script = Script.query.get(id)
    db.session.delete(script)
    db.session.commit()
    return redirect('/admin')

@app.route('/admin/add_application', methods=['POST'])
@login_required
def add_application():
    name = request.form['name']
    description = request.form['description']
    new_application = Application(name=name, description=description)
    db.session.add(new_application)
    db.session.commit()
    return redirect('/admin')

@app.route('/api/validate-password/<int:id>', methods=['POST'])
def validate_password(id):
    entered_password = request.json.get('password')
    script = Script.query.get(id)
    if script and script.password == entered_password:
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Invalid password'})

if __name__ == '__main__':
    app.run(debug=True)