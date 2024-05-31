import os
from flask import Flask, render_template, redirect, url_for, jsonify, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
import logging
from asgiref.wsgi import WsgiToAsgi

# logging.basicConfig(level=logging.DEBUG)
uvicorn_ws_enabled = os.getenv('UVICORN_WS', 'on') == 'on'

app = Flask(__name__)

secret_key = 'cdd303f0-d70a-4e36-a9f7-f94a14b59942'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgresql:oW0Al1JPI03FikwBTkAQcX4d5STstWy0@dpg-cnlujkol5elc73cb0e20-a.oregon-postgres.render.com/kafolat'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secret_key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)

class Light(db.Model):
    s_id = db.Column(db.String(30), primary_key=True)
    s_ip = db.Column(db.String(30), nullable=True)
    s_status = db.Column(db.String(10), nullable=True)

class Temperature(db.Model):
    s_id = db.Column(db.String(30), primary_key=True)
    s_ip = db.Column(db.String(30), nullable=True)
    s_temperature = db.Column(db.String(10), nullable=True)
    s_humidity = db.Column(db.String(10), nullable=True)

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

@app.route('/')
@login_required
def _():
    return redirect(url_for('home'))

@app.route('/user')
@login_required
def user():
    return redirect(url_for('profile'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html", is_admin=current_user.admin)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You were logged out!')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            logging.debug(f"Retrieved password hash from database: {user.password}")
            if bcrypt.check_password_hash(user.password, password):
                flash('You were successfully logged in!')
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Password is incorrect!!!", "error")
        else:
            flash("User does not exist!!!", "error")
    return render_template('login.html', form=form)

def username_exists(username):
    user = User.query.filter_by(username=username).first()
    return user is not None

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.admin:
        user_db = User.query.all()
        if request.method == 'POST':
            query = request.form['query']
            username = request.form['username']
            password = request.form['password']
            if " " in username or " " in password:
                flash("Username or Password must not consist of spaces.")
                return redirect(url_for('admin'))
            if query == 'Register':
                if username_exists(username):
                    flash("Username exists in the database!!!")
                    return redirect(url_for('admin'))
                if username and password:
                    admin = username in ['admin', 'smartboy']
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    new_user = User(username=username, password=hashed_password, admin=admin)
                    db.session.add(new_user)
                    db.session.commit()
                    flash('User registered successfully!!!')
                    return redirect(url_for('admin'))
                flash("Please, make sure Username or Password entered correctly!!!")
                return redirect(url_for("admin"))
            if query == 'Update':
                if username and password:
                    user = User.query.filter_by(username=username).first()
                    if user:
                        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
                        db.session.commit()
                        flash('User updated successfully!!!')
                        return redirect(url_for('admin'))
                    flash('User not found!!!')
                    return redirect(url_for('admin'))
                flash("Please, Make Sure Username or Password Entered Correctly!!!")
                return redirect(url_for("admin"))
            if query == 'Delete':
                user = User.query.filter_by(username=username).first()
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    flash('User successfully removed!!!')
                    return redirect(url_for('admin'))
                flash('User not found or already removed!!!')
                return redirect(url_for('admin'))
        return render_template('admin.html', users=user_db)
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    return jsonify({
        "username": current_user.username,
        "admin": current_user.admin,
        "password": None
    })

@app.route('/light', methods=['GET', 'POST'])
def light():
    if request.method == 'POST':
        data = request.json
        s_id = data.get('s_id')
        s_ip = data.get('s_ip')
        s_status = data.get('s_status')
        light_entry = Light.query.filter_by(s_id=s_id).first()
        if light_entry:
            if s_ip:
                light_entry.s_ip = s_ip
            if s_status:
                light_entry.s_status = s_status
            db.session.commit()
        return jsonify({"status": "success"}), 201
    return redirect(url_for('home_redirect'))

@app.route('/temperature', methods=['GET', 'POST'])
def temperature():
    if request.method == 'POST':
        data = request.json
        s_id = data.get('s_id')
        s_ip = data.get('s_ip')
        s_temperature = data.get('s_temperature')
        s_humidity = data.get('s_humidity')
        temp_entry = Temperature.query.filter_by(s_id=s_id).first()
        if temp_entry:
            if s_ip:
                temp_entry.s_ip = s_ip
            if s_temperature and s_humidity:
                temp_entry.s_temperature = s_temperature
                temp_entry.s_humidity = s_humidity
            db.session.commit()
            return jsonify({"status": "success"}), 201
        else:
            return jsonify({"status": "failed"}), 404
    return redirect(url_for('_'))

def admin_db():
    hashed_password = bcrypt.generate_password_hash("password123#").decode("utf-8")
    user = User.query.filter_by(username="smartboy").first()
    if not user:
        new_user = User(username="smartboy", password=hashed_password, admin=True)
        db.session.add(new_user)
        db.session.commit()

from uvicorn.config import Config

class CustomConfig(Config):
    ws = False

asgi_app = WsgiToAsgi(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # admin_db()
    app.run(host="0.0.0.0")
