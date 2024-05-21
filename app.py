from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
# import requests
import logging
# import psycopg2
# from psycopg2.extras import RealDictCursor
########################################################################################################################
from asgiref.wsgi import WsgiToAsgi

logging.basicConfig(level=logging.DEBUG)

########################################################################################################################
# ...
########################################################################################################################
app = Flask(__name__)

secret_key = 'cdd303f0-d70a-4e36-a9f7-f94a14b59942'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgresql:oW0Al1JPI03FikwBTkAQcX4d5STstWy0@dpg-cnlujkol5elc73cb0e20-a.oregon-postgres.render.com/kafolat'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secret_key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.errorhandler(404)
# inbuilt function which takes error as parameter
def not_found(e):
    # defining function
    return render_template("404.html")


########################################################################################################################
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    admin = db.Column(db.Boolean(10), nullable=False)



########################################################################################################################
# db.models
class ip_address(db.Model):
    s_id = db.Column(db.String(30), primary_key=True)
    s_ip = db.Column(db.String(30), nullable=False)
    s_password = db.Column(db.String(150), nullable=False)

# sensors:
    # 1. light
    # 2. door
    # 3. heat
    # 4. motion
    # 5. temperature
    # 6. automation
    # 7. ..........
########################################################################################################################
class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


########################################################################################################################
@app.route('/')
@login_required
def _():
    return redirect(url_for('home'))


@app.route(f'/user')
@login_required
def user():
    return redirect(url_for('profile'))


########################################################################################################################

@app.route(f'/home', methods=['GET', 'POST'])
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
    else:
        form = LoginForm()
        if form.validate_on_submit():
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            # user = User.query.filter_by(username=form.username.data).first()
            if user:
                logging.debug(f"Retrieved password hash from database: {user.password}")

                # if user.password == form.password.data:
                # if user and bcrypt.check_password_hash(user.password, form.password.data):
                if bcrypt.check_password_hash(user.password, password):
                    flash('You were successfully logged in!')
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    flash("Password is incorrect!!!", "error")
            else:
                flash("User does not exists!!!", "error")
        return render_template('login.html', form=form)


#################################################### A d m i n #########################################################
def username_exists(username):
    # Query the User table to check if the username exists
    user = User.query.filter_by(username=username).first()
    return user is not None


@app.route(f'/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.admin:

        user_db = User.query.all()

        if request.method == 'POST':

            query = request.form['query']
            username = request.form['username']
            password = request.form['password']

            if " " in username or " " in password:
                flash("Username or Password must not consists from spaces.")
                return redirect(url_for('admin'))

            if query == 'Register':
                if username_exists(username):
                    flash("Username exists in the database!!!.")
                    return redirect(url_for('admin'))
                else:
                    if username and password:
                        if username in ['admin', 'smartboy']:
                            admin = True
                        else:
                            admin = False

                        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                        new_user = User(username=username, password=hashed_password, admin=admin)
                        db.session.add(new_user)
                        db.session.commit()
                        flash('User registered successfully!!!')
                        return redirect(url_for('admin'))
                    else:
                        flash("Please, make sure Username or Password entered correctly!!!")
                        return redirect(url_for("admin"))

            if query == 'Update':
                if username and password:
                    user = User.query.filter_by(username=username).first()
                    if user:
                        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
                        # user.password = password
                        db.session.commit()
                        flash('User updated successfully!!!')
                        return redirect(url_for('admin'))
                    else:
                        flash('User not found!!!')
                        return redirect(url_for('admin'))
                else:
                    flash("Please, Make Sure Username or Password Entered Correctly!!!")
                    return redirect(url_for("admin"))

            if query == 'Delete':
                user = User.query.filter_by(username=username).first()
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    flash('User successfully removed!!!')
                    return redirect(url_for('admin'))
                else:
                    flash('User not found or already removed!!!')
                    return redirect(url_for('admin'))

        return render_template('admin.html', users=user_db)
    else:
        return redirect(url_for('home'))


########################################################################################################################


@app.route(f'/profile')
@login_required
def profile():
    return jsonify({
        "username": current_user.username,
        "admin": current_user.admin,
        "password": None
    })

########################################################################################################################

@app.route('/data', methods=['GET', 'POST'])
def data():

    if request.method == 'POST':
        data = request.json
        s_id = data['s_id']
        s_ip = data['s_ip']
        s_password = data['s_password']

        ip = ip_address.query.filter_by(s_id=s_id).first()
        if not ip:
            new_ip = ip_address(s_id=s_id, s_password=s_password, s_ip=s_ip)
            db.session.add(new_ip)
            db.session.commit()
        return jsonify({"status": "success"}), 201
    else:
        return redirect(url_for('_'))


########################################################################################################################
def admin_db():
    hashed_password = bcrypt.generate_password_hash("password123#").decode("utf-8")
    user = User.query.filter_by(username="smartboy").first()
    if not user:
        new_user = User(username="smartboy", password=hashed_password, admin=True)
        db.session.add(new_user)
        db.session.commit()

########################################################################################################################
from uvicorn.config import Config

class CustomConfig(Config):
    ws = False

asgi_app = WsgiToAsgi(app)
########################################################################################################################

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     admin_db()
#     app.run(host="0.0.0.0")
