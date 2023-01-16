from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask login
login_manager = LoginManager()
login_manager.init_app(app=app)

# user loader callback function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':

        # check if email already exists in DB
        if User.query.filter_by(email=request.form['email']).first():
            flash(f'User with email: {request.form["email"]}, already exits, Try logging in')
            return redirect(url_for('login'))

        # register new user
        new_user = User(
            email = request.form['email'],
            name = request.form['name'],
            # hash +salt password - secure
            password = generate_password_hash(password=request.form['password'], method='pbkdf2:sha256', salt_length=8)
        )
        # add user to DB
        db.session.add(new_user)
        db.session.commit()

        # then, log in and authenticate user 
        login_user(new_user)

        return redirect(url_for('secrets'))
    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # find user using the entered email
        user = User.query.filter_by(email=email).first()
        # if no user has such mentioned email
        if not user:
            flash('Email does not exist, try again')
            return redirect(url_for('login'))
        # check hashed password against plain-text unhashed password
        elif not check_password_hash(user.password, password):
            flash('Incorrect password, try again')
            return redirect(url_for('login'))
        # if both email and password match to a user
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# download file
@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
