from flask import Flask, flash, render_template, redirect, url_for, request, session
import requests
import json
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SuckmydickWW3ainthappening'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///imgflipapp.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
current_username = None


class User(UserMixin, db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))


class Memes(db.Model):
    __tablename__ = 'Memes'
    meme_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    meme = db.Column(db.String)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                session['username'] = form.username.data
                return redirect(url_for('top100'))
        flash('Invalid username or password')
        return redirect(url_for('login'))
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
        except:
            flash('Username or email is already taken')
            return redirect(url_for('signup'))
        return redirect(url_for('login'))
    # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/top100')
@login_required
def top100():
    response = requests.get('https://api.imgflip.com/get_memes')
    memes = response.json()
    top100 = []
    m = memes['data']['memes']

    for n in m:
        if n['box_count'] == 2:
            top100.append([n['url'], n['name'], n['id']])
    top100_main = top100
    return render_template('topmemes.html',images=top100,error=False)


@app.route('/editing', methods=['GET', 'POST'])
@login_required
def editing():
    try:
        template_id = request.form['template_id']
        image = request.form['meme']
        name=request.form['name']
        return render_template('editing.html', image=image, template_id=template_id,name=name)
    except:
        flash('Sneaky fellow, pick a meme to edit first')
        return redirect(url_for('top100'))


@app.route('/mymemes', methods=['GET', 'POST'])
@login_required
def mymemes():
    if request.method == 'POST':
        template_id = request.form['template_id']
        text0 = request.form['text1']
        text1 = request.form['text2']
        username = 'peepeepoopoo54'
        password = 'testing12'

        data = {'template_id': template_id, 'username': username, 'password': password, 'text0': text0, 'text1': text1,'font':'arial','max_font_size':35}

        edited_meme = requests.post(url='https://api.imgflip.com/caption_image', data=data).json()
        update_meme = edited_meme['data']['url']
        meme = Memes(username=session['username'], meme=update_meme)
        db.session.add(meme)
        db.session.commit()
    memes = []
    result = db.engine.execute("SELECT * FROM Memes WHERE username='%s' " % session['username'])
    for users in result:
        memes.append(users.meme)
    memes.reverse()
    return render_template('mymemes.html', memes=memes, username=session['username'])


if __name__ == '__main__':
    app.run(debug=True)
