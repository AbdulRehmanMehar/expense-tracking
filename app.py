from flask import session, Flask, jsonify, Markup, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from flask_login import UserMixin, current_user, LoginManager, login_user, login_required, logout_user
from sqlalchemy import ForeignKey
from wtforms import Form, IntegerField, EmailField, PasswordField, StringField, DateField, validators, ValidationError
import dataclasses, json
from flask_session import Session
from wtforms_sqlalchemy.fields import QuerySelectField



class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


# app config...

app = Flask(__name__)
app.config['SECRET_KEY'] = 'the random string'
app.config['APP_NAME'] = 'Expense Management'
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/a.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
Session(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


def convert_list_to_dict(a):
    it = iter(a)
    res_dct = dict(zip(it, it))
    return res_dct

# Models...


@dataclasses.dataclass
class User(UserMixin, db.Model):
    id: int
    name: str
    dob: str
    email: str
    password: str

    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    dob = db.Column(db.DateTime, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, name, dob, email, password):
        self.name = name
        self.dob = dob
        self.email = email
        self.password = self.hash(password)

    def hash(self, password):
        return sha256_crypt.encrypt(password)

    def compare(self, pwd):
        return sha256_crypt.verify(pwd, self.password)

    def __repr__(self):
        return '<User %r>' % self.name


@dataclasses.dataclass
class Category(db.Model):
    id: int
    name: str

    __tablename__ = 'Category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), default='Investment', unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


@dataclasses.dataclass
class Profile(db.Model):
    id: int
    name: str
    user: User

    __tablename__ = 'Profile'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('User.id'))
    name = db.Column(db.String(80), nullable=False, unique=True)
    user = db.relationship("User", backref=db.backref("user", uselist=False))

    def __init__(self, user_id, name):
        self.user_id = user_id
        self.name = name


@dataclasses.dataclass
class Budget(db.Model):
    id: int
    mode: str
    amount: int
    description: str
    issued_on: str
    profile_id: int
    # user: User

    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(80), nullable=False)
    issued_on = db.Column(db.DateTime, nullable=False)
    mode_id = db.Column(db.Integer, ForeignKey('Category.id'))
    mode = db.relationship("Category", backref=db.backref("mode", uselist=False))
    profile_id = db.Column(db.Integer, ForeignKey('Profile.id'))
    profile = db.relationship("Profile", backref=db.backref("profile", uselist=False))

    def __init__(self, mode_id, amount, description, issued_on, profile_id):
        self.mode_id = mode_id
        self.amount = amount
        self.description = description
        self.issued_on = issued_on
        self.profile_id = profile_id


# Forms...


class RegistrationForm(Form):
    name = StringField('Name', [
        validators.DataRequired(),
        validators.Length(min=5, max=25)
    ], description='Jone Doe')
    dob = DateField('Date of Birth', [
        validators.DataRequired(),
    ], description='11-11-2000')
    email = EmailField('Email Address', [
        validators.DataRequired(),
        validators.Email()
    ], description='jone@doe.io')

    def validate_email(self, field):
        user = User.query.filter(User.email == field.data).first()
        if user is not None:
            raise ValidationError('Email already registered.')

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, max=25),
        validators.equal_to('cpassword', message='Passwords don\'t match.')
    ], description='************')
    cpassword = PasswordField('Confirm Password', [
        validators.DataRequired(),
        validators.equal_to('password', message='Passwords don\'t match.')
    ], description='************')


class LoginForm(Form):
    username = StringField('Email', [
        validators.DataRequired()
    ], description='jone')

    def validate_username(self, field):
        self.user = User.query.filter((User.email == field.data)).first()
        if not self.user:
            raise ValidationError('Email was not found in record.' + Markup('<a href='+ url_for('register') +' style="float: right">Register?</a>'))

    password = PasswordField('Password', [
        validators.DataRequired()
    ], description='**********')

    def validate_password(self, field):
        if (not self.user or not self.user.compare(field.data)) and not len(self.username.errors) > 0:
            raise ValidationError('Incorrect Credentials were provided. ')

    def get_user(self):
        return self.user


def get_cats():
    return Category.query


class BudgetForm(Form):
    mode = QuerySelectField('Mode', query_factory=get_cats, get_pk=lambda a: a.id, get_label=lambda a: a.name, allow_blank=False)

    # mode = SelectField('Type of Budget', [
    #     validators.DataRequired()
    # ], choices=['Investment', 'Saving'])
    description = StringField('Describe a little bit', [
        validators.DataRequired(),
        validators.Length(min=10, max=50)
    ], description='Spent on Car/House or Saved from Monthly Salary')
    issued_on = DateField('Issue Date', [
        validators.DataRequired(),
    ], description='01-05-2013')
    amount = IntegerField('Amount ', [
        validators.DataRequired(),
    ], description='$ 100')


class CategoryForm(Form):
    name = StringField('Name of Category', [
        validators.DataRequired(),
        validators.Length(min=3, max=50)
    ], description='Investment / Saving')


# Routes...


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.context_processor
def inject():
    prof = []
    if current_user.is_authenticated:
        prof = Profile.query.filter(Profile.user_id == current_user.id).all()
        print(prof)
    return dict(profiles=prof)


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST' and form.validate():
        usr = form.get_user()
        prof = Profile.query.filter(Profile.user_id == usr.id).first()
        session['profile_id'] = prof.id
        session['profile_name'] = prof.name
        login_user(usr)
        flash('You\'re logged in successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.name.data, form.dob.data, form.email.data, form.password.data)
        db.session.add(user)
        prof = Profile(user.id, 'Main')
        db.session.add(prof)
        db.session.commit()
        flash('Your email is now registered with ' + app.config['APP_NAME'] + '.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/budget', methods=['GET', 'POST'])
@login_required
def budget():
    form = BudgetForm(request.form)
    if request.method == 'POST' and form.validate():
        cat = Category.query.filter(Category.name == str(form.mode.data)).first()
        if cat is not None:
            bget = Budget(cat.id, form.amount.data, form.description.data, form.issued_on.data, session.get('profile_id'))
            db.session.add(bget)
            db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('BudgetForm.html', form=form)


@app.route('/get-budget')
@login_required
def get_budget():
    print(session.get('profile_id'))
    return jsonify(dict(results=Budget.query.filter(Budget.profile_id == session.get('profile_id')).all()))


@app.route('/category', methods=['GET', 'POST'])
@login_required
def category():
    form = CategoryForm(request.form)
    if request.method == 'POST' and form.validate():
        cat = Category(form.name.data)
        db.session.add(cat)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('CategoryForm.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.get_json()['name']
        prof = Profile(current_user.id, name)
        db.session.add(prof)
        db.session.commit()
        session['profile_id'] = prof.id
        session['profile_name'] = prof.name
        return jsonify(dict(results=prof))

    id = request.args.get('id')
    if id is not None:
        prof = Profile.query.filter(Profile.id == id).first()
        session['profile_id'] = prof.id
        session['profile_name'] = prof.name
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run()
