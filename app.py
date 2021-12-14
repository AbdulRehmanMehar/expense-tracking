from flask import Flask, jsonify, Markup, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from flask_login import UserMixin, current_user, LoginManager, login_user, login_required, logout_user
from sqlalchemy import ForeignKey
from wtforms import Form, SelectField, IntegerField, EmailField, PasswordField, StringField, DateField, validators, ValidationError
import dataclasses, json


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


# app config...

app = Flask(__name__)
app.config['SECRET_KEY'] = 'the random string'
app.config['APP_NAME'] = 'Expense Management'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
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
        return '<User %r>' % self.username


@dataclasses.dataclass
class Budget(db.Model):
    id: int
    mode: str
    amount: int
    description: str
    issued_on: str
    user_id: int
    # user: User

    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(80), default='Investment')
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(80), nullable=False)
    issued_on = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('User.id'))
    user = db.relationship("User", backref=db.backref("user", uselist=False))

    def __init__(self, mode, amount, description, issued_on, user_id):
        self.mode = mode
        self.amount = amount
        self.description = description
        self.issued_on = issued_on
        self.user_id = user_id


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


class BudgetForm(Form):
    mode = SelectField('Type of Budget', [
        validators.DataRequired()
    ], choices=['Investment', 'Saving'])
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

# Routes...


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST' and form.validate():
        login_user(form.get_user())
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
        bget = Budget(form.mode.data, form.amount.data, form.description.data, form.issued_on.data, current_user.id)
        db.session.add(bget)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('BudgetForm.html', form=form)


@app.route('/get-budget')
@login_required
def get_budget():
    return jsonify(dict(results=Budget.query.filter(Budget.user_id == current_user.id).all()))


if __name__ == '__main__':
    app.run()
