from project1 import app
from flask import render_template, url_for, redirect, flash, request, jsonify
from project1.forms import RegisterForm, LoginForm
from project1.models import User, Note
from project1 import db
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token


@app.route("/")
@app.route("/home_page")
def home_page():
    return render_template('home.html')

@app.route("/user", methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['username'] = user.username
        output.append(user_data)

    return jsonify({'users' : output})

@app.route("/user", methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    newUser = User(username=data['username'], password=hashed_password, email_address=data['email_address'])
    db.session.add(newUser)
    db.session.commit()
    return jsonify({'message' : 'New user created'})

@app.route('/token', methods=['POST'])
def create_token():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/notes', methods=['GET'])
def get_all_notes():
    notes = Note.query.all()
    output = []

    for note in notes:
        note_data = {}
        note_data['user_id'] = note.user_id
        note_data['data'] = note.data
        output.append(note_data)

    return jsonify({'notes': output})




@app.route("/register", methods=['GET','POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        validated_user = User(username=form.username.data,
                              email_address=form.email_address.data,
                              password=form.password1.data)
        db.session.add(validated_user)
        db.session.commit()
        return redirect(url_for('home_page'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user_to_login = User.query.filter_by(username=form.username.data).first()
        if user_to_login and user_to_login.check_password(attempted_password=form.password.data):
            login_user(user_to_login)
            flash(f'Success! You are logged in as: {user_to_login.username}', category='success')
            return redirect(url_for('add_note'))
        else:
            flash('Username and password are not match! Please try again', category='danger')
    return render_template('login.html', form=form, user=current_user)

@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for("home_page"))

@app.route('/add_note', methods=['GET', 'POST'])
@login_required
def add_note():

    if request.method == 'POST':
        note = request.form.get('note')#Gets the note from the HTML
        new_note = Note(data=note, user_id=current_user.id)  #providing the schema for the note
        db.session.add(new_note) #adding the note to the database
        db.session.commit()
        flash('Note added!', category='success')
        return redirect(url_for('add_note'))

    return render_template("my_notes.html",user=current_user)

@app.route('/delete/<int:id>', methods=['POST'])
def remove(id):
    object = Note.query.get_or_404(id)
    #note_to_delete = Note.query.filter_by(id=id).first()
    db.session.delete(object)
    db.session.commit()
    flash("Note successfully deleted", category='success')
    return redirect(url_for('add_note'))





