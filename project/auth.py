from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
import re

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    hashed_password = generate_password_hash(password, method="sha256")

    # check if the user actually exists
    # take the user-supplied password and compare it with the stored password
    if not user or not check_password_hash(hashed_password, password):
        flash('Please check your login details and try again.')
        current_app.logger.warning("User login failed")
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    # Email Checker Function to change email into safe email
    def email_checker(email):
        username_list = list(email.strip())
        safe_email_array = []

        #Retrieves username of email address
        for char in email:
            if char == '@':
                safe_email_array.append('@')
                del username_list[0]
                break
            else:
                safe_email_array.append(char)
                del username_list[0]

        mail_server_string = ''.join(username_list)
        mail_server_list = username_list

        #Retrieves mail server of email address
        for char in mail_server_string:
            if char == '.':
                safe_email_array.append('.')
                del mail_server_list[0]
                break
            else:
                safe_email_array.append(char)
                del mail_server_list[0]

        domain_list = ''.join(mail_server_list)

        #Retrieves domain of email address
        for char in domain_list:
            if (bool(re.match('^[a-zA-Z0-9]*$',char))==True):
                safe_email_array.append(char)
            else:
                return render_template('signup.html')

        safe_email = ''.join(safe_email_array)
        return safe_email
    
    email = request.form.get(email_checker('email'))
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
  
    if (user is not None): # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')  # 'flash' function stores a message accessible in the template code.
        current_app.logger.debug("User email already exists")
        return redirect(url_for('auth.signup'))

    hashed_password = generate_password_hash(password, method="sha256")
    # create a new user with the form data. TODO: Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=hashed_password)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

# See https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login for more information
