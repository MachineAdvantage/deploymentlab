import datetime
import json

from flask import (
    Blueprint, render_template, request, make_response, session, 
    abort, current_app, url_for, redirect)
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError
from webauthn.helpers.exceptions import (
    InvalidRegistrationResponse, InvalidAuthenticationResponse)
from webauthn.helpers.structs import (
    AuthenticationCredential, PublicKeyCredentialCreationOptions)
from webauthn.helpers import (
    base64url_to_bytes, bytes_to_base64url, parse_registration_credential_json,
    parse_authentication_credential_json)
from flask_login import login_user, login_required, current_user, logout_user

from models import db, User
from auth import security, util


auth = Blueprint("auth", __name__, template_folder="templates")


@auth.route("/register")
def register():
    return render_template("auth/register.html")


@auth.route("/create-user", methods=["POST"])
def create_user():
    """Handle creation of new users from the user creation form."""
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")

    user = User(name=name, username=username, email=email)
    # Temporary naive error handling
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        return render_template(
            "auth/_partials/user_creation_form.html",
            error="That username or email address is already in use. "
            "Please enter a different one.",
        )
    
    login_user(user)  # TODO shouldn't this be further down?
    session['used_webauthn'] = False
    pcco_json = security.prepare_credential_creation(user)

    res = make_response(
        render_template(
            "auth/_partials/register_credential.html",
            public_credential_creation_options=pcco_json,
        )
    )
    session['registration_user_uid'] = user.uid  # TODO still necessary with flask login?
    return res


@auth.route("/login", methods=["GET"])
def login():
    """Prepare to login user with passwordless auth"""
    user_uid = request.cookies.get("user_uid")
    user = User.query.filter_by(uid=user_uid).first()

    # If not remembered, we render login page w/o username
    if not user:
        return render_template("auth/login.html", username=None, auth_options=None)
    
    # If remembered we prepare the with username and options
    auth_options = security.prepare_login_with_credential(user)
    session['login_user_uid'] = user.uid

    return render_template("auth/login.html", username=user.username, auth_options=auth_options)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@auth.route("/add-credential", methods=["POST"])
@login_required
def add_credential():
    """Receive a newly registered credentials to validate and save."""
    registration_data = request.get_data()
    registration_json_data = json.loads(registration_data)
    registration_credential = parse_registration_credential_json(registration_json_data)
    try:
        security.verify_and_save_credential(current_user, registration_credential)
        session['used_webauthn'] = False
        session["registration_user_uid"] = None
        res = util.make_json_response(
            {"verified": True, "next": url_for("auth.user_profile")}
        )
        res.set_cookie(
            "user_uid",
            current_user.uid,  # TODO should this be .get_id()?
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=datetime.timedelta(days=30), #TODO: change to less
        )
        return res
    except InvalidRegistrationResponse as e:
        current_app.logger.error('Invalid registration response: ' + str(e))
        abort(make_response('{"verified": false}', 400))


@auth.route('/create-credential')
@login_required
def create_credential():
    """Start creation of new credentials by existing users."""
    pcco_json = security.prepare_credential_creation(current_user)
    return make_response(
        render_template(
            "auth/_partials/register_credential.html",
            public_credential_creation_options=pcco_json,
        )
    )


@auth.route("/prepare-login", methods=["POST"])
def prepare_login():
    """Prepare login options for a user based on their username or email"""
    username_or_email = request.form.get("username_email", "").lower()
    # The lower function just does case insensitivity for us.
    user = User.query.filter(
        or_(
            func.lower(User.username) == username_or_email,
            func.lower(User.email) == username_or_email,
        )
    ).first()

    # If no user matches, send back the form with an error message
    if not user:
        return render_template(
            "auth/_partials/username_form.html", error="No matching user found"
        )

    auth_options = security.prepare_login_with_credential(user)

    res = make_response(
        render_template(
            "auth/_partials/select_login.html",
            auth_options=auth_options,
            username=user.username,
        )
    )

    # Set the user uid on the session to get when we are authenticating later.
    session["login_user_uid"] = user.uid
    res.set_cookie(
        "user_uid",
        user.uid,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=datetime.timedelta(days=30),
    )
    return res


@auth.route("/login-switch-user")
def login_switch_user():
    """Remove a remembered user and show the username form again."""
    session["login_user_uid"] = None
    res = make_response(redirect(url_for('auth.login')))
    res.delete_cookie('user_uid')
    return res


@auth.route("/verify-login-credential", methods=["POST"])
def verify_login_credential():
    """Remove a remembered user and show the username form again."""
    user_uid = session.get("login_user_uid")  # TODO should this be current_user?
    user = User.query.filter_by(uid=user_uid).first()
    if not user:
        abort(make_response('{"verified": false}', 400))
    
    authetication_data = request.get_data()
    authetication_json_data = json.loads(authetication_data)

    authentication_credential = parse_authentication_credential_json(authetication_json_data)
    try:
        security.verify_authentication_credential(user, authentication_credential)
        login_user(user)
        session['used_webauthn'] = False
        next_ = request.args.get('next')
        if not next_ or not util.is_safe_url(next_):
            next_ = url_for("auth.user_profile")
            
        return util.make_json_response({"verified": True, "next": next_})
        # return make_response('{"verified": true}')
    except InvalidAuthenticationResponse as e:
        current_app.logger.error('Invalid authentication response: ' + str(e))
        abort(make_response('{"verified": false}', 400))


@auth.route('/profile')
@login_required
def user_profile():
    return render_template("auth/user_profile.html")


@auth.route("/email-login")
def email_login():
    """Request login by emailed link."""
    user_uid = session.get("login_user_uid")
    user = User.query.filter_by(uid=user_uid).first()

    # This is probably impossible, but seems like useful protection
    if not user:
        res = make_response(
            render_template(
                "auth/_partials/username_form.html", error="No matching user found."
            )
        )
        session.pop("login_user_uid", None)
        return res
    login_url = security.generate_magic_link(user.uid)
    util.send_email(
        user.email,
        "Flask WebAuthn Login",
        "Click or copy this link to log in. You must use the same browser that "
        f"you were using when you requested to log in. {login_url}",
    )
    res = make_response(render_template("auth/_partials/email_login_message.html"))
    res.set_cookie(
        "magic_link_user_uid",
        user.uid,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=datetime.timedelta(minutes=15),
    )
    return res


@auth.route("/magic-link")
def magic_link():
    """Handle incoming magic link authentications."""
    url_secret = request.args.get("secret")
    user_uid = request.cookies.get("magic_link_user_uid")
    user = User.query.filter_by(uid=user_uid).first()
    
    if not user:
        return redirect(url_for("auth.login"))
    
    if security.verify_magic_link(user_uid, url_secret):
        login_user(user)
        session['used_webauthn'] = False
        return redirect(url_for("auth.user_profile"))
    
    return redirect(url_for("auth.login"))
