import datetime
import json
import uuid

from flask import Blueprint, render_template, request, make_response, session, abort, current_app
from sqlalchemy.exc import IntegrityError
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import RegistrationCredential, PublicKeyCredentialCreationOptions
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, parse_registration_credential_json

from models import db, User
from auth import security


auth = Blueprint("auth", __name__, template_folder="templates")


@auth.route("/register")
def register():
    return render_template("auth/register.html")


@auth.route("/login")
def login():
    return "Login user"


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
    
    pcco_json = security.prepare_credential_creation(user)

    res = make_response(
        render_template(
            "auth/_partials/register_credential.html",
            public_credential_creation_options=pcco_json,
        )
    )
    session['registration_user_uid'] = user.uid

    return res

@auth.route("/add-credential", methods=["POST"])
def add_credential():
    """Receive a newly registered credentials to validate and save."""
    user_uid = session.get("registration_user_uid")
    if not user_uid:
        abort(make_response("Error user not found", 400))

    registration_data = request.get_data()

    ## Use py_webauthn to parse the registration data
    registration_json_data = json.loads(registration_data)
    registration_credential = parse_registration_credential_json(registration_json_data)

    user = User.query.filter_by(uid=user_uid).first()

    # try:
    security.verify_and_save_credential(user, registration_credential)

    session["registration_user_uid"] = None
    res = make_response('{"verified": true}', 201)
    res.set_cookie(
        "user_uid",
        user.uid,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=datetime.timedelta(days=30), #TODO: change to less
    )
    
    current_app.logger.info('success?') #, flush=True)

    return res
    # except InvalidRegistrationResponse as e:
    #     current_app.logger.error('Invalid registration response: ' + str(e))
    #     abort(make_response('{"verified": false}', 400))


