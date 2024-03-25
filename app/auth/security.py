import os
import datetime
import uuid
import json
from urllib.parse import urlparse
import secrets 

from flask import Blueprint, request, current_app, url_for
from redis import Redis
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from argon2 import PasswordHasher

from models import WebAuthnCredential, db


# All the REDIS databases!
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REGISTRATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD
)
AUTHENTICATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD
)
EMAIL_AUTH_SECRETS = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=2, password=REDIS_PASSWORD
)


# Globals
auth = Blueprint("auth", __name__, template_folder="templates")
ph = PasswordHasher() 


def _hostname():
    return str(urlparse(request.base_url).hostname) #+ ':5000'
    #"http://localhost:5000"


# @auth.route("/generate-registration-options", methods=["GET"])
def prepare_credential_creation(user):
    """Generate the configuration needed by the client to start registering a new
    WebAuthn credential."""
    current_app.logger.info('hostname: '+ _hostname())
    # uid_bytes = bytes(user.uid, 'utf-8')
    uid_bytes = uuid.UUID(user.uid).bytes
    public_credential_creation_options = webauthn.generate_registration_options(
        rp_name="AI Test My Code",  # Relying Party Name (a user-friendly name for our site)
        rp_id=_hostname(),  # server's hostname from helper function
        user_id=uid_bytes,  # user id (bytes necessary see https://github.com/duo-labs/py_webauthn/blob/7d73676e17a71945154c510f23d32413ce0ee8cf/examples/registration.py#L36)
        user_name=user.username, 
        # Require the user to verify their identity to the authenticator
        # authenticator_selection=AuthenticatorSelectionCriteria(
            # user_verification=UserVerificationRequirement.REQUIRED,),
    )

    # Redis to store the binary challenge value. TODO: change this to configurable "track idle" time
    REGISTRATION_CHALLENGES.set(user.uid, public_credential_creation_options.challenge)
    REGISTRATION_CHALLENGES.expire(user.uid, datetime.timedelta(minutes=10))

    return webauthn.options_to_json(public_credential_creation_options)


@auth.route("/verify-registration-response", methods=["POST"])
def verify_and_save_credential(user, registration_credential):
    """Verify that a new credential is valid for the session"""
    expected_challenge = REGISTRATION_CHALLENGES.get(user.uid)

    # If the credential is somehow invalid (i.e. the challenge is wrong),
    # this will raise an exception. It's easier to handle that in the view
    # since we can send back an error message directly. 

    auth_verification = webauthn.verify_registration_response(
        credential=registration_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
    )

    # At this point verification has succeeded and we can save the credential
    credential = WebAuthnCredential(
        user=user,
        credential_public_key=auth_verification.credential_public_key,
        credential_id=auth_verification.credential_id,
    )

    current_app.logger.info('credential success') #, flush=True)

    db.session.add(credential)
    db.session.commit()


def prepare_login_with_credential(user):
    """
    Prepare the authentication options for a user trying to log in.
    """
    allowed_credentials = [
        PublicKeyCredentialDescriptor(id=credential.credential_id)
        for credential in user.credentials
    ]

    authentication_options = webauthn.generate_authentication_options(
        rp_id=_hostname(),
        allow_credentials=allowed_credentials,
    )

    AUTHENTICATION_CHALLENGES.set(user.uid, authentication_options.challenge)
    AUTHENTICATION_CHALLENGES.expire(user.uid, datetime.timedelta(minutes=10))

    return json.loads(webauthn.options_to_json(authentication_options))


def verify_authentication_credential(user, authentication_credential):
    """
    Verify a submitted credential against a credential in the database and the
    challenge stored in redis.
    """
    expected_challenge = AUTHENTICATION_CHALLENGES.get(user.uid)
    stored_credential = (
        WebAuthnCredential.query.with_parent(user).filter_by(
            credential_id=webauthn.base64url_to_bytes(authentication_credential.id)
        ).first()
    )
    
    # This will raise if the credential does not authenticate
    # It seems that safari doesn't track credential sign count correctly, so we just
    # have to leave it on zero so that it will authenticate
    webauthn.verify_authentication_response(
        credential=authentication_credential,
        expected_challenge=expected_challenge,
        expected_origin=f"https://{_hostname()}",
        expected_rp_id=_hostname(),
        credential_public_key=stored_credential.credential_public_key,
        credential_current_sign_count=0
    )
    
    # After a successful authentication, expire the challenge so it can't be used again.
    AUTHENTICATION_CHALLENGES.expire(user.uid, datetime.timedelta(seconds=1))

    
    # Update the credential sign count after using, then save it back to the database.
    # This is mainly for reference since we can't use it because of Safari's weirdness.
    stored_credential.current_sign_count += 1
    db.session.add(stored_credential)
    db.session.commit()


def generate_magic_link(user_uid):
    """Generate a special secret link to log in a user and save a hash of the secret."""
    url_secret = secrets.token_urlsafe()
    secret_hash = ph.hash(url_secret)
    EMAIL_AUTH_SECRETS.set(user_uid, secret_hash)
    EMAIL_AUTH_SECRETS.expire(user_uid, datetime.timedelta(minutes=10))
    return url_for("auth.magic_link", secret=url_secret, _external=True, _scheme="https")


def verify_magic_link(user_uid, secret):
    """Verify the secret from a magic login link against the saved hash for that 
    user."""
    secret_hash = EMAIL_AUTH_SECRETS.get(user_uid)
    if ph.verify(secret_hash, secret):
        EMAIL_AUTH_SECRETS.expire(user_uid, datetime.timedelta(seconds=1))
        return True
    return False
