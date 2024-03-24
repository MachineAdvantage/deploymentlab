import os
import datetime
import uuid
from urllib.parse import urlparse
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

from flask import Blueprint, request, current_app
from redis import Redis

from models import WebAuthnCredential, db


REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REGISTRATION_CHALLENGES = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD
)


auth = Blueprint("auth", __name__, template_folder="templates")


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
        # user_id=user.uid,  # user id (bytes necessary see https://github.com/duo-labs/py_webauthn/blob/7d73676e17a71945154c510f23d32413ce0ee8cf/examples/registration.py#L36)
        user_name=user.username, 
        # Require the user to verify their identity to the authenticator
        # authenticator_selection=AuthenticatorSelectionCriteria(
            # user_verification=UserVerificationRequirement.REQUIRED,),

    )

    # Redis to store the binary challenge value. FEATURE: change this to track idle time
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
