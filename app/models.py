import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref


db = SQLAlchemy()


# Don't directly call this function it will yield the same uids
def _str_uuid():
    return str(uuid.uuid4())
# Generate a random UUID
# uuid_bytes = uuid.uuid4().bytes

# Convert the UUID bytes to a UUID object
# uuid_obj = uuid.UUID(bytes=uuid_bytes)

    
class User(db.Model):
    """A user in the database"""

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(40), default=_str_uuid, unique=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    credentials = db.relationship(
        "WebAuthnCredential",
        backref=backref("user", cascade="all, delete"),
        lazy=True
    )
    # TODO update; use of relationship.back_populates with explicit relationship() constructs should be preferred.

    def __repr__(self):
        return f"<User {self.username}>"


class WebAuthnCredential(db.Model):
    """Stored WebAuthn Credentials as a replacement for passwords."""
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False)
    credential_public_key = db.Column(db.LargeBinary, nullable=False)
    current_sign_count = db.Column(db.Integer, default=0)  # For client-checks. not currently used

    def __repr__(self):
        return f"<Credential {self.credential_id}>"
