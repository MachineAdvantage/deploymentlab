import os
import logging

from flask import Flask, render_template
from flask_migrate import Migrate
from flask_login import LoginManager

from models import db, User
from auth.view import auth


# Flask application
app = Flask(__name__)
app.register_blueprint(auth, url_prefix="/auth")

# Configuring logging
logging.basicConfig(level=logging.DEBUG)

# Database and env var configuration
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv('DATABASE_URL')  # "postgresql://testuser:testpassword@db:5432/appdb" 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)
Migrate(app, db)

# Login manager configuration
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "auth.login"


@app.route('/')
def index():
    """Render the index.html as the main page."""
    #logging test
    app.logger.info('TESTING TESTING Processing request for index route')
    #end test
    return render_template('index.html')  # Create an index.html template


@login_manager.user_loader
def load_user(user_uid):
    return User.query.filter_by(uid=user_uid).first()



## Only necessary for Flask dev deployment
# if __name__ == '__main__':
#     app.run()
# debug=True, port=8001