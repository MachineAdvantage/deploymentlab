import os

from flask import Flask, render_template
from flask_migrate import Migrate

from models import db
from auth.views import auth



# Flask application
app = Flask(__name__)
app.register_blueprint(auth, url_prefix="/auth")

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv('DATABASE_URL')  # "postgresql://testuser:testpassword@db:5432/appdb" 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)
Migrate(app, db)


@app.route('/')
def index():
    """Render the index.html as the main page."""
    return render_template('index.html')  # Create an index.html template

## Only necessary for Flask dev deployment
# if __name__ == '__main__':
#     app.run()
# debug=True, port=8001