import os

from flask import Flask
from flask_migrate import Migrate

from models import db


# Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv('DATABASE_URL')  # "postgresql://testuser:testpassword@db:5432/appdb" 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)
Migrate(app, db)


@app.route('/')
def index():
    return "Hello World"
    # return render_template('index.html')  # Create an index.html template

# if __name__ == '__main__':
#     app.run()
# debug=True, port=8001