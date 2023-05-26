from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
# init SQLAlchemy so we can use it later in our models

db = SQLAlchemy()


def create_app():
    
    # Fixed CWE-259 hardcoded password vulnerability by using .env file - can provide .env file if needed
    load_dotenv()

    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.getenv(SECRET_KEY)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurantmenu.db'

    db.init_app(app)

    # blueprint for auth routes in our app
    from .json import json as json_blueprint
    app.register_blueprint(json_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
