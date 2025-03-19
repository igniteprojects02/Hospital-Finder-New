from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config

# Flask extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Setting the login view to redirect unauthorized users
    #login_manager.login_view = 'admin.admin_login'  # The login route for admin (or hospital as needed)

    # Register blueprints (we'll define routes later)
    from app.routes import admin_routes, hospital_routes, client_routes,home_routes
    #app.register_blueprint(home_routes.bp) # Make sure hospital_routes is imported
    app.register_blueprint(admin_routes.bp, url_prefix='/admin')
    app.register_blueprint(hospital_routes.bp, url_prefix='/hospital')  # Register hospital routes
    app.register_blueprint(client_routes.bp, url_prefix='/client')
    app.register_blueprint(home_routes.bp, url_prefix='/')
    return app

# Loading the user object for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))  # Fixing the missing parentheses

