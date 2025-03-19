import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key_here')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URI', 'sqlite:///hospital_finder.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads/hospitals'  # Set the folder where hospital images will be stored
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 