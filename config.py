import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-12345-change-in-production')
    DATABASE = 'messenger.db'
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'admin123'  # Измените в продакшене!