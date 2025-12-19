import re
from functools import wraps
from flask import request, jsonify
from flask_login import current_user

def validate_username(username):
    """Валидация логина: только латиница, цифры и знаки препинания"""
    if not username or len(username) < 3:
        return False, "Логин должен содержать минимум 3 символа"
    
    pattern = r'^[a-zA-Z0-9._-]+$'
    if not re.match(pattern, username):
        return False, "Логин может содержать только латинские буквы, цифры, точки, дефисы и подчеркивания"
    
    return True, "OK"

def validate_password(password):
    """Валидация пароля"""
    if not password or len(password) < 6:
        return False, "Пароль должен содержать минимум 6 символов"
    
    pattern = r'^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$'
    if not re.match(pattern, password):
        return False, "Пароль может содержать только латинские буквы, цифры и специальные символы"
    
    return True, "OK"

# ========== ДЕКОРАТОРЫ ДЛЯ JSON-RPC ==========

def login_required_jsonrpc(f):
    """Декоратор для проверки авторизации в JSON-RPC методах"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            # Возвращаем JSON-RPC ошибку
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': -32000,
                    'message': 'Требуется авторизация'
                },
                'id': None
            }
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Декоратор для проверки прав администратора в JSON-RPC"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': -32000,
                    'message': 'Требуется авторизация'
                },
                'id': None
            }
        
        if not current_user.is_admin:
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': -32001,
                    'message': 'Доступ запрещен. Требуются права администратора'
                },
                'id': None
            }
        
        return f(*args, **kwargs)
    return decorated_function

# ========== СТАРЫЕ ДЕКОРАТОРЫ (если нужны для HTML маршрутов) ==========

def login_required_html(f):
    """Декоратор для проверки авторизации в HTML маршрутах"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required_html(f):
    """Декоратор для проверки прав администратора в HTML маршрутах"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('login'))
        
        if not current_user.is_admin:
            from flask import abort
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function