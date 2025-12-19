import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import config
from auth import validate_username, validate_password
from jsonrpc_handler import JSONRPCHandler, JSONRPCError
import json

app = Flask(__name__)
app.config.from_object(config.Config)
app.secret_key = app.config['SECRET_KEY']

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему для доступа к этой странице.'

# Инициализация JSON-RPC обработчика
jsonrpc_handler = JSONRPCHandler()

# ========== ФУНКЦИИ ДЛЯ РАБОТЫ С БАЗОЙ ДАННЫХ ==========

def get_db():
    """Получение соединения с БД"""
    if 'db' not in g:
        g.db = sqlite3.connect('messenger.db')
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Закрытие соединения с БД"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_database():
    """Инициализация базы данных"""
    conn = sqlite3.connect('messenger.db')
    cursor = conn.cursor()
    
    # Таблица users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Таблица messages
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_deleted_by_sender BOOLEAN DEFAULT FALSE,
            is_deleted_by_receiver BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    
    # Проверяем есть ли администратор
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_hash = generate_password_hash('admin123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            ('admin', admin_hash, True)
        )
        print("✅ Администратор создан")
    
    # Проверяем есть ли тестовые пользователи
    test_users = [
        ('alice', 'password123'),
        ('bob', 'password123'),
        ('charlie', 'password123'),
        ('diana', 'password123'),
        ('eve', 'password123')
    ]
    
    for username, password in test_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            password_hash = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
    
    conn.commit()
    conn.close()
    return True

# ========== МОДЕЛИ ==========

class User:
    def __init__(self, id, username, password_hash, is_admin=False, created_at=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)
        self.created_at = created_at

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        if user:
            return User(
                id=user['id'],
                username=user['username'],
                password_hash=user['password_hash'],
                is_admin=user['is_admin'],
                created_at=user['created_at']
            )
        return None

    @staticmethod
    def get_by_username(username):
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        if user:
            return User(
                id=user['id'],
                username=user['username'],
                password_hash=user['password_hash'],
                is_admin=user['is_admin'],
                created_at=user['created_at']
            )
        return None

    @staticmethod
    def create(username, password, is_admin=False):
        db = get_db()
        password_hash = generate_password_hash(password)
        try:
            cursor = db.execute(
                'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                (username, password_hash, 1 if is_admin else 0)
            )
            db.commit()
            return User.get(cursor.lastrowid)
        except sqlite3.IntegrityError:
            return None

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at
        }

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# ========== HTML МАРШРУТЫ ==========

@app.route('/')
def index():
    """Главная страница"""
    if current_user.is_authenticated:
        return redirect(url_for('users_page'))
    return render_template('/rgz/index.html', 
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        return render_template('/rgz/login.html', 
                             error='Неверный логин или пароль',
                             fio="Вотчинникова Анна Андреевна",
                             group="ФБИ-33")
    
    return render_template('/rgz/login.html',
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33")

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Страница регистрации"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Валидация
        valid_username, username_msg = validate_username(username)
        valid_password, password_msg = validate_password(password)
        
        errors = []
        if not valid_username:
            errors.append(username_msg)
        if not valid_password:
            errors.append(password_msg)
        if password != confirm_password:
            errors.append('Пароли не совпадают')
        
        if errors:
            return render_template('/rgz/register.html', 
                                 errors=errors,
                                 fio="Вотчинникова Анна Андреевна",
                                 group="ФБИ-33")
        
        # Проверка существования пользователя
        if User.get_by_username(username):
            return render_template('/rgz/register.html',
                                 errors=['Пользователь с таким логином уже существует'],
                                 fio="Вотчинникова Анна Андреевна",
                                 group="ФБИ-33")
        
        # Создание пользователя
        user = User.create(username, password)
        if user:
            login_user(user)
            return redirect(url_for('index'))
        
        return render_template('/rgz/register.html',
                             errors=['Ошибка при создании пользователя'],
                             fio="Вотчинникова Анна Андреевна",
                             group="ФБИ-33")
    
    return render_template('/rgz/register.html',
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33")

@app.route('/users')
@login_required
def users_page():
    """Страница списка пользователей"""
    return render_template('/rgz/users.html',
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33",
                          current_user=current_user)

@app.route('/chat/<int:user_id>')
@login_required
def chat_page(user_id):
    """Страница чата с пользователем"""
    # Получаем пользователя из базы данных
    db = get_db()
    user_data = db.execute(
        'SELECT * FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    
    if not user_data:
        return redirect(url_for('users_page'))
    
    # Создаем объект User
    from werkzeug.security import check_password_hash
    other_user = User(
        id=user_data['id'],
        username=user_data['username'],
        password_hash=user_data['password_hash'],
        is_admin=user_data['is_admin'],
        created_at=user_data['created_at']
    )
    
    return render_template('/rgz/chat.html',
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33",
                          other_user=other_user,
                          current_user=current_user)

@app.route('/admin')
@login_required
def admin_page():
    """Админ-панель"""
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    return render_template('/rgz/admin.html',
                          fio="Вотчинникова Анна Андреевна",
                          group="ФБИ-33",
                          current_user=current_user)

@app.route('/logout')
@login_required
def logout():
    """Выход из системы"""
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account_route():
    """Удаление своего аккаунта (HTML форма)"""
    # Используем JSON-RPC метод
    response = jsonrpc_handler.delete_account()
    return redirect(url_for('index'))

# ========== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ==========

@app.route('/init')
def init_db():
    """Инициализация базы данных (аналог примера)"""
    try:
        if init_database():
            return '''
                <h1>✅ База данных успешно инициализирована!</h1>
                <p>Тестовые аккаунты:</p>
                <ul>
                    <li>Администратор: <strong>admin</strong> / <strong>admin123</strong></li>
                    <li>Пользователь: <strong>alice</strong> / <strong>password123</strong></li>
                    <li>Пользователь: <strong>bob</strong> / <strong>password123</strong></li>
                    <li>Пользователь: <strong>charlie</strong> / <strong>password123</strong></li>
                </ul>
                <p><a href="/">Перейти на главную страницу</a></p>
            '''
        else:
            return "❌ Ошибка при инициализации БД"
    except Exception as e:
        return f"❌ Ошибка: {str(e)}"

# ========== JSON-RPC API ==========

@app.route('/api', methods=['POST'])
def api():
    """JSON-RPC endpoint"""
    try:
        return jsonrpc_handler.handle_request()
    except JSONRPCError as e:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {
                'code': e.code,
                'message': e.message,
                'data': e.data
            },
            'id': request.json.get('id') if request.is_json else None
        })
    except Exception as e:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {
                'code': -32603,
                'message': f'Internal server error: {str(e)}'
            },
            'id': request.json.get('id') if request.is_json else None
        }), 500

# ========== ВСПОМОГАТЕЛЬНЫЕ МАРШРУТЫ ==========

@app.route('/api/ping')
def ping():
    """Проверка работы API"""
    return jsonify({'status': 'ok', 'message': 'API работает'})

@app.route('/api/user_info')
@login_required
def user_info():
    """Информация о текущем пользователе"""
    return jsonify(current_user.to_dict())

# ========== ЗАКРЫТИЕ БД ПРИ ЗАВЕРШЕНИИ ==========
app.teardown_appcontext(close_db)

# ========== ЗАПУСК ==========
if __name__ == '__main__':
    # Проверяем наличие БД
    try:
        conn = sqlite3.connect('messenger.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("⚠️  База данных не инициализирована")
            print("📌 Перейдите по ссылке: http://localhost:5000/init")
        else:
            print("✅ База данных готова")
        conn.close()
    except Exception as e:
        print(f"❌ Ошибка подключения к БД: {e}")
    
    # Запускаем приложение
    print("🚀 Запуск приложения на http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)