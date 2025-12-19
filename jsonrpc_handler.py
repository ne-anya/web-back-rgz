from flask import request, jsonify, session
from flask_login import current_user
from auth import login_required_jsonrpc, admin_required
import json
import sqlite3

class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data

class JSONRPCHandler:
    
    def __init__(self):
        self.methods = {
            'send_message': self.send_message,
            'get_messages': self.get_messages,
            'delete_message': self.delete_message,
            'get_users': self.get_users,
            'get_user_info': self.get_user_info,
            'get_conversation': self.get_conversation,
            'admin_get_all_users': self.admin_get_all_users,
            'admin_delete_user': self.admin_delete_user,
            'admin_update_user': self.admin_update_user,
            'delete_account': self.delete_account,
        }
    
    def _get_db(self):
        from flask import g
        if 'db' not in g:
            g.db = sqlite3.connect('messenger.db')
            g.db.row_factory = sqlite3.Row
        return g.db
    
    def handle_request(self):
        if not request.is_json:
            raise JSONRPCError(-32700, 'Invalid JSON')
        
        data = request.get_json()
        
        # Проверка формата JSON-RPC 2.0
        if not isinstance(data, dict):
            raise JSONRPCError(-32600, 'Invalid Request')
        
        jsonrpc = data.get('jsonrpc')
        method_name = data.get('method')
        params = data.get('params', {})
        request_id = data.get('id')
        
        if jsonrpc != '2.0':
            raise JSONRPCError(-32600, 'Invalid Request: jsonrpc must be "2.0"')
        
        if not method_name or not isinstance(method_name, str):
            raise JSONRPCError(-32600, 'Invalid Request: method is required')
        
        if not isinstance(params, dict):
            raise JSONRPCError(-32602, 'Invalid params')
        
        # Выполнение метода
        if method_name not in self.methods:
            raise JSONRPCError(-32601, f'Method not found: {method_name}')
        
        try:
            result = self.methods[method_name](**params)
            response = {
                'jsonrpc': '2.0',
                'result': result,
                'id': request_id
            }
            return jsonify(response)
            
        except JSONRPCError as e:
            return self._error_response(e.code, e.message, e.data, request_id)
        except Exception as e:
            return self._error_response(-32603, f'Internal error: {str(e)}', None, request_id)
    
    def _error_response(self, code, message, data, request_id):
        return jsonify({
            'jsonrpc': '2.0',
            'error': {
                'code': code,
                'message': message,
                'data': data
            },
            'id': request_id
        })
    
    
    @login_required_jsonrpc
    def send_message(self, receiver_id, text):
        if not text or len(text.strip()) == 0:
            raise JSONRPCError(-32602, 'Текст сообщения не может быть пустым')
        
        if len(text) > 1000:
            raise JSONRPCError(-32602, 'Сообщение слишком длинное (максимум 1000 символов)')
        
        db = self._get_db()
        receiver = db.execute(
            'SELECT * FROM users WHERE id = ?', (receiver_id,)
        ).fetchone()
        
        if not receiver:
            raise JSONRPCError(-32602, 'Получатель не найден')
        
        if receiver['id'] == current_user.id:
            raise JSONRPCError(-32602, 'Нельзя отправить сообщение самому себе')
        
        # Сохраняем сообщение
        cursor = db.execute(
            'INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (?, ?, ?)',
            (current_user.id, receiver_id, text.strip())
        )
        db.commit()
        
        # Получаем созданное сообщение
        message = db.execute(
            'SELECT * FROM messages WHERE id = ?', (cursor.lastrowid,)
        ).fetchone()
        
        return {
            'message_id': message['id'],
            'sent_at': message['sent_at']
        }
    
    @login_required_jsonrpc
    def get_messages(self, limit=50, offset=0):
        try:
            limit = int(limit)
            offset = int(offset)
        except ValueError:
            raise JSONRPCError(-32602, 'Некорректные параметры limit/offset')
        
        if limit > 100:
            limit = 100
        
        db = self._get_db()
        messages = db.execute('''
            SELECT m.*, u1.username as sender_name, u2.username as receiver_name
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.receiver_id = u2.id
            WHERE (m.sender_id = ? OR m.receiver_id = ?)
            AND NOT (m.sender_id = ? AND m.is_deleted_by_sender = 1)
            AND NOT (m.receiver_id = ? AND m.is_deleted_by_receiver = 1)
            ORDER BY m.sent_at DESC
            LIMIT ? OFFSET ?
        ''', (current_user.id, current_user.id, current_user.id, current_user.id, limit, offset)).fetchall()
        
        result = []
        for msg in messages:
            result.append({
                'id': msg['id'],
                'sender_id': msg['sender_id'],
                'sender_name': msg['sender_name'],
                'receiver_id': msg['receiver_id'],
                'receiver_name': msg['receiver_name'],
                'text': msg['message_text'],
                'sent_at': msg['sent_at'],
                'is_mine': msg['sender_id'] == current_user.id,
                'can_delete': True
            })
        
        return {'messages': result, 'total': len(result)}
    
    @login_required_jsonrpc
    def delete_message(self, message_id, delete_for='me'):
        db = self._get_db()
        message = db.execute(
            'SELECT * FROM messages WHERE id = ?', (message_id,)
        ).fetchone()
        
        if not message:
            raise JSONRPCError(-32602, 'Сообщение не найдено')
        
        if delete_for == 'me':
            # Удаляем для себя (получателя)
            if current_user.id == message['receiver_id']:
                db.execute(
                    'UPDATE messages SET is_deleted_by_receiver = 1 WHERE id = ?',
                    (message_id,)
                )
            elif current_user.id == message['sender_id']:
                db.execute(
                    'UPDATE messages SET is_deleted_by_sender = 1 WHERE id = ?',
                    (message_id,)
                )
            else:
                raise JSONRPCError(-32001, 'Нет прав на удаление этого сообщения')
        
        elif delete_for == 'both' and current_user.id == message['sender_id']:
            db.execute(
                'UPDATE messages SET is_deleted_by_sender = 1 WHERE id = ?',
                (message_id,)
            )
            db.execute(
                'UPDATE messages SET is_deleted_by_receiver = 1 WHERE id = ?',
                (message_id,)
            )
        else:
            raise JSONRPCError(-32602, 'Некорректный параметр delete_for')
        
        db.commit()
        return {'success': True}
    
    @login_required_jsonrpc
    def get_users(self, search=None, limit=50, offset=0):
        """Получение списка пользователей (кроме текущего)"""
        try:
            limit = int(limit)
            offset = int(offset)
        except ValueError:
            raise JSONRPCError(-32602, 'Некорректные параметры limit/offset')
        
        if limit > 100:
            limit = 100
        
        db = self._get_db()
        query = 'SELECT id, username, created_at FROM users WHERE id != ?'
        params = [current_user.id]
        
        if search:
            query += ' AND username LIKE ?'
            params.append(f'%{search}%')
        
        query += ' ORDER BY username LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        users = db.execute(query, params).fetchall()
        
        result = []
        for user in users:
            # Получаем последнее сообщение в диалоге
            last_msg = db.execute('''
                SELECT message_text, sent_at FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?)
                ORDER BY sent_at DESC LIMIT 1
            ''', (current_user.id, user['id'], user['id'], current_user.id)).fetchone()
            
            result.append({
                'id': user['id'],
                'username': user['username'],
                'created_at': user['created_at'],
                'last_message': last_msg['message_text'] if last_msg else None,
                'last_message_time': last_msg['sent_at'] if last_msg else None
            })
        
        return {'users': result}
    
    @login_required_jsonrpc
    def get_user_info(self, user_id):
        """Получение информации о пользователе"""
        db = self._get_db()
        user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        
        if not user:
            raise JSONRPCError(-32602, 'Пользователь не найден')
        
        return {
            'id': user['id'],
            'username': user['username'],
            'is_admin': bool(user['is_admin']),
            'created_at': user['created_at']
        }
    
    @login_required_jsonrpc
    def get_conversation(self, other_user_id, limit=50, offset=0):
        """Получение переписки с конкретным пользователем"""
        try:
            limit = int(limit)
            offset = int(offset)
        except ValueError:
            raise JSONRPCError(-32602, 'Некорректные параметры limit/offset')
        
        if limit > 100:
            limit = 100
        
        db = self._get_db()
        
        # Проверяем существование пользователя
        other_user = db.execute(
            'SELECT * FROM users WHERE id = ?', (other_user_id,)
        ).fetchone()
        
        if not other_user:
            raise JSONRPCError(-32602, 'Пользователь не найден')
        
        # Получаем сообщения
        messages = db.execute('''
            SELECT * FROM messages 
            WHERE ((sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?))
            AND NOT (sender_id = ? AND is_deleted_by_sender = 1)
            AND NOT (receiver_id = ? AND is_deleted_by_receiver = 1)
            ORDER BY sent_at DESC
            LIMIT ? OFFSET ?
        ''', (current_user.id, other_user_id, other_user_id, current_user.id, 
              current_user.id, current_user.id, limit, offset)).fetchall()
        
        result = []
        for msg in messages:
            result.append({
                'id': msg['id'],
                'sender_id': msg['sender_id'],
                'receiver_id': msg['receiver_id'],
                'text': msg['message_text'],
                'sent_at': msg['sent_at'],
                'is_mine': msg['sender_id'] == current_user.id,
                'can_delete': msg['sender_id'] == current_user.id
            })
        
        return {
            'other_user': {
                'id': other_user['id'],
                'username': other_user['username'],
                'is_admin': bool(other_user['is_admin']),
                'created_at': other_user['created_at']
            },
            'messages': result
        }
    
    @admin_required
    def admin_get_all_users(self, limit=100, offset=0, search=None, role_filter=None):
        """Админ: получение всех пользователей с фильтрацией"""
        try:
            print(f"DEBUG: Вызов admin_get_all_users, поиск: '{search}', фильтр: '{role_filter}'")
        
            db = self._get_db()
        
            # Строим запрос с фильтрами
            query = "SELECT * FROM users WHERE 1=1"
            params = []
        
            if search:
                query += " AND username LIKE ?"
                params.append(f"%{search}%")
        
            if role_filter:
                if role_filter == 'admin':
                    query += " AND is_admin = 1"
                elif role_filter == 'user':
                    query += " AND is_admin = 0"
        
            # Получаем общее количество (для пагинации)
            count_query = query.replace("SELECT *", "SELECT COUNT(*)")
            total_count = db.execute(count_query, params).fetchone()[0]
        
            # Добавляем сортировку и пагинацию
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        
            print(f"DEBUG: SQL запрос: {query}")
            print(f"DEBUG: Параметры: {params}")
        
            users = db.execute(query, params).fetchall()
        
            print(f"DEBUG: Найдено {len(users)} пользователей (всего: {total_count})")
        
            result = []
            for user in users:
                # Считаем количество сообщений
                sent_count = db.execute(
                    'SELECT COUNT(*) FROM messages WHERE sender_id = ?',
                    (user['id'],)
                ).fetchone()[0]
            
                received_count = db.execute(
                    'SELECT COUNT(*) FROM messages WHERE receiver_id = ?',
                    (user['id'],)
                ).fetchone()[0]
            
                result.append({
                    'id': user['id'],
                    'username': user['username'],
                    'is_admin': bool(user['is_admin']),
                    'created_at': user['created_at'],
                    'messages_sent': sent_count,
                    'messages_received': received_count
                })
        
            return {
                'users': result,
                'total': total_count,
                'limit': limit,
                'offset': offset
            }
        
        except Exception as e:
            print(f"ERROR в admin_get_all_users: {str(e)}")
            raise JSONRPCError(-32603, f'Internal server error: {str(e)}')
    
    @admin_required
    def admin_delete_user(self, user_id):
        """Админ: удаление пользователя"""
        if user_id == current_user.id:
            raise JSONRPCError(-32602, 'Нельзя удалить самого себя')
        
        db = self._get_db()
        
        # Проверяем существование пользователя
        user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        
        if not user:
            raise JSONRPCError(-32602, 'Пользователь не найден')
        
        db.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        
        return {'success': True, 'deleted_user_id': user_id}
    
    @admin_required
    def admin_update_user(self, user_id, is_admin=None, new_password=None):
        """Админ: обновление пользователя"""
        db = self._get_db()
        
        # Проверяем существование пользователя
        user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        
        if not user:
            raise JSONRPCError(-32602, 'Пользователь не найден')
        
        updates = []
        params = []
        
        if is_admin is not None:
            updates.append('is_admin = ?')
            params.append(1 if is_admin else 0)
        
        if new_password:
            from werkzeug.security import generate_password_hash
            updates.append('password_hash = ?')
            params.append(generate_password_hash(new_password))
        
        if not updates:
            raise JSONRPCError(-32602, 'Не указаны данные для обновления')
        
        params.append(user_id)
        db.execute(
            f'UPDATE users SET {", ".join(updates)} WHERE id = ?',
            params
        )
        db.commit()
        
        return {'success': True, 'updated_user_id': user_id}
    
    @login_required_jsonrpc
    def delete_account(self):
        """Удаление своего аккаунта"""
        db = self._get_db()
        
        # Удаляем все сообщения пользователя
        db.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', 
                  (current_user.id, current_user.id))
        
        # Удаляем пользователя (кроме администратора)
        if current_user.is_admin:
            # Администратора просто деактивируем
            db.execute('UPDATE users SET username = username || "_deleted_" || id WHERE id = ?',
                      (current_user.id,))
        else:
            db.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
        
        db.commit()
        
        # Выходим из системы
        from flask_login import logout_user
        logout_user()
        
        return {'success': True, 'message': 'Аккаунт удален'}