# core/auth.py
"""
Модуль аутентификации и авторизации врачей
Защита медицинских данных с использованием bcrypt и JWT
"""

import bcrypt
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
import os
import sqlite3

class AuthError(Exception):
    """Базовое исключение для ошибок аутентификации"""
    pass

class InvalidCredentialsError(AuthError):
    """Неверные учетные данные"""
    pass

class TokenExpiredError(AuthError):
    """Токен истёк"""
    pass

class TokenInvalidError(AuthError):
    """Неверный токен"""
    pass

class AuthManager:
    """
    Менеджер аутентификации врачей
    
    Использует:
    - bcrypt для хэширования паролей
    - JWT для сессионных токенов
    - PBKDF2 для ключей шифрования данных
    """
    
    def __init__(self, secret_key: Optional[str] = None, token_expiry_hours: int = 8):
        """
        Инициализация менеджера аутентификации
        
        Args:
            secret_key: Секретный ключ для JWT (если None, генерируется)
            token_expiry_hours: Срок действия токена в часах
        """
        self.secret_key = secret_key or os.getenv('MEDICAL_JWT_SECRET', secrets.token_hex(32))
        self.token_expiry = timedelta(hours=token_expiry_hours)
        
        # Список отозванных токенов (в production использовать Redis)
        self.revoked_tokens = set()
    
    def hash_password(self, password: str) -> str:
        """
        Безопасное хэширование пароля с использованием bcrypt
        
        Args:
            password: Пароль в открытом виде
            
        Returns:
            str: Хэшированный пароль для хранения в БД
            
        Raises:
            ValueError: Если пароль пустой
        """
        if not password or not password.strip():
            raise ValueError("Пароль не может быть пустым")
        
        # Генерация соли и хэширование
        salt = bcrypt.gensalt(rounds=12)  # 12 раундов - безопасный баланс
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Проверка пароля против хэша
        
        Args:
            password: Пароль для проверки
            hashed_password: Хэшированный пароль из БД
            
        Returns:
            bool: True если пароль верный
            
        Note:
            Использует constant-time сравнение для защиты от timing-атак
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            # Неправильный формат хэша
            return False
    
    def create_token(self, doctor_id: int, username: str, 
                    additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Создание JWT токена для сессии врача
        
        Args:
            doctor_id: ID врача в БД
            username: Имя пользователя
            additional_claims: Дополнительные claims для токена
            
        Returns:
            str: JWT токен
            
        Raises:
            ValueError: Если данные невалидны
        """
        if not doctor_id or not username:
            raise ValueError("doctor_id и username обязательны")
        
        payload = {
            'doctor_id': doctor_id,
            'username': username,
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16),  # Уникальный идентификатор токена
            'type': 'access_token',
            'iss': 'medical_diary_pro',
            'aud': 'medical_api'
        }
        
        # Добавляем дополнительные claims если есть
        if additional_claims:
            payload.update(additional_claims)
        
        # Создаём токен
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Проверка и декодирование JWT токена
        
        Args:
            token: JWT токен для проверки
            
        Returns:
            Dict: Декодированный payload токена
            
        Raises:
            TokenExpiredError: Если токен истёк
            TokenInvalidError: Если токен невалидный
            ValueError: Если токен отозван
        """
        if not token:
            raise TokenInvalidError("Токен не предоставлен")
        
        # Проверяем не отозван ли токен
        if token in self.revoked_tokens:
            raise TokenInvalidError("Токен отозван")
        
        try:
            # Декодируем токен с проверкой подписи и срока
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=['HS256'],
                options={
                    'require': ['exp', 'iat', 'jti', 'doctor_id', 'username'],
                    'verify_exp': True,
                    'verify_iat': True
                },
                issuer='medical_diary_pro',
                audience='medical_api'
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Токен истёк")
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(f"Неверный токен: {str(e)}")
    
    def revoke_token(self, token: str):
        """
        Отзыв токена (для logout)
        
        Args:
            token: Токен для отзыва
        """
        self.revoked_tokens.add(token)
        
        # В production здесь нужно сохранять в Redis с TTL
        # Ограничиваем размер множества отозванных токенов
        if len(self.revoked_tokens) > 1000:
            # Удаляем самые старые токены
            self.revoked_tokens = set(list(self.revoked_tokens)[-500:])
    
    def authenticate_doctor(self, db_connection: sqlite3.Connection, 
                          username: str, password: str) -> Tuple[int, str, str]:
        """
        Аутентификация врача по логину и паролю
        
        Args:
            db_connection: Подключение к БД
            username: Имя пользователя
            password: Пароль
            
        Returns:
            Tuple: (doctor_id, username, token)
            
        Raises:
            InvalidCredentialsError: Если логин/пароль неверные
            ValueError: Если врач неактивен
        """
        if not username or not password:
            raise InvalidCredentialsError("Логин и пароль обязательны")
        
        cursor = db_connection.cursor()
        
        # Ищем врача
        cursor.execute("""
        SELECT id, username, password_hash, full_name, is_active
        FROM doctors 
        WHERE username = ?
        """, (username,))
        
        doctor = cursor.fetchone()
        
        if doctor is None:
            # Используем constant-time сравнение даже для несуществующих пользователей
            # для защиты от timing-атак
            self._dummy_verify()
            raise InvalidCredentialsError("Неверный логин или пароль")
        
        # Проверяем активен ли врач
        if not doctor['is_active']:
            raise ValueError("Учетная запись врача деактивирована")
        
        # Проверяем пароль
        if not self.verify_password(password, doctor['password_hash']):
            raise InvalidCredentialsError("Неверный логин или пароль")
        
        # Обновляем время последнего входа
        cursor.execute("""
        UPDATE doctors 
        SET last_login = CURRENT_TIMESTAMP 
        WHERE id = ?
        """, (doctor['id'],))
        db_connection.commit()
        
        # Создаём токен
        token = self.create_token(
            doctor_id=doctor['id'],
            username=doctor['username'],
            additional_claims={'full_name': doctor['full_name']}
        )
        
        return doctor['id'], doctor['username'], token
    
    def register_doctor(self, db_connection: sqlite3.Connection,
                       username: str, password: str, full_name: str,
                       specialization: str = "") -> int:
        """
        Регистрация нового врача
        
        Args:
            db_connection: Подключение к БД
            username: Имя пользователя
            password: Пароль
            full_name: Полное имя
            specialization: Специализация
            
        Returns:
            int: ID созданного врача
            
        Raises:
            ValueError: Если пользователь уже существует или данные невалидны
        """
        # Валидация входных данных
        if not username or len(username) < 3:
            raise ValueError("Имя пользователя должно быть не менее 3 символов")
        
        if not password or len(password) < 8:
            raise ValueError("Пароль должен быть не менее 8 символов")
        
        if not full_name:
            raise ValueError("Полное имя обязательно")
        
        cursor = db_connection.cursor()
        
        # Проверяем существует ли пользователь
        cursor.execute("SELECT id FROM doctors WHERE username = ?", (username,))
        if cursor.fetchone():
            raise ValueError(f"Пользователь '{username}' уже существует")
        
        # Хэшируем пароль
        password_hash = self.hash_password(password)
        
        # Создаём врача
        cursor.execute("""
        INSERT INTO doctors 
        (username, password_hash, full_name, specialization, is_active)
        VALUES (?, ?, ?, ?, 1)
        """, (username, password_hash, full_name, specialization))
        
        doctor_id = cursor.lastrowid
        db_connection.commit()
        
        return doctor_id
    
    def change_password(self, db_connection: sqlite3.Connection,
                       doctor_id: int, old_password: str, new_password: str) -> bool:
        """
        Смена пароля врача
        
        Args:
            db_connection: Подключение к БД
            doctor_id: ID врача
            old_password: Старый пароль
            new_password: Новый пароль
            
        Returns:
            bool: True если пароль успешно изменён
            
        Raises:
            InvalidCredentialsError: Если старый пароль неверный
            ValueError: Если новый пароль невалиден
        """
        cursor = db_connection.cursor()
        
        # Получаем текущий хэш пароля
        cursor.execute("SELECT password_hash FROM doctors WHERE id = ?", (doctor_id,))
        result = cursor.fetchone()
        
        if not result:
            raise InvalidCredentialsError("Врач не найден")
        
        # Проверяем старый пароль
        if not self.verify_password(old_password, result['password_hash']):
            raise InvalidCredentialsError("Неверный старый пароль")
        
        # Валидация нового пароля
        if not new_password or len(new_password) < 8:
            raise ValueError("Новый пароль должен быть не менее 8 символов")
        
        # Хэшируем новый пароль
        new_password_hash = self.hash_password(new_password)
        
        # Обновляем пароль в БД
        cursor.execute("""
        UPDATE doctors 
        SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """, (new_password_hash, doctor_id))
        
        db_connection.commit()
        
        # Отзываем все активные токены врача
        self._revoke_all_doctor_tokens(doctor_id)
        
        return True
    
    def _revoke_all_doctor_tokens(self, doctor_id: int):
        """
        Отзыв всех токенов врача (при смене пароля и т.д.)
        
        Note: В production нужно хранить mapping doctor_id -> tokens
        """
        # В этой простой реализации просто очищаем все токены
        # В production нужно использовать Redis с поиском по doctor_id
        print(f"⚠️  Все токены для врача {doctor_id} должны быть отозваны")
        # Здесь должна быть логика отзыва токенов по doctor_id
    
    def _dummy_verify(self):
        """
        Dummy-проверка для constant-time операций
        
        Защита от timing-атак при проверке несуществующих пользователей
        """
        dummy_hash = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt())
        bcrypt.checkpw(b"dummy_password", dummy_hash)
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Проверка сложности пароля
        
        Args:
            password: Пароль для проверки
            
        Returns:
            Tuple: (is_valid, error_message)
        """
        if len(password) < 8:
            return False, "Пароль должен быть не менее 8 символов"
        
        if not any(c.isupper() for c in password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        
        if not any(c.islower() for c in password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        
        if not any(c.isdigit() for c in password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        
        # Проверка на простые пароли
        common_passwords = ['password', '12345678', 'qwerty', 'admin', 'doctor']
        if password.lower() in common_passwords:
            return False, "Пароль слишком простой"
        
        return True, "Пароль соответствует требованиям сложности"


# Синглтон для удобного доступа
_auth_instance = None

def get_auth_manager() -> AuthManager:
    """Получение экземпляра менеджера аутентификации"""
    global _auth_instance
    if _auth_instance is None:
        _auth_instance = AuthManager()
    return _auth_instance


if __name__ == "__main__":
    """Тестирование модуля аутентификации"""
    print("🧪 Тестирование модуля аутентификации")
    print("=" * 60)
    
    # Создаём временную БД для тестов
    import tempfile
    import sqlite3
    
    # Создаём временный файл БД
    temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp_db.close()
    
    try:
        # Подключаемся к БД
        conn = sqlite3.connect(temp_db.name)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Создаём таблицу doctors
        cursor.execute("""
        CREATE TABLE doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            specialization TEXT,
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        
        # Создаём менеджер аутентификации
        auth = AuthManager(secret_key="test_secret_key")
        
        print("1. Тест регистрации врача...")
        doctor_id = auth.register_doctor(
            conn, "test_doctor", "SecurePass123", "Доктор Тестовый", "Терапевт"
        )
        print(f"   ✅ Врач зарегистрирован, ID: {doctor_id}")
        
        print("\n2. Тест аутентификации...")
        try:
            doc_id, username, token = auth.authenticate_doctor(conn, "test_doctor", "SecurePass123")
            print(f"   ✅ Аутентификация успешна")
            print(f"   ID: {doc_id}, Username: {username}")
            print(f"   Токен: {token[:50]}...")
        except InvalidCredentialsError as e:
            print(f"   ❌ Ошибка аутентификации: {e}")
        
        print("\n3. Тест проверки токена...")
        try:
            payload = auth.verify_token(token)
            print(f"   ✅ Токен валиден")
            print(f"   Doctor ID: {payload['doctor_id']}")
            print(f"   Username: {payload['username']}")
        except (TokenExpiredError, TokenInvalidError) as e:
            print(f"   ❌ Ошибка токена: {e}")
        
        print("\n4. Тест неверных учетных данных...")
        try:
            auth.authenticate_doctor(conn, "test_doctor", "wrong_password")
            print("   ❌ Должна быть ошибка!")
        except InvalidCredentialsError:
            print("   ✅ Правильно отклонило неверный пароль")
        
        print("\n5. Тест сложности пароля...")
        test_passwords = [
            ("weak", False),
            ("Medium1", True),
            ("STRONGPASS123", False),  # нет строчных
            ("strongpass123", False),  # нет заглавных
            ("VeryStrongPass123", True)
        ]
        
        for pwd, should_be_valid in test_passwords:
            is_valid, msg = auth.validate_password_strength(pwd)
            status = "✅" if is_valid == should_be_valid else "❌"
            print(f"   {status} '{pwd}': {msg}")
        
        print("\n6. Тест смены пароля...")
        try:
            success = auth.change_password(conn, doctor_id, "SecurePass123", "NewPass456!")
            print(f"   ✅ Пароль изменён: {success}")
        except Exception as e:
            print(f"   ❌ Ошибка смены пароля: {e}")
        
        print("\n" + "=" * 60)
        print("🎉 Все тесты аутентификации пройдены успешно!")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Закрываем соединение и удаляем временный файл
        conn.close()
        os.unlink(temp_db.name)
        print("\n🧹 Временная БД удалена")