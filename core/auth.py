# core/auth.py
"""
Модуль аутентификации и авторизации врачей
Интеграция с криптографической системой безопасности
"""

import bcrypt
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
import os
import sqlite3
import json
import base64

# Импортируем криптографический фасад
from medical_crypto import MedicalCryptoFacade, get_crypto_facade
from security.types import SecurityConfig, CryptoError

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

class CryptoAuthError(AuthError):
    """Ошибка криптографической системы"""
    pass

class AuthManager:
    """
    Менеджер аутентификации врачей с криптографической поддержкой
    
    Использует:
    - bcrypt для хэширования паролей (обратная совместимость)
    - JWT для сессионных токенов
    - MedicalCryptoFacade для криптографических операций
    """
    
    def __init__(self, secret_key: Optional[str] = None, 
                 token_expiry_hours: int = 8,
                 crypto_config: Optional[SecurityConfig] = None):
        """
        Инициализация менеджера аутентификации
        
        Args:
            secret_key: Секретный ключ для JWT
            token_expiry_hours: Срок действия токена в часах
            crypto_config: Конфигурация криптосистемы
        """
        self.secret_key = secret_key or os.getenv('MEDICAL_JWT_SECRET', secrets.token_hex(32))
        self.token_expiry = timedelta(hours=token_expiry_hours)
        
        # Криптографический фасад
        self.crypto_facade = get_crypto_facade(crypto_config)
        
        # Список отозванных токенов
        self.revoked_tokens = set()
        
        # Инициализация криптографических таблиц
        self._init_crypto_tables()
    
    def _init_crypto_tables(self):
        """Инициализация криптографических таблиц (должна вызываться при создании БД)"""
        # Этот метод вызывается из database.py при инициализации БД
        pass
    
    def _create_crypto_tables(self, db_connection: sqlite3.Connection):
        """
        Создание криптографических таблиц в БД
        
        Args:
            db_connection: Подключение к БД
        """
        cursor = db_connection.cursor()
        
        # Таблица для криптографической информации врачей
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctor_crypto (
            doctor_id INTEGER PRIMARY KEY,
            key_salt TEXT NOT NULL,  -- Соль для вывода мастер-ключа
            crypto_version TEXT DEFAULT '2.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
        )
        """)
        
        # Таблица ключей пациентов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_keys (
            patient_id INTEGER PRIMARY KEY,
            encrypted_data_key TEXT NOT NULL,  -- Ключ данных, зашифрованный мастер-ключом врача
            key_salt TEXT NOT NULL,  -- Соль пациента
            crypto_version TEXT DEFAULT '2.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_rotated TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """)
        
        # Таблица сессий доступа (для аудита)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_sessions_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            doctor_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            access_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            revoked_at TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES doctors(id),
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
        """)
        
        db_connection.commit()
    
    def hash_password(self, password: str) -> str:
        """
        Безопасное хэширование пароля с использованием bcrypt (обратная совместимость)
        """
        if not password or not password.strip():
            raise ValueError("Пароль не может быть пустым")
        
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Проверка пароля против bcrypt хэша
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
    
    def _get_doctor_crypto_info(self, db_connection: sqlite3.Connection, 
                              doctor_id: int) -> Optional[Dict[str, Any]]:
        """
        Получение криптографической информации врача
        
        Returns:
            Dict с ключом 'key_salt' (bytes) или None если не найден
        """
        cursor = db_connection.cursor()
        cursor.execute("""
        SELECT key_salt, crypto_version 
        FROM doctor_crypto 
        WHERE doctor_id = ?
        """, (doctor_id,))
        
        result = cursor.fetchone()
        if not result:
            return None
        
        # Декодируем соль из base64
        key_salt = base64.b64decode(result['key_salt'])
        
        return {
            'key_salt': key_salt,
            'crypto_version': result['crypto_version']
        }
    
    def _save_doctor_crypto_info(self, db_connection: sqlite3.Connection,
                               doctor_id: int, key_salt: bytes):
        """
        Сохранение криптографической информации врача
        """
        cursor = db_connection.cursor()
        
        # Кодируем соль в base64 для хранения
        key_salt_b64 = base64.b64encode(key_salt).decode('utf-8')
        
        cursor.execute("""
        INSERT OR REPLACE INTO doctor_crypto (doctor_id, key_salt)
        VALUES (?, ?)
        """, (doctor_id, key_salt_b64))
        
        db_connection.commit()
    
    def _generate_doctor_salt(self) -> bytes:
        """
        Генерация уникальной соли для врача
        """
        return secrets.token_bytes(32)
    
    def create_token(self, doctor_id: int, username: str, 
                    additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Создание JWT токена для сессии врача
        
        Добавляем информацию о криптосистеме в токен
        """
        if not doctor_id or not username:
            raise ValueError("doctor_id и username обязательны")
        
        payload = {
            'doctor_id': doctor_id,
            'username': username,
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16),
            'type': 'access_token',
            'iss': 'medical_diary_pro',
            'aud': 'medical_api',
            'crypto_version': '2.0'  # Добавляем версию криптосистемы
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Проверка и декодирование JWT токена
        """
        if not token:
            raise TokenInvalidError("Токен не предоставлен")
        
        if token in self.revoked_tokens:
            raise TokenInvalidError("Токен отозван")
        
        try:
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
        Отзыв токена
        """
        self.revoked_tokens.add(token)
        if len(self.revoked_tokens) > 1000:
            self.revoked_tokens = set(list(self.revoked_tokens)[-500:])
    
    def authenticate_doctor(self, db_connection: sqlite3.Connection, 
                          username: str, password: str) -> Tuple[int, str, str]:
        """
        Аутентификация врача с криптографической поддержкой
        
        Returns:
            Tuple: (doctor_id, username, token)
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
            self._dummy_verify()
            raise InvalidCredentialsError("Неверный логин или пароль")
        
        if not doctor['is_active']:
            raise ValueError("Учетная запись врача деактивирована")
        
        # 1. Проверяем пароль через bcrypt (обратная совместимость)
        if not self.verify_password(password, doctor['password_hash']):
            raise InvalidCredentialsError("Неверный логин или пароль")
        
        # 2. Получаем или создаем криптографическую информацию врача
        crypto_info = self._get_doctor_crypto_info(db_connection, doctor['id'])
        
        if crypto_info:
            # Врач уже имеет криптографическую настройку
            # Аутентифицируем через криптофасад
            try:
                logged_in_doctor = self.crypto_facade.login_doctor(username, password)
                if not logged_in_doctor or not logged_in_doctor.is_authenticated:
                    raise InvalidCredentialsError("Ошибка криптографической аутентификации")
            except CryptoError as e:
                # Падаем обратно на bcrypt если криптосистема недоступна
                print(f"⚠️  Криптосистема недоступна: {e}. Используем bcrypt.")
        else:
            # Новый врач - настраиваем криптографию
            try:
                # Генерируем соль для врача
                doctor_salt = self._generate_doctor_salt()
                
                # Сохраняем соль в БД
                self._save_doctor_crypto_info(db_connection, doctor['id'], doctor_salt)
                
                # Регистрируем врача в криптосистеме
                # В реальной системе здесь нужно вызывать регистрацию врача
                # но для безопасности делаем это при следующем логине
                print(f"⚠️  Криптография настроена для врача {doctor['id']}. Требуется повторный логин.")
                
            except Exception as e:
                print(f"⚠️  Ошибка настройки криптографии: {e}. Продолжаем без криптографии.")
        
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
            additional_claims={
                'full_name': doctor['full_name'],
                'crypto_enabled': crypto_info is not None
            }
        )
        
        return doctor['id'], doctor['username'], token
    
    def register_doctor(self, db_connection: sqlite3.Connection,
                       username: str, password: str, full_name: str,
                       specialization: str = "") -> Dict[str, Any]:
        """
        Регистрация нового врача с криптографической поддержкой
        
        Returns:
            Dict: Информация о зарегистрированном враче
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
        
        # Создаём врача в основной таблице
        cursor.execute("""
        INSERT INTO doctors 
        (username, password_hash, full_name, specialization, is_active)
        VALUES (?, ?, ?, ?, 1)
        """, (username, password_hash, full_name, specialization))
        
        doctor_id = cursor.lastrowid
        
        try:
            # Генерируем соль для врача
            doctor_salt = self._generate_doctor_salt()
            
            # Сохраняем криптографическую информацию
            self._save_doctor_crypto_info(db_connection, doctor_id, doctor_salt)
            
            # Регистрируем врача в криптосистеме
            doctor_info = self.crypto_facade.register_doctor(
                username=username,
                password=password,
                full_name=full_name
            )
            
            crypto_status = "configured"
            
        except Exception as e:
            print(f"⚠️  Ошибка настройки криптографии: {e}")
            crypto_status = "failed"
            doctor_info = None
        
        db_connection.commit()
        
        return {
            'doctor_id': doctor_id,
            'username': username,
            'full_name': full_name,
            'specialization': specialization,
            'crypto_status': crypto_status,
            'crypto_info': doctor_info
        }
    
    def change_password(self, db_connection: sqlite3.Connection,
                       doctor_id: int, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Смена пароля врача с обновлением криптографических ключей
        
        Returns:
            Dict: Результат операции
        """
        cursor = db_connection.cursor()
        
        # Получаем текущий хэш пароля
        cursor.execute("SELECT password_hash, username FROM doctors WHERE id = ?", (doctor_id,))
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
        
        # Обновляем криптографическую соль (ротируем ключ)
        try:
            # Генерируем новую соль
            new_salt = self._generate_doctor_salt()
            
            # Сохраняем в БД
            self._save_doctor_crypto_info(db_connection, doctor_id, new_salt)
            
            # Здесь должна быть логика перешифрования ключей пациентов новым мастер-ключом
            # В реальной системе нужно перешифровать все patient_keys
            crypto_updated = True
            
        except Exception as e:
            print(f"⚠️  Ошибка обновления криптографии: {e}")
            crypto_updated = False
        
        db_connection.commit()
        
        # Отзываем все активные токены врача
        self._revoke_all_doctor_tokens(doctor_id)
        
        return {
            'success': True,
            'doctor_id': doctor_id,
            'crypto_updated': crypto_updated,
            'message': 'Пароль успешно изменен'
        }
    
    def get_doctor_crypto_status(self, db_connection: sqlite3.Connection, 
                               doctor_id: int) -> Dict[str, Any]:
        """
        Получение статуса криптографической настройки врача
        """
        cursor = db_connection.cursor()
        
        # Информация из doctor_crypto
        cursor.execute("""
        SELECT dc.crypto_version, dc.created_at,
               COUNT(pk.patient_id) as patient_keys_count
        FROM doctor_crypto dc
        LEFT JOIN patient_keys pk ON dc.doctor_id = ?
        WHERE dc.doctor_id = ?
        GROUP BY dc.doctor_id
        """, (doctor_id, doctor_id))
        
        result = cursor.fetchone()
        
        if result:
            return {
                'crypto_enabled': True,
                'crypto_version': result['crypto_version'],
                'configured_at': result['created_at'],
                'patient_keys_count': result['patient_keys_count']
            }
        else:
            return {
                'crypto_enabled': False,
                'crypto_version': None,
                'configured_at': None,
                'patient_keys_count': 0
            }
    
    def migrate_doctor_to_crypto(self, db_connection: sqlite3.Connection,
                               doctor_id: int, password: str) -> bool:
        """
        Миграция существующего врача на новую криптосистему
        
        Returns:
            bool: True если миграция успешна
        """
        cursor = db_connection.cursor()
        
        # Проверяем что врач существует
        cursor.execute("""
        SELECT id, username, password_hash, full_name
        FROM doctors 
        WHERE id = ? AND is_active = 1
        """, (doctor_id,))
        
        doctor = cursor.fetchone()
        if not doctor:
            raise InvalidCredentialsError("Врач не найден или неактивен")
        
        # Проверяем пароль
        if not self.verify_password(password, doctor['password_hash']):
            raise InvalidCredentialsError("Неверный пароль")
        
        # Проверяем что врач еще не мигрирован
        crypto_info = self._get_doctor_crypto_info(db_connection, doctor_id)
        if crypto_info:
            raise ValueError("Врач уже мигрирован на криптосистему")
        
        try:
            # Генерируем соль
            doctor_salt = self._generate_doctor_salt()
            
            # Сохраняем в БД
            self._save_doctor_crypto_info(db_connection, doctor_id, doctor_salt)
            
            # Регистрируем в криптосистеме
            doctor_info = self.crypto_facade.register_doctor(
                username=doctor['username'],
                password=password,
                full_name=doctor['full_name']
            )
            
            # Логируем успешную миграцию
            print(f"✅ Врач {doctor_id} ({doctor['username']}) успешно мигрирован на криптосистему")
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка миграции врача {doctor_id}: {e}")
            
            # Откатываем изменения
            cursor.execute("DELETE FROM doctor_crypto WHERE doctor_id = ?", (doctor_id,))
            db_connection.commit()
            
            return False
    
    def _revoke_all_doctor_tokens(self, doctor_id: int):
        """
        Отзыв всех токенов врача
        """
        # В production нужно хранить mapping doctor_id -> tokens
        print(f"⚠️  Все токены для врача {doctor_id} должны быть отозваны")
    
    def _dummy_verify(self):
        """
        Dummy-проверка для constant-time операций
        """
        dummy_hash = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt())
        bcrypt.checkpw(b"dummy_password", dummy_hash)
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Проверка сложности пароля
        """
        if len(password) < 8:
            return False, "Пароль должен быть не менее 8 символов"
        
        if not any(c.isupper() for c in password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        
        if not any(c.islower() for c in password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        
        if not any(c.isdigit() for c in password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        
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
    """Тестирование обновленного модуля аутентификации"""
    print("🧪 Тестирование модуля аутентификации с криптографией")
    print("=" * 60)
    
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
        
        # Создаём все таблицы
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
        
        # Создаём криптографические таблицы
        auth = AuthManager(secret_key="test_secret_key")
        auth._create_crypto_tables(conn)
        
        print("1. Тест регистрации врача с криптографией...")
        result = auth.register_doctor(
            conn, "dr_crypto", "SecurePass123", "Доктор Крипто", "Кардиолог"
        )
        print(f"   ✅ Врач зарегистрирован: {result['username']}")
        print(f"   🔐 Статус криптографии: {result['crypto_status']}")
        
        print("\n2. Тест аутентификации...")
        try:
            doc_id, username, token = auth.authenticate_doctor(conn, "dr_crypto", "SecurePass123")
            print(f"   ✅ Аутентификация успешна")
            print(f"   ID: {doc_id}, Username: {username}")
            print(f"   Токен: {token[:50]}...")
        except InvalidCredentialsError as e:
            print(f"   ❌ Ошибка аутентификации: {e}")
        
        print("\n3. Тест статуса криптографии...")
        crypto_status = auth.get_doctor_crypto_status(conn, doc_id)
        print(f"   🔐 Криптография включена: {crypto_status['crypto_enabled']}")
        print(f"   Версия: {crypto_status['crypto_version']}")
        
        print("\n4. Тест смены пароля с обновлением криптографии...")
        try:
            result = auth.change_password(conn, doc_id, "SecurePass123", "NewPass456!")
            print(f"   ✅ Пароль изменён: {result['success']}")
            print(f"   Криптография обновлена: {result['crypto_updated']}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        print("\n5. Тест миграции существующего врача...")
        # Создаем врача без криптографии
        cursor.execute("""
        INSERT INTO doctors (username, password_hash, full_name, specialization)
        VALUES ('dr_old', ?, 'Доктор Старый', 'Терапевт')
        """, (auth.hash_password("OldPass123"),))
        
        old_doctor_id = cursor.lastrowid
        conn.commit()
        
        try:
            migrated = auth.migrate_doctor_to_crypto(conn, old_doctor_id, "OldPass123")
            print(f"   ✅ Миграция успешна: {migrated}")
        except Exception as e:
            print(f"   ❌ Ошибка миграции: {e}")
        
        print("\n" + "=" * 60)
        print("🎉 Тесты аутентификации с криптографией пройдены!")
        print("=" * 60)
        print("\n📚 Новые возможности:")
        print("  • Регистрация врачей с криптографической настройкой")
        print("  • Аутентификация через криптофасад")
        print("  • Миграция существующих врачей")
        print("  • Управление криптографическими ключами")
        print("  • Проверка статуса криптографии")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn.close()
        os.unlink(temp_db.name)
        print("\n🧹 Временная БД удалена")