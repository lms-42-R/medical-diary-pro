"""
Типы данных для криптографической системы медицинского дневника
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import secrets
import base64
import json

@dataclass(frozen=True)
class MasterKey:
    """Мастер-ключ врача (выводится из пароля, хранится в памяти)"""
    key_bytes: bytes
    salt: bytes  # Соль использованная при выводе ключа
    algorithm: str = "PBKDF2-HMAC-SHA256"
    iterations: int = 600000
    created_at: datetime = field(default_factory=datetime.now)
    
    # Добавляем свойство key_id для совместимости с security_system.py
    @property
    def key_id(self) -> str:
        """Уникальный идентификатор ключа (первые 16 байт в hex)"""
        return self.key_bytes[:16].hex()
    
    # Добавляем свойство key для совместимости
    @property
    def key(self) -> bytes:
        """Алиас для key_bytes"""
        return self.key_bytes
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь (без ключа!)"""
        return {
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'algorithm': self.algorithm,
            'iterations': self.iterations,
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MasterKey':
        """Десериализация из словаря"""
        return cls(
            key_bytes=b'',  # Ключ не хранится!
            salt=base64.b64decode(data['salt']),
            algorithm=data['algorithm'],
            iterations=data['iterations'],
            created_at=datetime.fromisoformat(data['created_at'])
        )

@dataclass  # Убрали frozen=True
class DataKey:
    """Ключ данных пациента (шифруется мастер-ключем)"""
    key_id: str  # Уникальный идентификатор ключа
    key_bytes: bytes  # 32 байта для AES-256
    salt: bytes  # Уникальная соль пациента
    algorithm: str = "AES-256-GCM"
    created_at: datetime = field(default_factory=datetime.now)
    last_rotated: Optional[datetime] = None
    
    # Добавляем свойство key для совместимости
    @property
    def key(self) -> bytes:
        """Алиас для key_bytes"""
        return self.key_bytes
    
    @classmethod
    def generate(cls, key_id: Optional[str] = None) -> 'DataKey':
        """Генерация нового ключа данных"""
        return cls(
            key_id=key_id or secrets.token_hex(16),
            key_bytes=secrets.token_bytes(32),  # 256 бит
            salt=secrets.token_bytes(32)  # 256 бит соли
        )
    
    def mark_rotated(self):
        """Отметить ключ как ротированный"""
        self.last_rotated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь"""
        return {
            'key_id': self.key_id,
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat(),
            'last_rotated': self.last_rotated.isoformat() if self.last_rotated else None
        }

@dataclass(frozen=True)
class EncryptedData:
    """Зашифрованные данные с метаданными"""
    ciphertext: bytes
    nonce: bytes  # Для AES-GCM
    additional_data: bytes  # AAD для аутентификации
    version: str = "1.0"
    algorithm: str = "AES-256-GCM"
    key_id: Optional[str] = None  # Идентификатор ключа
    
    def to_json(self) -> str:
        """Сериализация в JSON строку"""
        return json.dumps({
            'ciphertext': base64.b64encode(self.ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(self.nonce).decode('utf-8'),
            'additional_data': base64.b64encode(self.additional_data).decode('utf-8'),
            'version': self.version,
            'algorithm': self.algorithm,
            'key_id': self.key_id
        }, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EncryptedData':
        """Десериализация из JSON строки"""
        data = json.loads(json_str)
        return cls(
            ciphertext=base64.b64decode(data['ciphertext']),
            nonce=base64.b64decode(data['nonce']),
            additional_data=base64.b64decode(data['additional_data']),
            version=data['version'],
            algorithm=data['algorithm'],
            key_id=data.get('key_id')
        )
    
    def __post_init__(self):
        """Валидация после инициализации"""
        if self.key_id and not isinstance(self.key_id, str):
            # В frozen dataclass используем object.__setattr__
            object.__setattr__(self, 'key_id', str(self.key_id))

@dataclass
class AccessSession:
    """Сессия доступа врача к данным пациента"""
    session_id: str
    doctor_id: int
    patient_id: int
    encrypted_session_key: bytes  # Ключ сессии, зашифрованный мастер-ключом
    access_type: str  # 'view', 'edit', 'emergency'
    permissions: Dict[str, bool]  # Права доступа
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=8))
    last_used: Optional[datetime] = None
    is_active: bool = True
    
    def __post_init__(self):
        """Инициализация прав доступа на основе типа"""
        if not self.permissions:
            if self.access_type == 'view':
                self.permissions = {'read': True, 'write': False, 'delete': False}
            elif self.access_type == 'edit':
                self.permissions = {'read': True, 'write': True, 'delete': False}
            elif self.access_type == 'emergency':
                self.permissions = {'read': True, 'write': True, 'delete': True}
            else:
                self.permissions = {'read': True, 'write': False, 'delete': False}
    
    def has_permission(self, permission: str) -> bool:
        """Проверка наличия права доступа"""
        return self.permissions.get(permission, False)
    
    def is_expired(self) -> bool:
        """Проверка истечения срока действия"""
        return datetime.now() > self.expires_at
    
    def update_last_used(self):
        """Обновление времени последнего использования"""
        self.last_used = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь"""
        return {
            'session_id': self.session_id,
            'doctor_id': self.doctor_id,
            'patient_id': self.patient_id,
            'access_type': self.access_type,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'is_active': self.is_active
        }

@dataclass
class EncryptionMetadata:
    """Метаданные шифрования для записи в БД"""
    record_id: int
    patient_id: int
    table_name: str  # 'medical_records', 'measurements', etc
    crypto_version: str = "1.0"
    key_id: Optional[str] = None
    algorithm: str = "AES-256-GCM"
    encrypted_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь"""
        return {
            'record_id': self.record_id,
            'patient_id': self.patient_id,
            'table_name': self.table_name,
            'crypto_version': self.crypto_version,
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'encrypted_at': self.encrypted_at.isoformat()
        }

# Типы для конфигурации
@dataclass
class SecurityConfig:
    """Конфигурация безопасности"""
    # Ключевые параметры
    default_algorithm: str = "AES-256-GCM"
    key_rotation_days: int = 90
    session_expiry_hours: int = 8
    
    # PBKDF2 параметры
    pbkdf2_iterations: int = 600000
    pbkdf2_key_length: int = 32  # 256 бит
    
    # Что шифровать
    encrypt_patient_data: bool = True
    encrypt_measurements: bool = True
    encrypt_prescriptions: bool = True
    encrypt_contact_info: bool = False  # Для поиска
    
    # Восстановление доступа
    emergency_access_enabled: bool = True
    emergency_approvers_required: int = 2
    
    # Аудит
    audit_all_accesses: bool = True
    audit_retention_days: int = 365
    
    def __post_init__(self):
        """Валидация конфигурации"""
        if self.pbkdf2_iterations < 100000:
            self.pbkdf2_iterations = 100000
        if self.pbkdf2_key_length < 32:
            self.pbkdf2_key_length = 32
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'SecurityConfig':
        """Загрузка конфигурации из YAML"""
        import yaml
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls(**data.get('security', {}))
    
    def to_yaml(self, yaml_path: str):
        """Сохранение конфигурации в YAML"""
        import yaml
        data = {'security': self.__dict__}
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# Исключения
class CryptoError(Exception):
    """Базовое исключение криптосистемы"""
    pass

class KeyNotFoundError(CryptoError):
    """Ключ не найден"""
    pass

class EncryptionError(CryptoError):
    """Ошибка шифрования"""
    pass

class DecryptionError(CryptoError):
    """Ошибка дешифрования"""
    pass

class AccessDeniedError(CryptoError):
    """Доступ запрещен"""
    pass

class KeyRotationError(CryptoError):
    """Ошибка ротации ключей"""
    pass

# Утилиты для совместимости
def create_test_master_key() -> MasterKey:
    """Создание тестового мастер-ключа для тестов"""
    return MasterKey(
        key_bytes=secrets.token_bytes(32),
        salt=secrets.token_bytes(32),
        algorithm="PBKDF2-HMAC-SHA256",
        iterations=100000
    )

def create_test_data_key() -> DataKey:
    """Создание тестового ключа данных для тестов"""
    return DataKey.generate()