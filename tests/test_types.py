"""
Тесты типов данных криптосистемы
"""

import sys
import os
import pytest
import secrets
from datetime import datetime, timedelta

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.security.types import *

def test_master_key_serialization():
    """Тест сериализации мастер-ключа"""
    salt = secrets.token_bytes(32)
    key = MasterKey(
        key_bytes=secrets.token_bytes(32),
        salt=salt,
        algorithm="PBKDF2-HMAC-SHA256",
        iterations=600000
    )
    
    # Сериализация (без ключа!)
    data = key.to_dict()
    assert 'salt' in data
    assert data['algorithm'] == "PBKDF2-HMAC-SHA256"
    assert data['iterations'] == 600000
    assert 'key_bytes' not in data  # Ключ не должен сериализоваться!
    
    # Десериализация
    key2 = MasterKey.from_dict(data)
    assert key2.salt == salt
    assert key2.algorithm == key.algorithm
    assert key2.iterations == key.iterations

def test_data_key_generation():
    """Тест генерации ключа данных"""
    key = DataKey.generate()
    
    assert len(key.key_id) == 32  # 16 байт в hex
    assert len(key.key_bytes) == 32  # 256 бит
    assert len(key.salt) == 32  # 256 бит
    
    # Проверка уникальности
    key2 = DataKey.generate()
    assert key.key_id != key2.key_id
    assert key.key_bytes != key2.key_bytes
    assert key.salt != key2.salt

def test_encrypted_data_json():
    """Тест сериализации зашифрованных данных"""
    encrypted = EncryptedData(
        ciphertext=b'test_ciphertext',
        nonce=b'test_nonce',
        additional_data=b'test_aad',
        key_id='test_key_123'
    )
    
    # В JSON и обратно
    json_str = encrypted.to_json()
    encrypted2 = EncryptedData.from_json(json_str)
    
    assert encrypted.ciphertext == encrypted2.ciphertext
    assert encrypted.nonce == encrypted2.nonce
    assert encrypted.additional_data == encrypted2.additional_data
    assert encrypted.key_id == encrypted2.key_id

def test_access_session_permissions():
    """Тест прав доступа в сессии"""
    session = AccessSession(
        session_id='test_session',
        doctor_id=1,
        patient_id=5,
        encrypted_session_key=b'test_key',
        access_type='view',
        permissions={'view_records': True, 'edit_records': False}
    )
    
    assert session.has_permission('view_records') == True
    assert session.has_permission('edit_records') == False
    assert session.has_permission('delete_records') == False  # Не существует

def test_access_session_expiry():
    """Тест проверки истечения срока сессии"""
    # Активная сессия
    session = AccessSession(
        session_id='test_session',
        doctor_id=1,
        patient_id=5,
        encrypted_session_key=b'test_key',
        access_type='view',
        permissions={},
        expires_at=datetime.now() + timedelta(hours=1)
    )
    assert not session.is_expired()
    
    # Истекшая сессия
    expired_session = AccessSession(
        session_id='expired_session',
        doctor_id=1,
        patient_id=5,
        encrypted_session_key=b'test_key',
        access_type='view',
        permissions={},
        expires_at=datetime.now() - timedelta(hours=1)
    )
    assert expired_session.is_expired()

def test_security_config():
    """Тест конфигурации безопасности"""
    config = SecurityConfig(
        default_algorithm="AES-256-GCM",
        key_rotation_days=90,
        encrypt_measurements=True,
        encrypt_contact_info=False
    )
    
    assert config.default_algorithm == "AES-256-GCM"
    assert config.key_rotation_days == 90
    assert config.encrypt_measurements == True
    assert config.encrypt_contact_info == False

def test_encryption_metadata():
    """Тест метаданных шифрования"""
    metadata = EncryptionMetadata(
        record_id=123,
        patient_id=5,
        table_name='medical_records',
        key_id='key_abc123'
    )
    
    data = metadata.to_dict()
    assert data['record_id'] == 123
    assert data['patient_id'] == 5
    assert data['table_name'] == 'medical_records'
    assert data['key_id'] == 'key_abc123'
    assert 'encrypted_at' in data

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v"])