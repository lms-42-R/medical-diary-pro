"""
Тесты менеджера ключей
"""

import sys
import os
import pytest
import secrets

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.security.key_managers.default import DefaultKeyManager
from core.security.types import MasterKey


def test_derive_master_key():
    """Тест вывода мастер-ключа из пароля"""
    manager = DefaultKeyManager()
    
    # Тест с автоматической генерацией соли
    master_key = manager.derive_master_key("test_password_123")
    
    assert len(master_key.key_bytes) == 32  # 256 бит
    assert len(master_key.salt) == 32
    assert master_key.algorithm == "PBKDF2-HMAC-SHA256"
    assert master_key.iterations == 600000
    
    # Тест с указанной солью
    salt = secrets.token_bytes(32)
    master_key2 = manager.derive_master_key("test_password_123", salt)
    assert master_key2.salt == salt


def test_derive_master_key_different_passwords():
    """Тест что разные пароли дают разные ключи"""
    manager = DefaultKeyManager()
    
    key1 = manager.derive_master_key("password1")
    key2 = manager.derive_master_key("password2")
    
    assert key1.key_bytes != key2.key_bytes


def test_derive_master_key_same_password_same_salt():
    """Тест что одинаковый пароль и соль дают одинаковый ключ"""
    manager = DefaultKeyManager()
    salt = secrets.token_bytes(32)
    
    key1 = manager.derive_master_key("password", salt)
    key2 = manager.derive_master_key("password", salt)
    
    assert key1.key_bytes == key2.key_bytes


def test_generate_data_key():
    """Тест генерации ключа данных"""
    manager = DefaultKeyManager()
    
    key = manager.generate_data_key(patient_id=1)
    
    assert len(key.key_id) > 0
    assert len(key.key_bytes) == 32  # 256 бит
    assert len(key.salt) == 32
    assert key.algorithm == "AES-256-GCM"
    
    # Ключи для разных пациентов должны быть разными
    key2 = manager.generate_data_key(patient_id=2)
    assert key.key_id != key2.key_id
    assert key.key_bytes != key2.key_bytes


def test_encrypt_decrypt_data_key():
    """Тест шифрования и дешифрования ключа данных"""
    manager = DefaultKeyManager()
    
    # Создаем мастер-ключ
    master_key = manager.derive_master_key("doctor_password")
    
    # Генерируем ключ данных
    data_key = manager.generate_data_key(patient_id=1)
    
    # Шифруем ключ данных
    encrypted = manager.encrypt_data_key(data_key, master_key)
    
    # Проверяем что зашифрованные данные не равны оригиналу
    assert encrypted != data_key.key_bytes
    
    # Расшифровываем
    decrypted = manager.decrypt_data_key(encrypted, master_key)
    
    # Проверяем что расшифровано правильно
    assert decrypted.key_id == data_key.key_id
    assert decrypted.key_bytes == data_key.key_bytes
    assert decrypted.salt == data_key.salt


def test_decrypt_wrong_key():
    """Тест что неверный мастер-ключ не расшифрует данные"""
    manager = DefaultKeyManager()
    
    # Создаем правильный мастер-ключ
    master_key1 = manager.derive_master_key("correct_password")
    
    # Создаем неправильный мастер-ключ
    master_key2 = manager.derive_master_key("wrong_password")
    
    # Генерируем и шифруем ключ данных
    data_key = manager.generate_data_key(patient_id=1)
    encrypted = manager.encrypt_data_key(data_key, master_key1)
    
    # Пытаемся расшифровать неправильным ключом
    with pytest.raises(Exception):
        manager.decrypt_data_key(encrypted, master_key2)


def test_key_rotation():
    """Тест ротации ключей"""
    manager = DefaultKeyManager()
    
    master_key = manager.derive_master_key("doctor_password")
    
    # Генерируем первый ключ
    key1 = manager.generate_data_key(patient_id=1)
    
    # Ротируем ключ
    key2 = manager.rotate_data_key(patient_id=1, master_key=master_key)
    
    # Проверяем что ключи разные
    assert key1.key_id != key2.key_id
    assert key1.key_bytes != key2.key_bytes
    
    # Проверяем историю ключей
    history = manager.get_key_history(patient_id=1)
    assert len(history) == 2
    assert key1.key_id in history
    assert key2.key_id in history


def test_verify_password():
    """Тест проверки пароля"""
    manager = DefaultKeyManager()
    
    # Создаем мастер-ключ
    password = "CorrectPassword123"
    master_key = manager.derive_master_key(password)
    
    # Проверяем правильный пароль
    assert manager.verify_password(password, master_key) == True
    
    # Проверяем неправильный пароль
    assert manager.verify_password("WrongPassword", master_key) == False
    
    # Проверяем constant-time сравнение (грубая проверка)
    import time
    
    correct_start = time.perf_counter()
    manager.verify_password(password, master_key)
    correct_time = time.perf_counter() - correct_start
    
    wrong_start = time.perf_counter()
    manager.verify_password("wrong", master_key)
    wrong_time = time.perf_counter() - wrong_start
    
    # Время должно быть примерно одинаковым (в пределах 2x)
    assert abs(correct_time - wrong_time) < correct_time * 2


def test_cache_operations():
    """Тест операций с кэшем"""
    manager = DefaultKeyManager()
    
    master_key = manager.derive_master_key("test")
    
    # Генерируем ключи для нескольких пациентов
    for i in range(3):
        manager.generate_data_key(patient_id=i)
    
    # Проверяем статистику кэша
    stats = manager.get_cache_stats()
    assert stats['cached_keys'] == 3
    
    # Получаем ключ из кэша
    key = manager.get_key_for_patient(patient_id=0, master_key=master_key)
    assert key is not None
    assert key.key_bytes is not None
    
    # Очищаем кэш
    manager.clear_cache()
    stats = manager.get_cache_stats()
    assert stats['cached_keys'] == 0


def test_empty_password():
    """Тест с пустым паролем"""
    manager = DefaultKeyManager()
    
    with pytest.raises(ValueError):
        manager.derive_master_key("")


def test_config_parameters():
    """Тест конфигурационных параметров"""
    config = {
        'pbkdf2_iterations': 100000,
        'pbkdf2_key_length': 16,  # 128 бит
    }
    
    manager = DefaultKeyManager(config)
    master_key = manager.derive_master_key("test")
    
    assert master_key.iterations == 100000
    assert len(master_key.key_bytes) == 16  # 128 бит


if __name__ == "__main__":
    pytest.main([__file__, "-v"])