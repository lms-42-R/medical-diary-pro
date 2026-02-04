"""
Тесты провайдера шифрования AES-GCM
"""

import sys
import os
import pytest
import json
import tempfile

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.security.providers.aes_gcm import AESCryptoProvider
from core.security.types import DataKey, EncryptedData
from core.security.key_managers.default import DefaultKeyManager


def test_encrypt_decrypt_text():
    """Тест шифрования и дешифрования текста"""
    provider = AESCryptoProvider()
    key_manager = DefaultKeyManager()
    
    # Создаем ключ данных
    data_key = DataKey.generate()
    
    # Текст для шифрования
    plaintext = "Конфиденциальные медицинские данные: АД 120/80, пульс 72"
    
    # Шифруем
    encrypted = provider.encrypt(plaintext, data_key)
    
    # Проверяем структуру
    assert len(encrypted.ciphertext) > 0
    assert len(encrypted.nonce) == 12  # 96 бит
    assert len(encrypted.additional_data) > 0
    assert encrypted.algorithm == "AES-256-GCM"
    assert encrypted.key_id == data_key.key_id
    
    # Дешифруем
    decrypted = provider.decrypt(encrypted, data_key)
    
    # Проверяем что получили исходный текст
    assert decrypted == plaintext


def test_encrypt_decrypt_with_different_keys():
    """Тест что разные ключи дают разные результаты"""
    provider = AESCryptoProvider()
    
    # Два разных ключа
    key1 = DataKey.generate()
    key2 = DataKey.generate()
    
    plaintext = "Одинаковый текст"
    
    # Шифруем одним ключом
    encrypted1 = provider.encrypt(plaintext, key1)
    
    # Шифруем другим ключом
    encrypted2 = provider.encrypt(plaintext, key2)
    
    # Шифротексты должны быть разными
    assert encrypted1.ciphertext != encrypted2.ciphertext
    assert encrypted1.nonce != encrypted2.nonce
    
    # Каждый ключ должен расшифровать только свои данные
    decrypted1 = provider.decrypt(encrypted1, key1)
    assert decrypted1 == plaintext
    
    decrypted2 = provider.decrypt(encrypted2, key2)
    assert decrypted2 == plaintext
    
    # Ключ 1 не должен расшифровать данные ключа 2
    with pytest.raises(Exception):
        provider.decrypt(encrypted2, key1)
    
    # Ключ 2 не должен расшифровать данные ключа 1
    with pytest.raises(Exception):
        provider.decrypt(encrypted1, key2)


def test_encrypt_empty_text():
    """Тест шифрования пустого текста"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    with pytest.raises(Exception):
        provider.encrypt("", data_key)


def test_decrypt_tampered_data():
    """Тест дешифрования подмененных данных"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    plaintext = "Медицинские данные"
    encrypted = provider.encrypt(plaintext, data_key)
    
    # Подменяем шифротекст
    tampered = EncryptedData(
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 0x01]),
        nonce=encrypted.nonce,
        additional_data=encrypted.additional_data,
        key_id=encrypted.key_id
    )
    
    # Должна быть ошибка аутентификации
    with pytest.raises(Exception):
        provider.decrypt(tampered, data_key)


def test_json_encryption():
    """Тест шифрования JSON данных"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    # Медицинские данные в формате JSON
    medical_data = {
        "patient_id": 123,
        "measurements": {
            "blood_pressure": "120/80",
            "heart_rate": 72,
            "temperature": 36.6
        },
        "diagnosis": "Эссенциальная гипертензия",
        "medications": ["Лизиноприл 10мг", "Аторвастатин 20мг"]
    }
    
    # Шифруем
    encrypted_json = provider.encrypt_json(medical_data, data_key)
    
    # Проверяем что это валидный JSON
    parsed = json.loads(encrypted_json)
    assert 'ciphertext' in parsed
    assert 'nonce' in parsed
    
    # Дешифруем
    decrypted = provider.decrypt_json(encrypted_json, data_key)
    
    # Проверяем что данные совпадают
    assert decrypted == medical_data


def test_additional_data():
    """Тест работы с дополнительными аутентифицируемыми данными (AAD)"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    plaintext = "Конфиденциальные данные"
    
    # Свои дополнительные данные
    custom_aad = json.dumps({
        "record_type": "diagnosis",
        "doctor_id": 1,
        "timestamp": "2024-01-01T12:00:00"
    }).encode('utf-8')
    
    # Шифруем с кастомными AAD
    encrypted = provider.encrypt(plaintext, data_key, custom_aad)
    assert encrypted.additional_data == custom_aad
    
    # Корректно дешифруем
    decrypted = provider.decrypt(encrypted, data_key)
    assert decrypted == plaintext
    
    # Меняем AAD - должно не дешифроваться
    wrong_aad = json.dumps({"wrong": "data"}).encode('utf-8')
    tampered = EncryptedData(
        ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        additional_data=wrong_aad,
        key_id=encrypted.key_id
    )
    
    with pytest.raises(Exception):
        provider.decrypt(tampered, data_key)


def test_supported_algorithms():
    """Тест получения списка поддерживаемых алгоритмов"""
    provider = AESCryptoProvider()
    
    algorithms = provider.get_supported_algorithms()
    
    assert "AES-256-GCM" in algorithms
    assert "AES-128-GCM" in algorithms
    assert len(algorithms) == 2


def test_algorithm_info():
    """Тест получения информации об алгоритмах"""
    provider = AESCryptoProvider()
    
    # Информация о AES-256-GCM
    info_256 = provider.get_algorithm_info("AES-256-GCM")
    assert info_256['name'] == "AES-256-GCM"
    assert info_256['key_length'] == 32
    assert info_256['authenticated'] == True
    assert info_256['recommended'] == True
    
    # Информация о AES-128-GCM
    info_128 = provider.get_algorithm_info("AES-128-GCM")
    assert info_128['name'] == "AES-128-GCM"
    assert info_128['key_length'] == 16
    assert info_128['recommended'] == False
    
    # Неподдерживаемый алгоритм
    with pytest.raises(ValueError):
        provider.get_algorithm_info("DES")


def test_file_encryption():
    """Тест шифрования файлов"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    # Создаем временный файл с медицинскими данными
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write("Медицинская запись пациента\n")
        f.write("Давление: 120/80\n")
        f.write("Пульс: 72\n")
        f.write("Диагноз: Эссенциальная гипертензия\n")
        temp_file = f.name
    
    encrypted_file = temp_file + '.enc'
    decrypted_file = temp_file + '.dec'
    
    try:
        # Шифруем файл
        result = provider.encrypt_file(temp_file, data_key, encrypted_file)
        assert result == encrypted_file
        assert os.path.exists(encrypted_file)
        
        # Дешифруем файл
        result = provider.decrypt_file(encrypted_file, data_key, decrypted_file)
        assert result == decrypted_file
        assert os.path.exists(decrypted_file)
        
        # Проверяем содержимое
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        with open(temp_file, 'r', encoding='utf-8') as f:
            original = f.read()
        
        assert content == original
        
    finally:
        # Удаляем временные файлы
        for file_path in [temp_file, encrypted_file, decrypted_file]:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except:
                    pass


def test_configuration():
    """Тест конфигурации провайдера"""
    config = {
        'nonce_length': 16,
        'algorithm_version': '2.0'
    }
    
    provider = AESCryptoProvider(config)
    data_key = DataKey.generate()
    
    plaintext = "Тестовый текст"
    encrypted = provider.encrypt(plaintext, data_key)
    
    assert len(encrypted.nonce) == 16  # Из конфигурации
    assert encrypted.version == '2.0'  # Из конфигурации


def test_encrypted_data_serialization():
    """Тест сериализации зашифрованных данных"""
    provider = AESCryptoProvider()
    data_key = DataKey.generate()
    
    plaintext = "Данные для теста сериализации"
    encrypted = provider.encrypt(plaintext, data_key)
    
    # В JSON и обратно
    json_str = encrypted.to_json()
    encrypted2 = EncryptedData.from_json(json_str)
    
    # Проверяем что данные совпадают
    assert encrypted.ciphertext == encrypted2.ciphertext
    assert encrypted.nonce == encrypted2.nonce
    assert encrypted.additional_data == encrypted2.additional_data
    
    # Должны расшифроваться одинаково
    decrypted1 = provider.decrypt(encrypted, data_key)
    decrypted2 = provider.decrypt(encrypted2, data_key)
    
    assert decrypted1 == decrypted2 == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])