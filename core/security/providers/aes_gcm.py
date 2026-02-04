"""
Провайдер шифрования AES-256-GCM

Стандартный провайдер для медицинского дневника:
- AES-256 для конфиденциальности
- GCM режим для аутентификации
- Дополнительные аутентифицируемые данные (AAD) для контекста
"""

import json
import base64
from typing import Optional, List, Dict, Any
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

from ..interfaces import CryptoProvider
from ..types import DataKey, EncryptedData, EncryptionError, DecryptionError


class AESCryptoProvider(CryptoProvider):
    """
    Провайдер шифрования AES-256-GCM для медицинских данных
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация провайдера AES-GCM
        
        Args:
            config: Конфигурация провайдера
        """
        self.config = config or {}
        
        # Длина nonce для GCM (рекомендуется 96 бит)
        self.nonce_length = self.config.get('nonce_length', 12)
        
        # Версия алгоритма для совместимости
        self.algorithm_version = self.config.get('algorithm_version', '1.0')
    
    def encrypt(self, plaintext: str, data_key: DataKey, 
                additional_data: Optional[bytes] = None) -> EncryptedData:
        """
        Шифрование текстовых данных с использованием AES-256-GCM
        
        Args:
            plaintext: Открытый текст для шифрования
            data_key: Ключ данных пациента
            additional_data: Дополнительные аутентифицируемые данные (AAD)
            
        Returns:
            EncryptedData: Зашифрованные данные с метаданными
            
        Raises:
            EncryptionError: Если шифрование не удалось
        """
        if not plaintext:
            raise EncryptionError("Текст для шифрования не может быть пустым")
        
        if len(data_key.key_bytes) != 32:
            raise EncryptionError(f"Некорректная длина ключа: {len(data_key.key_bytes)} байт")
        
        try:
            # Создаем AESGCM объект с ключом данных
            aesgcm = AESGCM(data_key.key_bytes)
            
            # Генерируем случайный nonce
            nonce = secrets.token_bytes(self.nonce_length)
            
            # Подготавливаем данные для шифрования
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Дополнительные данные (если есть)
            aad = additional_data or self._generate_default_aad(data_key)
            
            # Шифруем
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)
            
            return EncryptedData(
                ciphertext=ciphertext,
                nonce=nonce,
                additional_data=aad,
                version=self.algorithm_version,
                algorithm="AES-256-GCM",
                key_id=data_key.key_id
            )
            
        except Exception as e:
            raise EncryptionError(f"Ошибка шифрования: {str(e)}")
    
    def decrypt(self, encrypted_data: EncryptedData, data_key: DataKey) -> str:
        """
        Дешифрование данных
        
        Args:
            encrypted_data: Зашифрованные данные
            data_key: Ключ данных пациента
            
        Returns:
            str: Расшифрованный текст
            
        Raises:
            DecryptionError: Если дешифрование не удалось
        """
        # Проверяем что ключ подходит
        if encrypted_data.key_id and encrypted_data.key_id != data_key.key_id:
            raise DecryptionError(
                f"Идентификатор ключа не совпадает: "
                f"ожидался {encrypted_data.key_id}, получен {data_key.key_id}"
            )
        
        if len(data_key.key_bytes) != 32:
            raise DecryptionError(f"Некорректная длина ключа: {len(data_key.key_bytes)} байт")
        
        try:
            # Создаем AESGCM объект
            aesgcm = AESGCM(data_key.key_bytes)
            
            # Дешифруем
            plaintext_bytes = aesgcm.decrypt(
                encrypted_data.nonce,
                encrypted_data.ciphertext,
                encrypted_data.additional_data
            )
            
            # Конвертируем в строку
            return plaintext_bytes.decode('utf-8')
            
        except Exception as e:
            raise DecryptionError(f"Ошибка дешифрования: {str(e)}")
    
    def get_supported_algorithms(self) -> List[str]:
        """
        Получение списка поддерживаемых алгоритмов
        
        Returns:
            List[str]: Список алгоритмов
        """
        return ['AES-256-GCM', 'AES-128-GCM']
    
    def get_algorithm_info(self, algorithm: str) -> Dict[str, Any]:
        """
        Получение информации об алгоритме
        
        Args:
            algorithm: Название алгоритма
            
        Returns:
            Dict: Информация об алгоритме
        """
        if algorithm == 'AES-256-GCM':
            return {
                'name': 'AES-256-GCM',
                'key_length': 32,  # 256 бит
                'nonce_length': 12,  # 96 бит
                'tag_length': 16,  # 128 бит
                'mode': 'GCM',
                'authenticated': True,
                'recommended': True
            }
        elif algorithm == 'AES-128-GCM':
            return {
                'name': 'AES-128-GCM',
                'key_length': 16,  # 128 бит
                'nonce_length': 12,
                'tag_length': 16,
                'mode': 'GCM',
                'authenticated': True,
                'recommended': False
            }
        else:
            raise ValueError(f"Неподдерживаемый алгоритм: {algorithm}")
    
    def _generate_default_aad(self, data_key: DataKey) -> bytes:
        """
        Генерация стандартных дополнительных аутентифицируемых данных
        
        Args:
            data_key: Ключ данных
            
        Returns:
            bytes: Дополнительные данные для аутентификации
        """
        aad_data = {
            'key_id': data_key.key_id,
            'algorithm': data_key.algorithm,
            'created_at': data_key.created_at.isoformat(),
            'salt_hash': self._hash_salt(data_key.salt)
        }
        
        return json.dumps(aad_data, ensure_ascii=False).encode('utf-8')
    
    def _hash_salt(self, salt: bytes) -> str:
        """Хэширование соли для AAD"""
        import hashlib
        return hashlib.sha256(salt).hexdigest()[:16]
    
    def encrypt_json(self, data: Dict[str, Any], data_key: DataKey) -> str:
        """
        Удобный метод для шифрования JSON данных
        
        Args:
            data: Словарь с данными
            data_key: Ключ данных
            
        Returns:
            str: Зашифрованные данные в формате JSON строки
        """
        plaintext = json.dumps(data, ensure_ascii=False)
        encrypted = self.encrypt(plaintext, data_key)
        return encrypted.to_json()
    
    def decrypt_json(self, encrypted_json: str, data_key: DataKey) -> Dict[str, Any]:
        """
        Удобный метод для дешифрования JSON данных
        
        Args:
            encrypted_json: Зашифрованные данные в JSON формате
            data_key: Ключ данных
            
        Returns:
            Dict: Расшифрованные данные
        """
        encrypted_data = EncryptedData.from_json(encrypted_json)
        plaintext = self.decrypt(encrypted_data, data_key)
        return json.loads(plaintext)
    
    def encrypt_file(self, file_path: str, data_key: DataKey, 
                    output_path: Optional[str] = None) -> str:
        """
        Шифрование файла
        
        Args:
            file_path: Путь к файлу для шифрования
            data_key: Ключ данных
            output_path: Путь для сохранения (если None, добавляется .enc)
            
        Returns:
            str: Путь к зашифрованному файлу
        """
        if not output_path:
            output_path = file_path + '.enc'
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Кодируем бинарные данные в base64 для корректного UTF-8
            import base64
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # Шифруем
            encrypted = self.encrypt(file_data_b64, data_key)
            
            # Сохраняем
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(encrypted.to_json())
            
            return output_path
            
        except Exception as e:
            raise EncryptionError(f"Ошибка шифрования файла: {str(e)}")

    def decrypt_file(self, encrypted_file_path: str, data_key: DataKey,
                    output_path: Optional[str] = None) -> str:
        """
        Дешифрование файла
        
        Args:
            encrypted_file_path: Путь к зашифрованному файлу
            data_key: Ключ данных
            output_path: Путь для сохранения
            
        Returns:
            str: Путь к расшифрованному файлу
        """
        if not output_path:
            output_path = encrypted_file_path.replace('.enc', '')
        
        try:
            # Читаем зашифрованные данные
            with open(encrypted_file_path, 'r', encoding='utf-8') as f:
                encrypted_json = f.read()
            
            # Дешифруем
            encrypted_data = EncryptedData.from_json(encrypted_json)
            plaintext_b64 = self.decrypt(encrypted_data, data_key)
            
            # Декодируем из base64
            import base64
            file_data = base64.b64decode(plaintext_b64)
            
            # Сохраняем как бинарный файл
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return output_path
            
        except Exception as e:
            raise DecryptionError(f"Ошибка дешифрования файла: {str(e)}")