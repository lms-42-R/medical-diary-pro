"""
Менеджер ключей по умолчанию

Использует:
- PBKDF2-HMAC-SHA256 для вывода мастер-ключа из пароля
- HKDF для генерации ключей данных
- AES-GCM для шифрования ключей данных
"""

import hashlib
import hmac
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..interfaces import KeyManager
from ..types import MasterKey, DataKey, CryptoError, KeyRotationError


class DefaultKeyManager(KeyManager):
    """
    Менеджер ключей по умолчанию для медицинского дневника
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация менеджера ключей
        
        Args:
            config: Конфигурация менеджера ключей
        """
        self.config = config or {}
        
        # Параметры PBKDF2 (можно переопределить в config)
        self.pbkdf2_iterations = self.config.get('pbkdf2_iterations', 600000)
        self.pbkdf2_key_length = self.config.get('pbkdf2_key_length', 32)  # 256 бит
        
        # Параметры HKDF
        self.hkdf_key_length = self.config.get('hkdf_key_length', 32)  # 256 бит
        
        # Кэш расшифрованных ключей (только в памяти)
        self._key_cache: Dict[int, DataKey] = {}
        self._cache_ttl = timedelta(hours=1)  # TTL кэша
        
        # История ключей для ротации
        self._key_history: Dict[int, Dict[str, DataKey]] = {}
    
    def derive_master_key(self, password: str, salt: Optional[bytes] = None) -> MasterKey:
        """
        Вывод мастер-ключа из пароля пользователя с использованием PBKDF2
        
        Args:
            password: Пароль пользователя
            salt: Соль для PBKDF2 (если None - генерируется)
            
        Returns:
            MasterKey: Мастер-ключ пользователя
            
        Note:
            Мастер-ключ НИКОГДА не должен сохраняться на диск!
            Только в оперативной памяти на время сессии.
        """
        if not password:
            raise ValueError("Пароль не может быть пустым")
        
        # Генерация соли если не предоставлена
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Используем PBKDF2 для замедления брутфорса
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.pbkdf2_key_length,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        
        try:
            key_bytes = kdf.derive(password.encode('utf-8'))
            
            return MasterKey(
                key_bytes=key_bytes,
                salt=salt,
                algorithm="PBKDF2-HMAC-SHA256",
                iterations=self.pbkdf2_iterations,
                created_at=datetime.now()
            )
            
        except Exception as e:
            raise CryptoError(f"Ошибка вывода мастер-ключа: {str(e)}")
    
    def generate_data_key(self, patient_id: int) -> DataKey:
        """
        Генерация нового ключа данных для пациента
        
        Args:
            patient_id: ID пациента
            
        Returns:
            DataKey: Уникальный ключ данных пациента
        """
        # Генерируем случайный ключ
        key_bytes = secrets.token_bytes(32)  # 256 бит
        
        # Генерируем уникальную соль для пациента
        salt = secrets.token_bytes(32)
        
        # Создаем идентификатор ключа на основе patient_id и времени
        key_id = self._generate_key_id(patient_id)
        
        key = DataKey(
            key_id=key_id,
            key_bytes=key_bytes,
            salt=salt,
            algorithm="AES-256-GCM",
            created_at=datetime.now()
        )
        
        # Сохраняем в кэш
        self._key_cache[patient_id] = key
        
        # Сохраняем в историю
        if patient_id not in self._key_history:
            self._key_history[patient_id] = {}
        self._key_history[patient_id][key_id] = key
        
        return key
    
    def encrypt_data_key(self, data_key: DataKey, master_key: MasterKey) -> bytes:
        """
        Шифрование ключа данных пациента мастер-ключом врача с использованием AES-GCM
        
        Args:
            data_key: Ключ данных пациента
            master_key: Мастер-ключ врача
            
        Returns:
            bytes: Зашифрованный ключ данных (для хранения в БД)
        """
        try:
            # Создаем AESGCM объект с мастер-ключом
            aesgcm = AESGCM(master_key.key_bytes)
            
            # Генерируем nonce для шифрования
            nonce = secrets.token_bytes(12)  # 96 бит для GCM
            
            # Подготавливаем данные для шифрования
            # Формат: key_bytes + salt + key_id (utf-8)
            plaintext = (
                data_key.key_bytes + 
                data_key.salt + 
                data_key.key_id.encode('utf-8')
            )
            
            # Шифруем ключ данных
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Возвращаем nonce + ciphertext
            return nonce + ciphertext
            
        except Exception as e:
            raise CryptoError(f"Ошибка шифрования ключа данных: {str(e)}")
    
    def decrypt_data_key(self, encrypted_key: bytes, master_key: MasterKey) -> DataKey:
        """
        Расшифровка ключа данных пациента
        
        Args:
            encrypted_key: Зашифрованный ключ из БД (nonce + ciphertext)
            master_key: Мастер-ключ врача
            
        Returns:
            DataKey: Расшифрованный ключ данных
            
        Raises:
            DecryptionError: Если ключ не может быть расшифрован
        """
        try:
            # Извлекаем nonce (первые 12 байт) и ciphertext
            nonce = encrypted_key[:12]
            ciphertext = encrypted_key[12:]
            
            # Создаем AESGCM объект
            aesgcm = AESGCM(master_key.key_bytes)
            
            # Расшифровываем
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Разбираем plaintext: key_bytes(32) + salt(32) + key_id(variable)
            key_bytes = plaintext[:32]
            salt = plaintext[32:64]
            key_id = plaintext[64:].decode('utf-8')
            
            # Проверяем что ключ корректный
            if len(key_bytes) != 32:
                raise DecryptionError("Некорректная длина ключа данных")
            
            # Проверяем что соль корректная
            if len(salt) != 32:
                raise DecryptionError("Некорректная длина соли")
            
            return DataKey(
                key_id=key_id,
                key_bytes=key_bytes,
                salt=salt,
                algorithm="AES-256-GCM",
                created_at=datetime.now()
            )
            
        except Exception as e:
            raise DecryptionError(f"Ошибка расшифровки ключа данных: {str(e)}")
    
    def rotate_data_key(self, patient_id: int, master_key: MasterKey) ->     DataKey:
        """
        Ротация ключа данных пациента
    
        Args:
           patient_id: ID пациента
           master_key: Текущий мастер-ключ врача
        
        Returns:
            DataKey: Новый ключ данных
        """
        # Получаем текущий ключ
        current_key = self.get_key_for_patient(patient_id, master_key)
        if not current_key:
            raise KeyRotationError(f"Ключ для пациента {patient_id} не найден")
    
           # Отмечаем старый ключ как устаревший
        current_key.mark_rotated()  # Используем метод вместо прямого присваивания
    
        # Генерируем новый ключ
        new_key = self.generate_data_key(patient_id)
    
        # Обновляем кэш
        self._key_cache[patient_id] = new_key
    
       # В реальной системе здесь должна быть фоновая задача
       # для перешифрования старых данных новым ключом
    
        return new_key
    
    def get_key_for_patient(self, patient_id: int, master_key: MasterKey) -> Optional[DataKey]:
        """
        Получение ключа данных пациента из кэша
        
        Args:
            patient_id: ID пациента
            master_key: Мастер-ключ врача (не используется в кэше)
            
        Returns:
            Optional[DataKey]: Ключ данных или None если не найден
        """
        # В реальной системе здесь должно быть обращение к БД
        # с расшифровкой зашифрованного ключа
        
        # Пока возвращаем из кэша
        return self._key_cache.get(patient_id)
    
    def get_key_history(self, patient_id: int) -> Dict[str, DataKey]:
        """
        Получение истории ключей пациента
        
        Args:
            patient_id: ID пациента
            
        Returns:
            Dict: История ключей {key_id: DataKey}
        """
        return self._key_history.get(patient_id, {})
    
    def _generate_key_id(self, patient_id: int) -> str:
        """
        Генерация уникального идентификатора ключа
        
        Args:
            patient_id: ID пациента
            
        Returns:
            str: Уникальный идентификатор ключа
        """
        timestamp = int(datetime.now().timestamp())
        random_part = secrets.token_hex(8)
        return f"key_{patient_id}_{timestamp}_{random_part}"
    
    def verify_password(self, password: str, master_key: MasterKey) -> bool:
        """
        Проверка пароля против мастер-ключа
        
        Args:
            password: Пароль для проверки
            master_key: Мастер-ключ для сравнения
            
        Returns:
            bool: True если пароль верный
            
        Note:
            Использует constant-time сравнение для защиты от timing-атак
        """
        try:
            # Выводим ключ из пароля с той же солью
            test_key = self.derive_master_key(password, master_key.salt)
            
            # Constant-time сравнение
            return hmac.compare_digest(
                test_key.key_bytes,
                master_key.key_bytes
            )
        except Exception:
            return False
    
    def clear_cache(self):
        """Очистка кэша ключей"""
        self._key_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Получение статистики кэша"""
        return {
            'cached_keys': len(self._key_cache),
            'key_history_size': sum(len(v) for v in self._key_history.values()),
            'memory_usage_estimate': len(self._key_cache) * 64  # Примерный размер
        }