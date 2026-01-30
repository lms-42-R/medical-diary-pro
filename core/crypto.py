# core/crypto.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os
import json

class DataCrypto:
    """Шифрование медицинских данных с использованием AES-GCM"""
    
    def __init__(self, salt: bytes = None):
        """
        Инициализация криптографического модуля
        
        Args:
            salt: Соль для PBKDF2 (если None, будет использована стандартная)
        """
        self.salt = salt or b'medical_diary_salt_2024'  # В production должен быть уникальным
        self.encoding = 'utf-8'
        
    def derive_key(self, password: str) -> bytes:
        """
        Генерация криптографического ключа из пароля
        
        Args:
            password: Пароль пользователя
            
        Returns:
            bytes: 32-байтный ключ для AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 требует 32 байта
            salt=self.salt,
            iterations=100000,  # Рекомендуемое количество итераций
        )
        return kdf.derive(password.encode(self.encoding))
    
    def encrypt(self, plaintext: str, key: bytes) -> str:
        """
        Шифрование текста
        
        Args:
            plaintext: Открытый текст для шифрования
            key: Ключ шифрования
            
        Returns:
            str: JSON строка с зашифрованными данными в base64
        """
        if not plaintext:
            return ""
            
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96 бит для GCM
        
        # Шифрование
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(self.encoding), None)
        
        # Формируем структуру данных
        encrypted_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(self.encoding),
            'nonce': base64.b64encode(nonce).decode(self.encoding),
            'version': '1.0'
        }
        
        return json.dumps(encrypted_data)
    
    def decrypt(self, encrypted_json: str, key: bytes) -> str:
        """
        Дешифрование текста
        
        Args:
            encrypted_json: JSON строка с зашифрованными данными
            key: Ключ шифрования
            
        Returns:
            str: Расшифрованный текст
            
        Raises:
            ValueError: Если данные повреждены или ключ неверный
        """
        if not encrypted_json:
            return ""
            
        try:
            encrypted_data = json.loads(encrypted_json)
            
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode(self.encoding)
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def test_encryption(self, password: str = "test_password") -> bool:
        """
        Тест шифрования/дешифрования
        
        Args:
            password: Тестовый пароль
            
        Returns:
            bool: True если тест пройден
        """
        test_text = "Тестовое медицинское сообщение: АД 120/80, пульс 72"
        key = self.derive_key(password)
        
        try:
            encrypted = self.encrypt(test_text, key)
            decrypted = self.decrypt(encrypted, key)
            
            success = decrypted == test_text
            if success:
                print("✓ Crypto test PASSED")
            else:
                print("✗ Crypto test FAILED: decrypted text doesn't match")
                
            return success
            
        except Exception as e:
            print(f"✗ Crypto test FAILED with error: {str(e)}")
            return False


if __name__ == "__main__":
    # Запуск теста при прямом выполнении файла
    crypto = DataCrypto()
    if crypto.test_encryption():
        print("Crypto module is working correctly!")
    else:
        print("Crypto module has issues!")