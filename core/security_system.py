"""
Главная система безопасности медицинского дневника

Объединяет все модули безопасности в единую систему:
- Управление ключами врачей и пациентов
- Шифрование/дешифрование медицинских данных
- Управление доступом и сессиями
- Аудит всех операций
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from security.key_managers.default import DefaultKeyManager
from security.providers.aes_gcm import AESCryptoProvider
from security.access.memory import MemoryAccessManager
from security.types import (
    MasterKey, DataKey, EncryptedData, AccessSession,
    SecurityConfig, CryptoError, AccessDeniedError
)


class MedicalSecuritySystem:
    """
    Главная система безопасности медицинского дневника
    
    Предоставляет единый интерфейс для всех криптографических операций:
    1. Настройка и управление врачами
    2. Создание и управление ключами пациентов
    3. Шифрование/дешифрование медицинских данных
    4. Управление сессиями доступа
    5. Аудит всех операций
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Инициализация системы безопасности
        
        Args:
            config: Конфигурация безопасности (если None - используется по умолчанию)
        """
        self.config = config or SecurityConfig()
        
        # Инициализация компонентов
        self.key_manager = DefaultKeyManager({
            'pbkdf2_iterations': self.config.pbkdf2_iterations,
            'pbkdf2_key_length': self.config.pbkdf2_key_length
        })
        
        self.crypto_provider = AESCryptoProvider({
            'algorithm_version': '2.0'
        })
        
        self.access_manager = MemoryAccessManager({
            'default_session_hours': self.config.session_expiry_hours,
            'max_log_entries': 10000
        })
        
        # Кэш мастер-ключей (в памяти, только на время работы)
        self._master_keys: Dict[int, MasterKey] = {}
        
        # Кэш ключей данных пациентов (в памяти)
        self._patient_keys: Dict[int, Dict[int, DataKey]] = {}
        
        # Статистика использования
        self._stats = {
            'encryptions': 0,
            'decryptions': 0,
            'sessions_created': 0,
            'errors': 0
        }
    
    # ==================== УПРАВЛЕНИЕ ВРАЧАМИ ====================
    
    def setup_doctor(self, doctor_id: int, password: str, 
                    doctor_salt: Optional[bytes] = None) -> MasterKey:
        """
        Настройка безопасности для врача
        
        Args:
            doctor_id: Уникальный ID врача
            password: Пароль врача
            doctor_salt: Соль для вывода ключа (если None - генерируется)
            
        Returns:
            MasterKey: Созданный мастер-ключ врача
            
        Note:
            Мастер-ключ хранится только в оперативной памяти!
            Для постоянного хранения нужно сохранить соль врача в БД.
        """
        try:
            # Вывод мастер-ключа из пароля
            master_key = self.key_manager.derive_master_key(password, doctor_salt)
            
            # Сохраняем в кэш
            self._master_keys[doctor_id] = master_key
            
            # Логируем
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=0,
                action='setup_doctor',
                success=True,
                details={'has_salt': doctor_salt is not None}
            )
            
            return master_key
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=0,
                action='setup_doctor',
                success=False,
                details={'error': str(e)}
            )
            raise CryptoError(f"Ошибка настройки врача: {str(e)}")
    
    def login_doctor(self, doctor_id: int, password: str, 
                    doctor_salt: bytes) -> bool:
        """
        Аутентификация врача
        
        Args:
            doctor_id: ID врача
            password: Пароль для проверки
            doctor_salt: Соль врача из БД
            
        Returns:
            bool: True если аутентификация успешна
            
        Note:
            В реальной системе соль должна храниться в БД отдельно для каждого врача.
        """
        try:
            # Выводим мастер-ключ из пароля
            master_key = self.key_manager.derive_master_key(password, doctor_salt)
            
            # Проверяем пароль
            is_valid = self.key_manager.verify_password(password, master_key)
            
            if is_valid:
                # Сохраняем мастер-ключ в кэш
                self._master_keys[doctor_id] = master_key
                
                self.access_manager.log_access(
                    doctor_id=doctor_id,
                    patient_id=0,
                    action='login',
                    success=True
                )
            else:
                self.access_manager.log_access(
                    doctor_id=doctor_id,
                    patient_id=0,
                    action='login',
                    success=False,
                    details={'reason': 'invalid_password'}
                )
            
            return is_valid
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=0,
                action='login',
                success=False,
                details={'error': str(e)}
            )
            return False
    
    def get_doctor_master_key(self, doctor_id: int) -> Optional[MasterKey]:
        """
        Получение мастер-ключа врача из кэша
        
        Args:
            doctor_id: ID врача
            
        Returns:
            Optional[MasterKey]: Мастер-ключ или None если врач не аутентифицирован
        """
        return self._master_keys.get(doctor_id)
    
    def logout_doctor(self, doctor_id: int) -> bool:
        """
        Выход врача из системы
        
        Args:
            doctor_id: ID врача
            
        Returns:
            bool: True если выход успешен
        """
        if doctor_id in self._master_keys:
            # Удаляем мастер-ключ из кэша
            del self._master_keys[doctor_id]
            
            # Отзываем все сессии врача
            self.access_manager.revoke_all_sessions(doctor_id)
            
            # Очищаем кэш ключей пациентов этого врача
            if doctor_id in self._patient_keys:
                del self._patient_keys[doctor_id]
            
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=0,
                action='logout',
                success=True
            )
            return True
        
        return False
    
    # ==================== УПРАВЛЕНИЕ ПАЦИЕНТАМИ ====================
    
    def setup_patient(self, doctor_id: int, patient_id: int) -> DataKey:
        """
        Настройка безопасности для пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            DataKey: Ключ данных пациента
            
        Raises:
            CryptoError: Если врач не аутентифицирован
        """
        master_key = self.get_doctor_master_key(doctor_id)
        if not master_key:
            raise CryptoError(f"Врач {doctor_id} не аутентифицирован")
        
        try:
            # Генерируем ключ данных для пациента
            data_key = self.key_manager.generate_data_key(patient_id)
            
            # Сохраняем в кэш
            if doctor_id not in self._patient_keys:
                self._patient_keys[doctor_id] = {}
            self._patient_keys[doctor_id][patient_id] = data_key
            
            # Логируем
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='setup_patient',
                success=True,
                details={'key_id': data_key.key_id}
            )
            
            return data_key
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='setup_patient',
                success=False,
                details={'error': str(e)}
            )
            raise CryptoError(f"Ошибка настройки пациента: {str(e)}")
    
    def get_patient_key(self, doctor_id: int, patient_id: int) -> Optional[DataKey]:
        """
        Получение ключа данных пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            Optional[DataKey]: Ключ данных или None если не найден
        """
        # Пытаемся получить из кэша
        if (doctor_id in self._patient_keys and 
            patient_id in self._patient_keys[doctor_id]):
            return self._patient_keys[doctor_id][patient_id]
        
        return None
    
    def rotate_patient_key(self, doctor_id: int, patient_id: int) -> DataKey:
        """
        Ротация ключа данных пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            DataKey: Новый ключ данных
            
        Note:
            Старый ключ сохраняется для дешифрования старых данных.
            Новые данные шифруются новым ключом.
        """
        master_key = self.get_doctor_master_key(doctor_id)
        if not master_key:
            raise CryptoError(f"Врач {doctor_id} не аутентифицирован")
        
        try:
            # Ротируем ключ
            new_key = self.key_manager.rotate_data_key(patient_id, master_key)
            
            # Обновляем кэш
            if doctor_id not in self._patient_keys:
                self._patient_keys[doctor_id] = {}
            self._patient_keys[doctor_id][patient_id] = new_key
            
            # Логируем
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='rotate_key',
                success=True,
                details={'new_key_id': new_key.key_id}
            )
            
            return new_key
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='rotate_key',
                success=False,
                details={'error': str(e)}
            )
            raise CryptoError(f"Ошибка ротации ключа: {str(e)}")
    
    # ==================== ШИФРОВАНИЕ ДАННЫХ ====================
    
    def encrypt_patient_data(self, doctor_id: int, patient_id: int, 
                           plaintext: str, additional_data: Optional[Dict] = None) -> str:
        """
        Шифрование данных пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            plaintext: Открытый текст для шифрования
            additional_data: Дополнительные данные для аутентификации
            
        Returns:
            str: Зашифрованные данные в формате JSON
            
        Raises:
            CryptoError: Если ключ не найден или шифрование не удалось
        """
        # Получаем ключ пациента
        data_key = self.get_patient_key(doctor_id, patient_id)
        if not data_key:
            # Пытаемся создать ключ, если пациента еще нет в системе
            data_key = self.setup_patient(doctor_id, patient_id)
        
        try:
            # Подготавливаем дополнительные данные
            aad = None
            if additional_data:
                aad = json.dumps(additional_data, ensure_ascii=False).encode('utf-8')
            
            # Шифруем
            encrypted = self.crypto_provider.encrypt(plaintext, data_key, aad)
            
            # Обновляем статистику
            self._stats['encryptions'] += 1
            
            # Логируем
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='encrypt_data',
                success=True,
                details={
                    'data_length': len(plaintext),
                    'has_additional_data': additional_data is not None
                }
            )
            
            return encrypted.to_json()
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='encrypt_data',
                success=False,
                details={'error': str(e)}
            )
            raise CryptoError(f"Ошибка шифрования: {str(e)}")
    
    def decrypt_patient_data(self, doctor_id: int, patient_id: int, 
                           encrypted_json: str) -> str:
        """
        Дешифрование данных пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            encrypted_json: Зашифрованные данные в формате JSON
            
        Returns:
            str: Расшифрованный текст
            
        Raises:
            CryptoError: Если ключ не найден или дешифрование не удалось
            AccessDeniedError: Если у врача нет доступа к данным пациента
        """
        # Проверяем доступ врача к пациенту
        if not self._check_doctor_access(doctor_id, patient_id):
            raise AccessDeniedError(
                f"Врач {doctor_id} не имеет доступа к пациенту {patient_id}"
            )
        
        # Получаем ключ пациента
        data_key = self.get_patient_key(doctor_id, patient_id)
        if not data_key:
            raise CryptoError(f"Ключ для пациента {patient_id} не найден")
        
        try:
            # Дешифруем
            encrypted_data = EncryptedData.from_json(encrypted_json)
            plaintext = self.crypto_provider.decrypt(encrypted_data, data_key)
            
            # Обновляем статистику
            self._stats['decryptions'] += 1
            
            # Логируем
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='decrypt_data',
                success=True,
                details={'data_length': len(plaintext)}
            )
            
            return plaintext
            
        except Exception as e:
            self._stats['errors'] += 1
            self.access_manager.log_access(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='decrypt_data',
                success=False,
                details={'error': str(e)}
            )
            raise CryptoError(f"Ошибка дешифрования: {str(e)}")
    
    # ==================== УПРАВЛЕНИЕ ДОСТУПОМ ====================
    
    def create_access_session(self, doctor_id: int, patient_id: int,
                            access_type: str = 'view',
                            duration_hours: int = 8) -> AccessSession:
        """
        Создание сессии доступа врача к данным пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            access_type: Тип доступа ('view', 'edit', 'emergency')
            duration_hours: Длительность сессии в часах
            
        Returns:
            AccessSession: Созданная сессия доступа
        """
        try:
            session = self.access_manager.create_session(
                doctor_id=doctor_id,
                patient_id=patient_id,
                access_type=access_type,
                duration_hours=duration_hours
            )
            
            self._stats['sessions_created'] += 1
            
            return session
            
        except Exception as e:
            self._stats['errors'] += 1
            raise CryptoError(f"Ошибка создания сессии: {str(e)}")
    
    def validate_access_session(self, session_id: str) -> bool:
        """
        Проверка валидности сессии доступа
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия активна и валидна
        """
        return self.access_manager.validate_session(session_id)
    
    def get_session(self, session_id: str) -> Optional[AccessSession]:
        """
        Получение сессии по ID
        
        Args:
            session_id: ID сессии
            
        Returns:
            Optional[AccessSession]: Сессия или None если не найдена
        """
        return self.access_manager.get_session(session_id)
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Отзыв сессии доступа
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия была отозвана
        """
        return self.access_manager.revoke_session(session_id)
    
    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================
    
    def _check_doctor_access(self, doctor_id: int, patient_id: int) -> bool:
        """
        Проверка доступа врача к пациенту
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            bool: True если врач имеет доступ к пациенту
            
        Note:
            В реальной системе здесь должна быть проверка из БД.
            Сейчас всегда возвращает True для упрощения.
        """
        # TODO: Реализовать проверку из БД
        # Проверять что пациент действительно принадлежит врачу
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики использования системы
        
        Returns:
            Dict: Статистика
        """
        access_stats = self.access_manager.get_stats()
        
        return {
            'security_system': self._stats,
            'access_manager': access_stats,
            'master_keys_cached': len(self._master_keys),
            'patient_keys_cached': sum(len(v) for v in self._patient_keys.values()),
            'timestamp': datetime.now().isoformat()
        }
    
    def clear_cache(self):
        """Очистка всех кэшей"""
        self._master_keys.clear()
        self._patient_keys.clear()
        self.key_manager.clear_cache()
    
    def get_access_logs(self, filters: Optional[Dict[str, Any]] = None,
                       limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Получение логов доступа
        
        Args:
            filters: Фильтры для логов
            limit: Максимальное количество записей
            offset: Смещение
            
        Returns:
            List[Dict]: Логи доступа
        """
        return self.access_manager.get_access_logs(filters, limit, offset)
    
    def get_active_sessions(self, doctor_id: Optional[int] = None,
                           patient_id: Optional[int] = None) -> List[AccessSession]:
        """
        Получение активных сессий
        
        Args:
            doctor_id: Фильтр по врачу
            patient_id: Фильтр по пациенту
            
        Returns:
            List[AccessSession]: Активные сессии
        """
        return self.access_manager.get_active_sessions(doctor_id, patient_id)
    
    def cleanup_expired_sessions(self) -> int:
        """
        Очистка истекших сессий
        
        Returns:
            int: Количество очищенных сессий
        """
        return self.access_manager.cleanup_expired_sessions()


# Синглтон для удобного доступа
_security_system_instance = None

def get_security_system(config: Optional[SecurityConfig] = None) -> MedicalSecuritySystem:
    """
    Получение экземпляра системы безопасности
    
    Args:
        config: Конфигурация (если None - используется по умолчанию)
        
    Returns:
        MedicalSecuritySystem: Экземпляр системы безопасности
    """
    global _security_system_instance
    if _security_system_instance is None:
        _security_system_instance = MedicalSecuritySystem(config)
    return _security_system_instance


if __name__ == "__main__":
    # Демонстрация работы системы
    print("🧪 Демонстрация MedicalSecuritySystem")
    print("=" * 60)
    
    # Создаем систему
    security = MedicalSecuritySystem()
    
    try:
        # 1. Настройка врача
        print("1. Настройка врача...")
        doctor_salt = b"test_salt_for_doctor_123"
        master_key = security.setup_doctor(
            doctor_id=1,
            password="SecureDoctorPass123",
            doctor_salt=doctor_salt
        )
        print(f"   ✅ Мастер-ключ создан: {master_key.key_id[:16]}...")
        
        # 2. Настройка пациента
        print("2. Настройка пациента...")
        patient_key = security.setup_patient(doctor_id=1, patient_id=5)
        print(f"   ✅ Ключ пациента создан: {patient_key.key_id[:16]}...")
        
        # 3. Шифрование данных
        print("3. Шифрование медицинских данных...")
        medical_data = "Диагноз: Эссенциальная гипертензия. АД: 140/90, пульс: 80"
        encrypted = security.encrypt_patient_data(
            doctor_id=1,
            patient_id=5,
            plaintext=medical_data,
            additional_data={"record_type": "diagnosis", "timestamp": "2024-01-01"}
        )
        print(f"   ✅ Данные зашифрованы ({len(encrypted)} байт)")
        
        # 4. Дешифрование данных
        print("4. Дешифрование данных...")
        decrypted = security.decrypt_patient_data(
            doctor_id=1,
            patient_id=5,
            encrypted_json=encrypted
        )
        print(f"   ✅ Данные расшифрованы: {decrypted[:50]}...")
        
        # 5. Создание сессии доступа
        print("5. Создание сессии доступа...")
        session = security.create_access_session(
            doctor_id=1,
            patient_id=5,
            access_type='view',
            duration_hours=4
        )
        print(f"   ✅ Сессия создана: {session.session_id}")
        
        # 6. Проверка сессии
        print("6. Проверка сессии...")
        is_valid = security.validate_access_session(session.session_id)
        print(f"   ✅ Сессия валидна: {is_valid}")
        
        # 7. Статистика
        print("7. Статистика системы...")
        stats = security.get_statistics()
        print(f"   📊 Шифрований: {stats['security_system']['encryptions']}")
        print(f"   📊 Дешифрований: {stats['security_system']['decryptions']}")
        print(f"   📊 Сессий создано: {stats['security_system']['sessions_created']}")
        
        # 8. Получение логов
        print("8. Получение логов доступа...")
        logs = security.get_access_logs(limit=5)
        print(f"   📝 Последние {len(logs)} событий:")
        for log in logs:
            print(f"     - {log['action']}: {log.get('success', 'N/A')}")
        
        print("\n" + "=" * 60)
        print("🎉 Система безопасности работает корректно!")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()