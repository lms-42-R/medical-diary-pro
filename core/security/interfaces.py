"""
Абстрактные интерфейсы криптографической системы медицинского дневника

Позволяют реализовать различные провайдеры безопасности:
- AES-GCM (стандартный)
- Российские ГОСТ алгоритмы
- Аппаратные HSM модули
- Квантово-безопасные алгоритмы
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from .types import MasterKey, DataKey, EncryptedData, AccessSession


class KeyManager(ABC):
    """
    Менеджер ключей - создание, хранение, ротация ключей
    
    Основные обязанности:
    1. Вывод мастер-ключа из пароля пользователя
    2. Генерация и управление ключами данных пациентов
    3. Ротация ключей по расписанию или требованию
    """
    
    @abstractmethod
    def derive_master_key(self, password: str, salt: Optional[bytes] = None) -> MasterKey:
        """
        Вывод мастер-ключа из пароля пользователя
        
        Args:
            password: Пароль пользователя
            salt: Соль для PBKDF2 (если None - генерируется)
            
        Returns:
            MasterKey: Мастер-ключ пользователя
            
        Note:
            Мастер-ключ НИКОГДА не должен сохраняться на диск!
            Только в оперативной памяти на время сессии.
        """
        pass
    
    @abstractmethod
    def generate_data_key(self, patient_id: int) -> DataKey:
        """
        Генерация нового ключа данных для пациента
        
        Args:
            patient_id: ID пациента
            
        Returns:
            DataKey: Уникальный ключ данных пациента
        """
        pass
    
    @abstractmethod
    def encrypt_data_key(self, data_key: DataKey, master_key: MasterKey) -> bytes:
        """
        Шифрование ключа данных пациента мастер-ключом врача
        
        Args:
            data_key: Ключ данных пациента
            master_key: Мастер-ключ врача
            
        Returns:
            bytes: Зашифрованный ключ данных (для хранения в БД)
        """
        pass
    
    @abstractmethod
    def decrypt_data_key(self, encrypted_key: bytes, master_key: MasterKey) -> DataKey:
        """
        Расшифровка ключа данных пациента
        
        Args:
            encrypted_key: Зашифрованный ключ из БД
            master_key: Мастер-ключ врача
            
        Returns:
            DataKey: Расшифрованный ключ данных
            
        Raises:
            DecryptionError: Если ключ не может быть расшифрован
        """
        pass
    
    @abstractmethod
    def rotate_data_key(self, patient_id: int, master_key: MasterKey) -> DataKey:
        """
        Ротация ключа данных пациента
        
        Args:
            patient_id: ID пациента
            master_key: Текущий мастер-ключ врача
            
        Returns:
            DataKey: Новый ключ данных
            
        Note:
            Старый ключ должен сохраняться для расшифровки старых данных
            до тех пор, пока они не будут перешифрованы новым ключом.
        """
        pass
    
    @abstractmethod
    def get_key_for_patient(self, patient_id: int, master_key: MasterKey) -> Optional[DataKey]:
        """
        Получение ключа данных пациента
        
        Args:
            patient_id: ID пациента
            master_key: Мастер-ключ врача
            
        Returns:
            Optional[DataKey]: Ключ данных или None если не найден
        """
        pass


class CryptoProvider(ABC):
    """
    Провайдер шифрования - алгоритмы шифрования/дешифрования данных
    
    Основные обязанности:
    1. Шифрование медицинских данных
    2. Дешифрование по запросу
    3. Поддержка различных алгоритмов
    """
    
    @abstractmethod
    def encrypt(self, plaintext: str, data_key: DataKey, 
                additional_data: Optional[bytes] = None) -> EncryptedData:
        """
        Шифрование текстовых данных
        
        Args:
            plaintext: Открытый текст для шифрования
            data_key: Ключ данных пациента
            additional_data: Дополнительные аутентифицируемые данные (AAD)
            
        Returns:
            EncryptedData: Зашифрованные данные с метаданными
            
        Raises:
            EncryptionError: Если шифрование не удалось
        """
        pass
    
    @abstractmethod
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
        pass
    
    @abstractmethod
    def get_supported_algorithms(self) -> List[str]:
        """
        Получение списка поддерживаемых алгоритмов
        
        Returns:
            List[str]: Список алгоритмов (например, ['AES-256-GCM', 'ChaCha20-Poly1305'])
        """
        pass
    
    @abstractmethod
    def get_algorithm_info(self, algorithm: str) -> Dict[str, Any]:
        """
        Получение информации об алгоритме
        
        Args:
            algorithm: Название алгоритма
            
        Returns:
            Dict: Информация об алгоритме (ключевая длина, режим и т.д.)
        """
        pass


class AccessManager(ABC):
    """
    Менеджер доступа - управление сессиями и правами доступа к данным
    
    Основные обязанности:
    1. Создание сессий доступа врачей к данным пациентов
    2. Проверка прав доступа
    3. Аудит всех операций доступа
    """
    
    @abstractmethod
    def create_session(self, doctor_id: int, patient_id: int, 
                      access_type: str = 'view',
                      permissions: Optional[Dict[str, bool]] = None,
                      duration_hours: int = 8) -> AccessSession:
        """
        Создание сессии доступа врача к данным пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            access_type: Тип доступа ('view', 'edit', 'emergency')
            permissions: Специфичные права доступа
            duration_hours: Длительность сессии в часах
            
        Returns:
            AccessSession: Созданная сессия доступа
        """
        pass
    
    @abstractmethod
    def validate_session(self, session_id: str) -> bool:
        """
        Проверка валидности сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия активна и не истекла
        """
        pass
    
    @abstractmethod
    def get_session(self, session_id: str) -> Optional[AccessSession]:
        """
        Получение сессии по ID
        
        Args:
            session_id: ID сессии
            
        Returns:
            Optional[AccessSession]: Сессия или None если не найдена
        """
        pass
    
    @abstractmethod
    def revoke_session(self, session_id: str) -> bool:
        """
        Отзыв (завершение) сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия была отозвана
        """
        pass
    
    @abstractmethod
    def revoke_all_sessions(self, doctor_id: int, patient_id: Optional[int] = None) -> int:
        """
        Отзыв всех сессий врача (при смене пароля и т.д.)
        
        Args:
            doctor_id: ID врача
            patient_id: Опционально - конкретный пациент
            
        Returns:
            int: Количество отозванных сессий
        """
        pass
    
    @abstractmethod
    def log_access(self, doctor_id: int, patient_id: int, 
                  action: str, record_type: Optional[str] = None,
                  success: bool = True, details: Optional[Dict] = None):
        """
        Логирование доступа к данным
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            action: Действие ('view', 'edit', 'delete', 'export')
            record_type: Тип записи (если применимо)
            success: Успешно ли действие
            details: Дополнительные детали
        """
        pass


class AuditLogger(ABC):
    """
    Логгер аудита - запись всех действий с медицинскими данными
    
    Основные обязанности:
    1. Логирование всех операций с данными
    2. Хранение логов в соответствии с требованиями
    3. Предоставление логов для проверки
    """
    
    @abstractmethod
    def log(self, event_type: str, user_id: int, 
           target_type: str, target_id: int,
           action: str, details: Dict[str, Any]):
        """
        Запись события в лог аудита
        
        Args:
            event_type: Тип события ('access', 'encrypt', 'decrypt', 'key_rotate')
            user_id: ID пользователя (врача)
            target_type: Тип цели ('patient', 'record', 'measurement')
            target_id: ID цели
            action: Действие ('view', 'create', 'update', 'delete')
            details: Детали события
        """
        pass
    
    @abstractmethod
    def get_logs(self, filters: Optional[Dict[str, Any]] = None,
                limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Получение логов с фильтрацией
        
        Args:
            filters: Фильтры (например, {'user_id': 1, 'date_from': '2024-01-01'})
            limit: Максимальное количество записей
            offset: Смещение
            
        Returns:
            List[Dict]: Список событий аудита
        """
        pass
    
    @abstractmethod
    def export_logs(self, output_format: str = 'json',
                   filters: Optional[Dict[str, Any]] = None) -> str:
        """
        Экспорт логов в указанный формат
        
        Args:
            output_format: Формат вывода ('json', 'csv', 'html')
            filters: Фильтры
            
        Returns:
            str: Экспортированные данные
        """
        pass


class RecoveryManager(ABC):
    """
    Менеджер восстановления доступа - для экстренных случаев
    
    Основные обязанности:
    1. Восстановление доступа к данным при утере пароля
    2. Экстренный доступ для спасения жизни
    3. Управление резервными ключами
    """
    
    @abstractmethod
    def setup_recovery(self, doctor_id: int, 
                      recovery_method: str = 'questions',
                      **kwargs) -> Dict[str, Any]:
        """
        Настройка восстановления доступа
        
        Args:
            doctor_id: ID врача
            recovery_method: Метод восстановления ('questions', 'keyshare', 'print')
            **kwargs: Параметры метода
            
        Returns:
            Dict: Информация о настройке восстановления
        """
        pass
    
    @abstractmethod
    def initiate_emergency_access(self, patient_id: int,
                                requesting_doctor_id: int,
                                reason: str) -> str:
        """
        Инициация экстренного доступа к данным пациента
        
        Args:
            patient_id: ID пациента
            requesting_doctor_id: ID врача, запрашивающего доступ
            reason: Причина экстренного доступа
            
        Returns:
            str: ID запроса на экстренный доступ
        """
        pass
    
    @abstractmethod
    def approve_emergency_access(self, request_id: str,
                               approving_doctor_id: int) -> bool:
        """
        Подтверждение экстренного доступа вторым врачом
        
        Args:
            request_id: ID запроса
            approving_doctor_id: ID подтверждающего врача
            
        Returns:
            bool: True если доступ подтвержден
        """
        pass
    
    @abstractmethod
    def get_emergency_key(self, request_id: str) -> Optional[bytes]:
        """
        Получение временного ключа для экстренного доступа
        
        Args:
            request_id: ID подтвержденного запроса
            
        Returns:
            Optional[bytes]: Временный ключ доступа (действует 24 часа)
        """
        pass


# Фабрика для создания провайдеров
class SecurityProviderFactory:
    """
    Фабрика для создания провайдеров безопасности
    
    Позволяет легко переключаться между различными реализациями
    или использовать несколько провайдеров одновременно.
    """
    
    @staticmethod
    def create_key_manager(provider_type: str = 'default', **kwargs) -> KeyManager:
        """
        Создание менеджера ключей
        
        Args:
            provider_type: Тип провайдера ('default', 'hardware', 'cloud')
            **kwargs: Параметры провайдера
            
        Returns:
            KeyManager: Созданный менеджер ключей
        """
        # Импорт здесь чтобы избежать циклических зависимостей
        if provider_type == 'default':
            from .key_managers.default import DefaultKeyManager
            return DefaultKeyManager(**kwargs)
        else:
            raise ValueError(f"Неизвестный тип провайдера ключей: {provider_type}")
    
    @staticmethod
    def create_crypto_provider(algorithm: str = 'AES-256-GCM', **kwargs) -> CryptoProvider:
        """
        Создание провайдера шифрования
        
        Args:
            algorithm: Алгоритм шифрования
            **kwargs: Параметры провайдера
            
        Returns:
            CryptoProvider: Созданный провайдер шифрования
        """
        if algorithm == 'AES-256-GCM':
            from .providers.aes_gcm import AESCryptoProvider
            return AESCryptoProvider(**kwargs)
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")
    
    @staticmethod
    def create_access_manager(storage_type: str = 'database', **kwargs) -> AccessManager:
        """
        Создание менеджера доступа
        
        Args:
            storage_type: Тип хранилища ('database', 'memory', 'redis')
            **kwargs: Параметры менеджера
            
        Returns:
            AccessManager: Созданный менеджер доступа
        """
        if storage_type == 'database':
            from .access.database import DatabaseAccessManager
            return DatabaseAccessManager(**kwargs)
        else:
            raise ValueError(f"Неизвестный тип хранилища: {storage_type}")