"""
Фасад криптосистемы медицинского дневника

Предоставляет максимально простой API для работы с криптографией:
- Минимальное количество методов
- Автоматическая обработка ошибок
- Готовые структуры данных для UI
- Поддержка всех операций безопасности
"""

from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import json

from security_system import MedicalSecuritySystem, get_security_system
from security.types import SecurityConfig, AccessSession, CryptoError, AccessDeniedError


@dataclass
class DoctorInfo:
    """Информация о враче для UI"""
    doctor_id: int
    username: str
    full_name: str
    is_authenticated: bool = False
    salt: Optional[bytes] = None  # Только для внутреннего использования
    last_login: Optional[datetime] = None


@dataclass
class PatientInfo:
    """Информация о пациенте для UI"""
    patient_id: int
    doctor_id: int
    full_name: str
    has_encryption_key: bool = False
    key_created: Optional[datetime] = None
    last_accessed: Optional[datetime] = None


@dataclass
class MedicalRecord:
    """Медицинская запись для UI"""
    record_id: int
    patient_id: int
    record_type: str  # 'diagnosis', 'examination', 'prescription', etc
    encrypted_content: str  # Зашифрованные данные
    created_at: datetime
    tags: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SessionInfo:
    """Информация о сессии для UI"""
    session_id: str
    doctor_id: int
    patient_id: int
    access_type: str  # 'view', 'edit', 'emergency'
    permissions: Dict[str, bool]
    created_at: datetime
    expires_at: datetime
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для JSON"""
        return {
            'session_id': self.session_id,
            'doctor_id': self.doctor_id,
            'patient_id': self.patient_id,
            'access_type': self.access_type,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'is_active': self.is_active
        }


@dataclass
class EncryptionResult:
    """Результат шифрования для UI"""
    success: bool
    encrypted_data: Optional[str] = None
    error_message: Optional[str] = None
    record_id: Optional[int] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class DecryptionResult:
    """Результат дешифрования для UI"""
    success: bool
    plaintext: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class MedicalCryptoFacade:
    """
    Фасад криптосистемы медицинского дневника
    
    Предоставляет простой API для всех криптографических операций:
    1. Регистрация и аутентификация врачей
    2. Управление пациентами и их ключами
    3. Шифрование/дешифрование медицинских данных
    4. Управление сессиями доступа
    5. Получение статистики и логов
    
    Все сложности криптографии скрыты от пользователя API.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Инициализация фасада
        
        Args:
            config: Конфигурация безопасности
        """
        # Основная система безопасности
        self.security_system = get_security_system(config)
        
        # Хранилище информации о врачах (в памяти, для демонстрации)
        # В реальной системе должно быть в БД
        self._doctors: Dict[int, DoctorInfo] = {}
        
        # Хранилище информации о пациентах (в памяти)
        self._patients: Dict[int, PatientInfo] = {}
        
        # Хранилище медицинских записей (в памяти)
        self._medical_records: Dict[int, MedicalRecord] = {}
        
        # Счетчик для ID записей
        self._next_record_id = 1
        
        # Кэш сессий для быстрого доступа
        self._sessions_cache: Dict[str, SessionInfo] = {}
    
    # ==================== УПРАВЛЕНИЕ ВРАЧАМИ ====================
    
    def register_doctor(self, username: str, password: str, 
                       full_name: str) -> DoctorInfo:
        """
        Регистрация нового врача
        
        Args:
            username: Имя пользователя
            password: Пароль
            full_name: Полное имя врача
            
        Returns:
            DoctorInfo: Информация о зарегистрированном враче
            
        Raises:
            ValueError: Если данные невалидны
            CryptoError: Если регистрация не удалась
        """
        # Валидация входных данных
        if not username or len(username) < 3:
            raise ValueError("Имя пользователя должно быть не менее 3 символов")
        
        if not password or len(password) < 8:
            raise ValueError("Пароль должен быть не менее 8 символов")
        
        if not full_name:
            raise ValueError("Полное имя обязательно")
        
        try:
            # Генерируем уникальный ID врача
            doctor_id = max(self._doctors.keys(), default=0) + 1
            
            # Генерируем уникальную соль для врача
            import secrets
            doctor_salt = secrets.token_bytes(32)
            
            # Настраиваем безопасность для врача
            self.security_system.setup_doctor(doctor_id, password, doctor_salt)
            
            # Создаем информацию о враче
            doctor = DoctorInfo(
                doctor_id=doctor_id,
                username=username,
                full_name=full_name,
                salt=doctor_salt,
                last_login=datetime.now()
            )
            
            # Сохраняем
            self._doctors[doctor_id] = doctor
            
            # Логируем
            self._log_operation(
                doctor_id=doctor_id,
                action='register_doctor',
                success=True,
                details={'username': username}
            )
            
            return doctor
            
        except Exception as e:
            self._log_operation(
                doctor_id=0,
                action='register_doctor',
                success=False,
                details={'error': str(e), 'username': username}
            )
            raise CryptoError(f"Ошибка регистрации врача: {str(e)}")
    
    def login_doctor(self, username: str, password: str) -> Optional[DoctorInfo]:
        """
        Аутентификация врача
        
        Args:
            username: Имя пользователя
            password: Пароль
            
        Returns:
            Optional[DoctorInfo]: Информация о враче или None если аутентификация не удалась
        """
        # Ищем врача по username
        doctor = None
        for doc in self._doctors.values():
            if doc.username == username:
                doctor = doc
                break
        
        if not doctor:
            # Не показываем что пользователь не существует (защита от timing-атак)
            self._dummy_login_check()
            return None
        
        try:
            # Аутентифицируем врача
            is_authenticated = self.security_system.login_doctor(
                doctor_id=doctor.doctor_id,
                password=password,
                doctor_salt=doctor.salt
            )
            
            if is_authenticated:
                # Обновляем информацию о враче
                doctor.is_authenticated = True
                doctor.last_login = datetime.now()
                self._doctors[doctor.doctor_id] = doctor
                
                self._log_operation(
                    doctor_id=doctor.doctor_id,
                    action='login',
                    success=True,
                    details={'username': username}
                )
                
                return doctor
            else:
                self._log_operation(
                    doctor_id=doctor.doctor_id,
                    action='login',
                    success=False,
                    details={'username': username, 'reason': 'invalid_password'}
                )
                return None
                
        except Exception as e:
            self._log_operation(
                doctor_id=doctor.doctor_id if doctor else 0,
                action='login',
                success=False,
                details={'error': str(e), 'username': username}
            )
            return None
    
    def logout_doctor(self, doctor_id: int) -> bool:
        """
        Выход врача из системы
        
        Args:
            doctor_id: ID врача
            
        Returns:
            bool: True если выход успешен
        """
        if doctor_id not in self._doctors:
            return False
        
        try:
            # Выход из системы безопасности
            success = self.security_system.logout_doctor(doctor_id)
            
            if success:
                # Обновляем информацию о враче
                doctor = self._doctors[doctor_id]
                doctor.is_authenticated = False
                self._doctors[doctor_id] = doctor
                
                # Очищаем кэш сессий этого врача
                self._cleanup_doctor_sessions(doctor_id)
                
                self._log_operation(
                    doctor_id=doctor_id,
                    action='logout',
                    success=True
                )
            
            return success
            
        except Exception as e:
            self._log_operation(
                doctor_id=doctor_id,
                action='logout',
                success=False,
                details={'error': str(e)}
            )
            return False
    
    def get_doctor(self, doctor_id: int) -> Optional[DoctorInfo]:
        """
        Получение информации о враче
        
        Args:
            doctor_id: ID врача
            
        Returns:
            Optional[DoctorInfo]: Информация о враче или None если не найден
        """
        return self._doctors.get(doctor_id)
    
    # ==================== УПРАВЛЕНИЕ ПАЦИЕНТАМИ ====================
    
    def add_patient(self, doctor_id: int, full_name: str, 
                   **patient_data) -> PatientInfo:
        """
        Добавление нового пациента
        
        Args:
            doctor_id: ID врача
            full_name: Полное имя пациента
            **patient_data: Дополнительные данные пациента
            
        Returns:
            PatientInfo: Информация о добавленном пациенте
            
        Raises:
            CryptoError: Если врач не аутентифицирован
        """
        # Проверяем что врач аутентифицирован
        doctor = self.get_doctor(doctor_id)
        if not doctor or not doctor.is_authenticated:
            raise CryptoError(f"Врач {doctor_id} не аутентифицирован")
        
        try:
            # Генерируем уникальный ID пациента
            patient_id = max(self._patients.keys(), default=0) + 1
            
            # Настраиваем безопасность для пациента
            self.security_system.setup_patient(doctor_id, patient_id)
            
            # Создаем информацию о пациенте
            patient = PatientInfo(
                patient_id=patient_id,
                doctor_id=doctor_id,
                full_name=full_name,
                has_encryption_key=True,
                key_created=datetime.now(),
                last_accessed=datetime.now()
            )
            
            # Сохраняем
            self._patients[patient_id] = patient
            
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='add_patient',
                success=True,
                details={'full_name': full_name, **patient_data}
            )
            
            return patient
            
        except Exception as e:
            self._log_operation(
                doctor_id=doctor_id,
                action='add_patient',
                success=False,
                details={'error': str(e), 'full_name': full_name}
            )
            raise CryptoError(f"Ошибка добавления пациента: {str(e)}")
    
    def get_patient(self, doctor_id: int, patient_id: int) -> Optional[PatientInfo]:
        """
        Получение информации о пациенте с проверкой прав доступа
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            Optional[PatientInfo]: Информация о пациенте или None если нет доступа
        """
        # Проверяем что пациент существует
        if patient_id not in self._patients:
            return None
        
        patient = self._patients[patient_id]
        
        # Проверяем что пациент принадлежит врачу
        if patient.doctor_id != doctor_id:
            return None
        
        # Обновляем время последнего доступа
        patient.last_accessed = datetime.now()
        self._patients[patient_id] = patient
        
        return patient
    
    def get_doctor_patients(self, doctor_id: int) -> List[PatientInfo]:
        """
        Получение списка пациентов врача
        
        Args:
            doctor_id: ID врача
            
        Returns:
            List[PatientInfo]: Список пациентов врача
        """
        return [
            patient for patient in self._patients.values() 
            if patient.doctor_id == doctor_id
        ]
    
    # ==================== РАБОТА С МЕДИЦИНСКИМИ ДАННЫМИ ====================
    
    def add_medical_record(self, doctor_id: int, patient_id: int, 
                          record_type: str, plaintext_content: str,
                          tags: Optional[List[str]] = None,
                          metadata: Optional[Dict[str, Any]] = None) -> EncryptionResult:
        """
        Добавление медицинской записи с автоматическим шифрованием
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            record_type: Тип записи ('diagnosis', 'examination', etc)
            plaintext_content: Содержимое записи (открытый текст)
            tags: Теги для поиска
            metadata: Дополнительные метаданные
            
        Returns:
            EncryptionResult: Результат операции шифрования
        """
        # Проверяем права доступа
        patient = self.get_patient(doctor_id, patient_id)
        if not patient:
            return EncryptionResult(
                success=False,
                error_message=f"Пациент {patient_id} не найден или нет доступа"
            )
        
        try:
            # Подготавливаем дополнительные данные для шифрования
            additional_data = {
                'record_type': record_type,
                'doctor_id': doctor_id,
                'patient_id': patient_id,
                'timestamp': datetime.now().isoformat(),
                'tags': tags or [],
                'metadata': metadata or {}
            }
            
            # Шифруем данные
            encrypted_content = self.security_system.encrypt_patient_data(
                doctor_id=doctor_id,
                patient_id=patient_id,
                plaintext=plaintext_content,
                additional_data=additional_data
            )
            
            # Создаем ID записи
            record_id = self._next_record_id
            self._next_record_id += 1
            
            # Создаем объект записи
            record = MedicalRecord(
                record_id=record_id,
                patient_id=patient_id,
                record_type=record_type,
                encrypted_content=encrypted_content,
                created_at=datetime.now(),
                tags=tags or [],
                metadata=metadata or {}
            )
            
            # Сохраняем
            self._medical_records[record_id] = record
            
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='add_medical_record',
                success=True,
                details={
                    'record_type': record_type,
                    'content_length': len(plaintext_content),
                    'record_id': record_id
                }
            )
            
            return EncryptionResult(
                success=True,
                encrypted_data=encrypted_content,
                record_id=record_id,
                timestamp=datetime.now()
            )
            
        except CryptoError as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='add_medical_record',
                success=False,
                details={'error': str(e), 'record_type': record_type}
            )
            
            return EncryptionResult(
                success=False,
                error_message=f"Ошибка шифрования: {str(e)}"
            )
        
        except Exception as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='add_medical_record',
                success=False,
                details={'error': str(e), 'record_type': record_type}
            )
            
            return EncryptionResult(
                success=False,
                error_message=f"Неизвестная ошибка: {str(e)}"
            )
    
    def get_medical_record(self, doctor_id: int, record_id: int) -> Optional[MedicalRecord]:
        """
        Получение медицинской записи (без дешифрования)
        
        Args:
            doctor_id: ID врача
            record_id: ID записи
            
        Returns:
            Optional[MedicalRecord]: Медицинская запись или None если нет доступа
        """
        if record_id not in self._medical_records:
            return None
        
        record = self._medical_records[record_id]
        
        # Проверяем права доступа через пациента
        patient = self.get_patient(doctor_id, record.patient_id)
        if not patient:
            return None
        
        return record
    
    def decrypt_medical_record(self, doctor_id: int, record_id: int) -> DecryptionResult:
        """
        Дешифрование медицинской записи
        
        Args:
            doctor_id: ID врача
            record_id: ID записи
            
        Returns:
            DecryptionResult: Результат дешифрования
        """
        # Получаем запись
        record = self.get_medical_record(doctor_id, record_id)
        if not record:
            return DecryptionResult(
                success=False,
                error_message=f"Запись {record_id} не найдена или нет доступа"
            )
        
        try:
            # Дешифруем содержимое
            plaintext = self.security_system.decrypt_patient_data(
                doctor_id=doctor_id,
                patient_id=record.patient_id,
                encrypted_json=record.encrypted_content
            )
            
            # Извлекаем метаданные из зашифрованных данных
            metadata = {}
            try:
                # Пытаемся получить дополнительные данные
                encrypted_data = json.loads(record.encrypted_content)
                if 'additional_data' in encrypted_data:
                    import base64
                    aad = base64.b64decode(encrypted_data['additional_data'])
                    metadata = json.loads(aad.decode('utf-8'))
            except:
                pass  # Метаданные не обязательны
            
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=record.patient_id,
                action='decrypt_medical_record',
                success=True,
                details={'record_id': record_id, 'record_type': record.record_type}
            )
            
            return DecryptionResult(
                success=True,
                plaintext=plaintext,
                metadata=metadata,
                timestamp=datetime.now()
            )
            
        except AccessDeniedError as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=record.patient_id,
                action='decrypt_medical_record',
                success=False,
                details={'error': str(e), 'record_id': record_id}
            )
            
            return DecryptionResult(
                success=False,
                error_message=f"Доступ запрещен: {str(e)}"
            )
        
        except CryptoError as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=record.patient_id,
                action='decrypt_medical_record',
                success=False,
                details={'error': str(e), 'record_id': record_id}
            )
            
            return DecryptionResult(
                success=False,
                error_message=f"Ошибка дешифрования: {str(e)}"
            )
        
        except Exception as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=record.patient_id,
                action='decrypt_medical_record',
                success=False,
                details={'error': str(e), 'record_id': record_id}
            )
            
            return DecryptionResult(
                success=False,
                error_message=f"Неизвестная ошибка: {str(e)}"
            )
    
    def get_patient_records(self, doctor_id: int, patient_id: int) -> List[MedicalRecord]:
        """
        Получение всех медицинских записей пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            
        Returns:
            List[MedicalRecord]: Список медицинских записей
        """
        # Проверяем права доступа
        patient = self.get_patient(doctor_id, patient_id)
        if not patient:
            return []
        
        # Возвращаем все записи пациента
        return [
            record for record in self._medical_records.values()
            if record.patient_id == patient_id
        ]
    
    # ==================== УПРАВЛЕНИЕ СЕССИЯМИ ====================
    
    def create_session(self, doctor_id: int, patient_id: int,
                      access_type: str = 'view') -> Optional[SessionInfo]:
        """
        Создание сессии доступа
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            access_type: Тип доступа ('view', 'edit', 'emergency')
            
        Returns:
            Optional[SessionInfo]: Информация о сессии или None если ошибка
        """
        # Проверяем права доступа
        patient = self.get_patient(doctor_id, patient_id)
        if not patient:
            return None
        
        try:
            # Создаем сессию в системе безопасности
            session = self.security_system.create_access_session(
                doctor_id=doctor_id,
                patient_id=patient_id,
                access_type=access_type
            )
            
            # Создаем информацию о сессии для UI
            session_info = SessionInfo(
                session_id=session.session_id,
                doctor_id=session.doctor_id,
                patient_id=session.patient_id,
                access_type=session.access_type,
                permissions=session.permissions,
                created_at=session.created_at,
                expires_at=session.expires_at,
                is_active=session.is_active
            )
            
            # Сохраняем в кэш
            self._sessions_cache[session.session_id] = session_info
            
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='create_session',
                success=True,
                details={'access_type': access_type, 'session_id': session.session_id}
            )
            
            return session_info
            
        except Exception as e:
            self._log_operation(
                doctor_id=doctor_id,
                patient_id=patient_id,
                action='create_session',
                success=False,
                details={'error': str(e), 'access_type': access_type}
            )
            return None
    
    def validate_session(self, session_id: str) -> bool:
        """
        Проверка валидности сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия валидна
        """
        # Проверяем в системе безопасности
        is_valid = self.security_system.validate_access_session(session_id)
        
        # Обновляем кэш если сессия невалидна
        if not is_valid and session_id in self._sessions_cache:
            del self._sessions_cache[session_id]
        
        return is_valid
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Получение информации о сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            Optional[SessionInfo]: Информация о сессии или None если не найдена
        """
        # Пытаемся получить из кэша
        if session_id in self._sessions_cache:
            session_info = self._sessions_cache[session_id]
            
            # Проверяем что сессия все еще валидна
            if self.validate_session(session_id):
                return session_info
            else:
                # Удаляем из кэша если невалидна
                del self._sessions_cache[session_id]
        
        return None
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Отзыв сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия была отозвана
        """
        # Получаем информацию о сессии
        session_info = self.get_session(session_id)
        if not session_info:
            return False
        
        try:
            # Отзываем в системе безопасности
            success = self.security_system.revoke_session(session_id)
            
            if success:
                # Удаляем из кэша
                if session_id in self._sessions_cache:
                    del self._sessions_cache[session_id]
                
                self._log_operation(
                    doctor_id=session_info.doctor_id,
                    patient_id=session_info.patient_id,
                    action='revoke_session',
                    success=True,
                    details={'session_id': session_id}
                )
            
            return success
            
        except Exception as e:
            self._log_operation(
                doctor_id=session_info.doctor_id,
                patient_id=session_info.patient_id,
                action='revoke_session',
                success=False,
                details={'error': str(e), 'session_id': session_id}
            )
            return False
    
    # ==================== УТИЛИТЫ И СТАТИСТИКА ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики системы
        
        Returns:
            Dict: Статистика
        """
        # Получаем статистику из системы безопасности
        security_stats = self.security_system.get_statistics()
        
        return {
            'doctors_count': len(self._doctors),
            'patients_count': len(self._patients),
            'medical_records_count': len(self._medical_records),
            'active_sessions': len(self._sessions_cache),
            'security_system': security_stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_access_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Получение логов доступа
        
        Args:
            limit: Максимальное количество записей
            
        Returns:
            List[Dict]: Логи доступа
        """
        return self.security_system.get_access_logs(limit=limit)
    
    def export_data(self, doctor_id: int, format: str = 'json') -> str:
        """
        Экспорт данных врача (для бекапа)
        
        Args:
            doctor_id: ID врача
            format: Формат экспорта ('json')
            
        Returns:
            str: Экспортированные данные
            
        Note:
            Экспортируются только метаданные, зашифрованные данные остаются зашифрованными
        """
        if format != 'json':
            raise ValueError(f"Неподдерживаемый формат: {format}")
        
        # Получаем данные врача
        doctor = self.get_doctor(doctor_id)
        if not doctor:
            raise ValueError(f"Врач {doctor_id} не найден")
        
        # Получаем пациентов врача
        patients = self.get_doctor_patients(doctor_id)
        
        # Получаем записи пациентов
        all_records = []
        for patient in patients:
            records = self.get_patient_records(doctor_id, patient.patient_id)
            all_records.extend(records)
        
        # Формируем данные для экспорта
        export_data = {
            'doctor': {
                'doctor_id': doctor.doctor_id,
                'username': doctor.username,
                'full_name': doctor.full_name,
                'last_login': doctor.last_login.isoformat() if doctor.last_login else None
            },
            'patients': [
                {
                    'patient_id': p.patient_id,
                    'full_name': p.full_name,
                    'has_encryption_key': p.has_encryption_key,
                    'key_created': p.key_created.isoformat() if p.key_created else None,
                    'last_accessed': p.last_accessed.isoformat() if p.last_accessed else None
                }
                for p in patients
            ],
            'medical_records': [
                {
                    'record_id': r.record_id,
                    'patient_id': r.patient_id,
                    'record_type': r.record_type,
                    'encrypted_content': r.encrypted_content,  # Остается зашифрованной!
                    'created_at': r.created_at.isoformat(),
                    'tags': r.tags,
                    'metadata': r.metadata
                }
                for r in all_records
            ],
            'export_timestamp': datetime.now().isoformat(),
            'export_format': format,
            'note': 'Зашифрованные данные остаются зашифрованными. Для чтения нужны ключи.'
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False, default=str)
    
    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================
    
    def _log_operation(self, doctor_id: int, action: str, success: bool,
                      patient_id: Optional[int] = None,
                      details: Optional[Dict[str, Any]] = None):
        """Внутреннее логирование операций"""
        # Используем систему безопасности для логирования
        self.security_system.access_manager.log_access(
            doctor_id=doctor_id,
            patient_id=patient_id or 0,
            action=action,
            success=success,
            details=details
        )
    
    def _dummy_login_check(self):
        """Фиктивная проверка для защиты от timing-атак"""
        import hashlib
        dummy_password = b"dummy_password_for_timing_protection"
        hashlib.sha256(dummy_password).hexdigest()
    
    def _cleanup_doctor_sessions(self, doctor_id: int):
        """Очистка сессий врача из кэша"""
        sessions_to_remove = []
        for session_id, session in self._sessions_cache.items():
            if session.doctor_id == doctor_id:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self._sessions_cache[session_id]
    
    def clear_all_data(self):
        """Очистка всех данных (только для тестирования!)"""
        self._doctors.clear()
        self._patients.clear()
        self._medical_records.clear()
        self._sessions_cache.clear()
        self._next_record_id = 1
        self.security_system.clear_cache()


# Синглтон для удобного доступа
_crypto_facade_instance = None

def get_crypto_facade(config: Optional[SecurityConfig] = None) -> MedicalCryptoFacade:
    """
    Получение экземпляра фасада криптосистемы
    
    Args:
        config: Конфигурация безопасности
        
    Returns:
        MedicalCryptoFacade: Экземпляр фасада
    """
    global _crypto_facade_instance
    if _crypto_facade_instance is None:
        _crypto_facade_instance = MedicalCryptoFacade(config)
    return _crypto_facade_instance


if __name__ == "__main__":
    # Демонстрация работы фасада
    print("🧪 Демонстрация MedicalCryptoFacade")
    print("=" * 60)
    
    # Создаем фасад
    crypto = MedicalCryptoFacade()
    
    try:
        # 1. Регистрация врача
        print("1. Регистрация врача...")
        doctor = crypto.register_doctor(
            username="dr_ivanov",
            password="SecurePass123",
            full_name="Иванов Иван Иванович"
        )
        print(f"   ✅ Врач зарегистрирован: {doctor.full_name} (ID: {doctor.doctor_id})")
        
        # 2. Вход врача
        print("2. Вход врача...")
        logged_in_doctor = crypto.login_doctor("dr_ivanov", "SecurePass123")
        if logged_in_doctor and logged_in_doctor.is_authenticated:
            print(f"   ✅ Врач аутентифицирован: {logged_in_doctor.full_name}")
        else:
            print("   ❌ Ошибка аутентификации")
            exit(1)
        
        # 3. Добавление пациента
        print("3. Добавление пациента...")
        patient = crypto.add_patient(
            doctor_id=doctor.doctor_id,
            full_name="Петров Петр Петрович",
            birth_date="1980-05-15",
            gender="M"
        )
        print(f"   ✅ Пациент добавлен: {patient.full_name} (ID: {patient.patient_id})")
        
        # 4. Добавление медицинской записи
        print("4. Добавление медицинской записи...")
        medical_text = """Диагноз: Эссенциальная гипертензия II стадии.
        Жалобы: головные боли, головокружение.
        АД: 150/95 мм рт.ст., пульс: 85 уд/мин.
        Назначения: Лизиноприл 10мг 1 раз в день."""
        
        result = crypto.add_medical_record(
            doctor_id=doctor.doctor_id,
            patient_id=patient.patient_id,
            record_type="diagnosis",
            plaintext_content=medical_text,
            tags=["гипертензия", "кардиология"],
            metadata={"urgency": "normal", "follow_up": "1 month"}
        )
        
        if result.success:
            print(f"   ✅ Запись добавлена (ID: {result.record_id})")
            print(f"   📊 Зашифрованные данные: {len(result.encrypted_data)} байт")
        else:
            print(f"   ❌ Ошибка: {result.error_message}")
        
        # 5. Получение и дешифрование записи
        print("5. Дешифрование медицинской записи...")
        decryption_result = crypto.decrypt_medical_record(
            doctor_id=doctor.doctor_id,
            record_id=result.record_id
        )
        
        if decryption_result.success:
            print(f"   ✅ Данные расшифрованы успешно")
            print(f"   📝 Тип записи: {decryption_result.metadata.get('record_type', 'unknown')}")
            print(f"   📝 Первые 100 символов: {decryption_result.plaintext[:100]}...")
        else:
            print(f"   ❌ Ошибка дешифрования: {decryption_result.error_message}")
        
        # 6. Создание сессии доступа
        print("6. Создание сессии доступа...")
        session = crypto.create_session(
            doctor_id=doctor.doctor_id,
            patient_id=patient.patient_id,
            access_type="view"
        )
        
        if session:
            print(f"   ✅ Сессия создана: {session.session_id}")
            print(f"   🔐 Права доступа: {list(session.permissions.keys())}")
        else:
            print("   ❌ Ошибка создания сессии")
        
        # 7. Статистика системы
        print("7. Статистика системы...")
        stats = crypto.get_statistics()
        print(f"   👥 Врачей: {stats['doctors_count']}")
        print(f"   👤 Пациентов: {stats['patients_count']}")
        print(f"   📝 Записей: {stats['medical_records_count']}")
        print(f"   🔐 Активных сессий: {stats['active_sessions']}")
        
        # 8. Экспорт данных
        print("8. Экспорт данных врача...")
        export_data = crypto.export_data(doctor.doctor_id)
        print(f"   📁 Экспортировано {len(export_data)} байт")
        
        # 9. Логи доступа
        print("9. Последние операции...")
        logs = crypto.get_access_logs(limit=5)
        for log in logs:
            print(f"   📋 {log['action']}: {'✅' if log['success'] else '❌'}")
        
        print("\n" + "=" * 60)
        print("🎉 Фасад криптосистемы работает корректно!")
        print("=" * 60)
        print("\n📚 Доступные методы API:")
        print("  - register_doctor() - регистрация врача")
        print("  - login_doctor() - аутентификация врача")
        print("  - add_patient() - добавление пациента")
        print("  - add_medical_record() - добавление записи с шифрованием")
        print("  - decrypt_medical_record() - чтение записи с дешифрованием")
        print("  - create_session() - создание сессии доступа")
        print("  - get_statistics() - получение статистики")
        print("  - export_data() - экспорт данных")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()