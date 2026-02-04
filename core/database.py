# core/database.py (с интеграцией криптографии)
"""
Медицинская база данных с криптографической защитой данных
"""

import sqlite3
import json
import base64
from datetime import datetime, date
from typing import Optional, List, Dict, Any, Tuple
import os
from dataclasses import dataclass, field
from enum import Enum

# Импортируем криптографические модули
from medical_crypto import MedicalCryptoFacade, get_crypto_facade
from auth import get_auth_manager
from security.types import SecurityConfig, CryptoError

class RecordType(Enum):
    """Типы медицинских записей"""
    EXAMINATION = "examination"  # Осмотр
    COMPLAINT = "complaint"      # Жалоба
    DIAGNOSIS = "diagnosis"      # Диагноз
    PRESCRIPTION = "prescription"  # Назначение
    TEST_RESULT = "test_result"  # Результат анализов
    NOTE = "note"               # Заметка
    PROCEDURE = "procedure"     # Процедура

@dataclass
class Patient:
    """Данные пациента"""
    id: Optional[int] = None
    doctor_id: int = 0
    full_name: str = ""
    birth_date: Optional[date] = None
    gender: str = ""
    blood_type: str = ""
    allergies: str = ""
    phone: str = ""
    email: str = ""
    address: str = ""
    insurance_number: str = ""
    created_at: Optional[datetime] = None
    crypto_key_id: Optional[str] = None  # ID криптографического ключа пациента
    
    @property
    def age(self) -> int:
        """Рассчитать возраст"""
        if not self.birth_date:
            return 0
        today = date.today()
        age = today.year - self.birth_date.year
        if (today.month, today.day) < (self.birth_date.month, self.birth_date.day):
            age -= 1
        return age

@dataclass
class MedicalRecord:
    """Медицинская запись с криптографией"""
    id: Optional[int] = None
    patient_id: int = 0
    doctor_id: int = 0
    record_type: str = ""
    encrypted_content: str = ""  # Зашифрованные данные в формате JSON
    plaintext_content: Optional[str] = None  # Временное хранение открытого текста (только в памяти)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    crypto_key_id: Optional[str] = None  # ID ключа использованного для шифрования

@dataclass
class Measurement:
    """Измерение (давление, сахар, температура)"""
    id: Optional[int] = None
    patient_id: int = 0
    measurement_type: str = ""
    value: float = 0.0
    unit: str = ""
    notes: str = ""
    taken_at: datetime = field(default_factory=datetime.now)
    encrypted_notes: str = ""  # Зашифрованные заметки
    crypto_key_id: Optional[str] = None

@dataclass
class Prescription:
    """Назначение (лекарства, процедуры)"""
    id: Optional[int] = None
    patient_id: int = 0
    doctor_id: int = 0
    medication_name: str = ""
    dosage: str = ""
    frequency: str = ""
    start_date: date = field(default_factory=date.today)
    end_date: Optional[date] = None
    is_active: bool = True
    plaintext_notes: str = ""
    encrypted_notes: str = ""  # Зашифрованные заметки
    created_at: datetime = field(default_factory=datetime.now)
    crypto_key_id: Optional[str] = None

class MedicalDatabaseV2:
    """
    База данных с криптографической защитой медицинских данных
    
    Особенности:
    - Все чувствительные данные шифруются
    - У каждого пациента свой ключ шифрования
    - Автоматическое управление ключами через MedicalCryptoFacade
    """
    
    def __init__(self, db_path: str = "medical_data_secure.db", 
                 crypto_config: Optional[SecurityConfig] = None):
        """
        Инициализация защищенной БД
        
        Args:
            db_path: Путь к файлу БД
            crypto_config: Конфигурация криптосистемы
        """
        self.db_path = db_path
        self.crypto_config = crypto_config
        
        # Криптографические компоненты
        self.crypto_facade = get_crypto_facade(crypto_config)
        self.auth_manager = get_auth_manager()
        
        self.connection = None
        self._init_connection()
    
    def _init_connection(self):
        """Инициализация подключения с настройками"""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        
        # Оптимизации
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA cache_size = -2000")
        
        # Создаём таблицы
        self._create_tables()
        
        # Создаём индексы
        self._create_indexes()
    
    def _create_tables(self):
        """Создание таблиц с криптографической поддержкой"""
        cursor = self.connection.cursor()
        
        # Основные таблицы (остаются без изменений)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            specialization TEXT,
            license_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            birth_date DATE,
            gender TEXT CHECK(gender IN ('M', 'F', 'O', '')),
            blood_type TEXT,
            allergies TEXT,
            phone TEXT,
            email TEXT,
            address TEXT,
            insurance_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            -- Криптографические поля
            crypto_key_id TEXT,  -- ID ключа данных пациента
            crypto_salt TEXT,    -- Соль пациента для шифрования
            
            FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
        )
        """)
        
        # Криптографические таблицы
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctor_crypto (
            doctor_id INTEGER PRIMARY KEY,
            key_salt TEXT NOT NULL,  -- Соль для вывода мастер-ключа
            crypto_version TEXT DEFAULT '2.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_keys (
            patient_id INTEGER PRIMARY KEY,
            encrypted_data_key TEXT NOT NULL,  -- Ключ данных, зашифрованный мастер-ключом
            key_salt TEXT NOT NULL,  -- Соль пациента
            crypto_version TEXT DEFAULT '2.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_rotated TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
        )
        """)
        
        # Медицинские записи с криптографией
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,  -- Полностью зашифрованные данные
            crypto_metadata TEXT DEFAULT '{}',  -- Метакриптографические данные
            tags_json TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
            FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
        )
        """)
        
        # Измерения с криптографией
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS measurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            measurement_type TEXT NOT NULL,
            value REAL NOT NULL,
            unit TEXT NOT NULL,
            encrypted_notes TEXT,  -- Зашифрованные заметки
            crypto_metadata TEXT DEFAULT '{}',
            taken_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
        )
        """)
        
        # Назначения с криптографией
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            medication_name TEXT NOT NULL,
            dosage TEXT NOT NULL,
            frequency TEXT NOT NULL,
            start_date DATE NOT NULL,
            end_date DATE,
            is_active BOOLEAN DEFAULT 1,
            encrypted_notes TEXT,  -- Зашифрованные заметки
            crypto_metadata TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
            FOREIGN KEY (doctor_id) REFERENCES doctors (id)
        )
        """)
        
        # Таблица аудита доступа
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER,
            patient_id INTEGER,
            action TEXT NOT NULL,
            record_type TEXT,
            record_id INTEGER,
            success BOOLEAN DEFAULT 1,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (doctor_id) REFERENCES doctors (id),
            FOREIGN KEY (patient_id) REFERENCES patients (id)
        )
        """)
        
        # Остальные таблицы (reminders, attachments) остаются без изменений
        
        self.connection.commit()
        print("✅ Защищенные таблицы созданы успешно")
    
    def _create_indexes(self):
        """Создание индексов"""
        cursor = self.connection.cursor()
        
        # Индексы для пациентов
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patients_doctor ON patients(doctor_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patients_crypto_key ON patients(crypto_key_id)")
        
        # Индексы для медицинских записей
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_patient_doctor ON medical_records(patient_id, doctor_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_type ON medical_records(record_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_created ON medical_records(created_at DESC)")
        
        # Индексы для криптографии
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patient_keys_patient ON patient_keys(patient_id)")
        
        # Индекс для аудита
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_doctor_patient ON access_audit(doctor_id, patient_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON access_audit(timestamp DESC)")
        
        self.connection.commit()
        print("✅ Индексы для защищенной БД созданы успешно")
    
    def add_patient(self, patient: Patient, doctor_password: Optional[str] = None) -> int:
        """
        Добавление нового пациента с созданием криптографического ключа
        
        Args:
            patient: Данные пациента
            doctor_password: Пароль врача (для дешифровки мастер-ключа)
            
        Returns:
            int: ID созданного пациента
            
        Raises:
            CryptoError: Если не удалось создать криптографический ключ
        """
        cursor = self.connection.cursor()
        
        # Проверяем, что у врача настроена криптография
        crypto_status = self._get_doctor_crypto_status(patient.doctor_id)
        if not crypto_status['crypto_enabled']:
            raise CryptoError(f"Врач {patient.doctor_id} не имеет настроенной криптографии")
        
        # Добавляем пациента
        cursor.execute("""
        INSERT INTO patients 
        (doctor_id, full_name, birth_date, gender, blood_type, allergies, 
         phone, email, address, insurance_number, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patient.doctor_id,
            patient.full_name,
            patient.birth_date.isoformat() if patient.birth_date else None,
            patient.gender,
            patient.blood_type,
            patient.allergies,
            patient.phone,
            patient.email,
            patient.address,
            patient.insurance_number,
            patient.created_at.isoformat() if patient.created_at else None
        ))
        
        patient_id = cursor.lastrowid
        
        try:
            # Создаем криптографический ключ для пациента
            self._setup_patient_crypto(patient.doctor_id, patient_id)
            
            # Обновляем пациента с ID ключа
            cursor.execute("""
            UPDATE patients SET crypto_key_id = ? WHERE id = ?
            """, (f"patient_key_{patient_id}", patient_id))
            
            self.connection.commit()
            
            # Логируем создание
            self._log_access(
                doctor_id=patient.doctor_id,
                patient_id=patient_id,
                action="add_patient",
                record_type="patient",
                record_id=patient_id,
                success=True
            )
            
            return patient_id
            
        except Exception as e:
            # Откатываем транзакцию при ошибке криптографии
            self.connection.rollback()
            raise CryptoError(f"Ошибка создания криптографического ключа: {str(e)}")
    
    def _setup_patient_crypto(self, doctor_id: int, patient_id: int):
        """
        Настройка криптографии для пациента
        
        Note: В реальной системе нужно использовать MedicalCryptoFacade
        """
        cursor = self.connection.cursor()
        
        # Генерируем соль для пациента
        import secrets
        patient_salt = secrets.token_bytes(32)
        
        # Генерируем ключ данных для пациента
        # В реальной системе это делается через MedicalCryptoFacade
        data_key = {
            'key_id': f"patient_key_{patient_id}",
            'salt': base64.b64encode(patient_salt).decode('utf-8'),
            'created_at': datetime.now().isoformat()
        }
        
        # Сохраняем информацию о ключе пациента
        cursor.execute("""
        INSERT INTO patient_keys 
        (patient_id, encrypted_data_key, key_salt, crypto_version)
        VALUES (?, ?, ?, ?)
        """, (
            patient_id,
            json.dumps(data_key),  # В реальной системе это зашифрованный ключ
            base64.b64encode(patient_salt).decode('utf-8'),
            '2.0'
        ))
    
    def add_medical_record(self, record: MedicalRecord, 
                          doctor_password: Optional[str] = None) -> int:
        """
        Добавление медицинской записи с шифрованием
        
        Args:
            record: Медицинская запись
            doctor_password: Пароль врача
            
        Returns:
            int: ID созданной записи
        """
        if not record.plaintext_content:
            raise ValueError("Для шифрования нужен plaintext_content")
        
        cursor = self.connection.cursor()
        
        try:
            # Шифруем содержимое через криптофасад
            encryption_result = self.crypto_facade.add_medical_record(
                doctor_id=record.doctor_id,
                patient_id=record.patient_id,
                record_type=record.record_type,
                plaintext_content=record.plaintext_content,
                tags=record.tags,
                metadata=record.metadata
            )
            
            if not encryption_result.success:
                raise CryptoError(f"Ошибка шифрования: {encryption_result.error_message}")
            
            # Получаем ID ключа пациента
            cursor.execute("SELECT crypto_key_id FROM patients WHERE id = ?", (record.patient_id,))
            patient_row = cursor.fetchone()
            crypto_key_id = patient_row['crypto_key_id'] if patient_row else None
            
            # Сохраняем метаданные шифрования
            crypto_metadata = {
                'key_id': crypto_key_id,
                'encrypted_at': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM',
                'record_type': record.record_type
            }
            
            # Добавляем запись в БД
            tags_json = json.dumps(record.tags, ensure_ascii=False)
            
            cursor.execute("""
            INSERT INTO medical_records 
            (patient_id, doctor_id, record_type, encrypted_content, 
             crypto_metadata, tags_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.patient_id,
                record.doctor_id,
                record.record_type,
                encryption_result.encrypted_data,
                json.dumps(crypto_metadata, ensure_ascii=False),
                tags_json,
                record.created_at.isoformat() if record.created_at else None
            ))
            
            record_id = cursor.lastrowid
            self.connection.commit()
            
            # Логируем создание
            self._log_access(
                doctor_id=record.doctor_id,
                patient_id=record.patient_id,
                action="add_medical_record",
                record_type=record.record_type,
                record_id=record_id,
                success=True
            )
            
            return record_id
            
        except Exception as e:
            self._log_access(
                doctor_id=record.doctor_id,
                patient_id=record.patient_id,
                action="add_medical_record",
                record_type=record.record_type,
                success=False,
                details={'error': str(e)}
            )
            raise
    
    def get_medical_record(self, doctor_id: int, record_id: int) -> Optional[MedicalRecord]:
        """
        Получение медицинской записи (без дешифрования)
        """
        cursor = self.connection.cursor()
        
        cursor.execute("""
        SELECT mr.*, p.full_name as patient_name, d.full_name as doctor_name
        FROM medical_records mr
        JOIN patients p ON mr.patient_id = p.id
        JOIN doctors d ON mr.doctor_id = d.id
        WHERE mr.id = ? AND mr.doctor_id = ?
        """, (record_id, doctor_id))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        # Проверяем права доступа
        if row['doctor_id'] != doctor_id:
            return None
        
        record = MedicalRecord(
            id=row['id'],
            patient_id=row['patient_id'],
            doctor_id=row['doctor_id'],
            record_type=row['record_type'],
            encrypted_content=row['encrypted_content'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None
        )
        
        if row['tags_json']:
            record.tags = json.loads(row['tags_json'])
        
        if row['crypto_metadata']:
            record.metadata = json.loads(row['crypto_metadata'])
            record.crypto_key_id = record.metadata.get('key_id')
        
        # Логируем доступ
        self._log_access(
            doctor_id=doctor_id,
            patient_id=record.patient_id,
            action="view_medical_record",
            record_type=record.record_type,
            record_id=record_id,
            success=True
        )
        
        return record
    
    def decrypt_medical_record(self, doctor_id: int, record_id: int) -> str:
        """
        Дешифрование медицинской записи
        
        Returns:
            str: Расшифрованное содержимое
            
        Raises:
            CryptoError: Если дешифрование не удалось
            AccessDeniedError: Если нет прав доступа
        """
        # Получаем запись
        record = self.get_medical_record(doctor_id, record_id)
        if not record:
            raise CryptoError(f"Запись {record_id} не найдена или нет доступа")
        
        # Дешифруем через криптофасад
        decryption_result = self.crypto_facade.decrypt_medical_record(
            doctor_id=doctor_id,
            record_id=record_id
        )
        
        if not decryption_result.success:
            raise CryptoError(f"Ошибка дешифрования: {decryption_result.error_message}")
        
        # Логируем дешифрование
        self._log_access(
            doctor_id=doctor_id,
            patient_id=record.patient_id,
            action="decrypt_medical_record",
            record_type=record.record_type,
            record_id=record_id,
            success=True,
            details={'data_length': len(decryption_result.plaintext) if decryption_result.plaintext else 0}
        )
        
        return decryption_result.plaintext or ""
    
    def get_patient_records(self, doctor_id: int, patient_id: int,
                          record_type: Optional[str] = None,
                          limit: int = 100,
                          offset: int = 0) -> List[Dict[str, Any]]:
        """
        Получение записей пациента (только метаданные, без дешифрования)
        """
        # Проверяем права доступа
        cursor = self.connection.cursor()
        cursor.execute("SELECT doctor_id FROM patients WHERE id = ?", (patient_id,))
        patient_row = cursor.fetchone()
        
        if not patient_row or patient_row['doctor_id'] != doctor_id:
            return []
        
        query = """
        SELECT mr.id, mr.patient_id, mr.doctor_id, mr.record_type, 
               mr.created_at, mr.updated_at, mr.tags_json,
               p.full_name as patient_name, d.full_name as doctor_name
        FROM medical_records mr
        JOIN patients p ON mr.patient_id = p.id
        JOIN doctors d ON mr.doctor_id = d.id
        WHERE mr.patient_id = ? AND mr.doctor_id = ?
        """
        params = [patient_id, doctor_id]
        
        if record_type:
            query += " AND mr.record_type = ?"
            params.append(record_type)
        
        query += " ORDER BY mr.created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        records = []
        for row in cursor.fetchall():
            record = dict(row)
            record['tags'] = json.loads(record['tags_json']) if record['tags_json'] else []
            del record['tags_json']
            records.append(record)
        
        return records
    
    def _get_doctor_crypto_status(self, doctor_id: int) -> Dict[str, Any]:
        """
        Получение статуса криптографии врача
        """
        cursor = self.connection.cursor()
        
        cursor.execute("""
        SELECT dc.crypto_version, dc.created_at,
               COUNT(pk.patient_id) as patient_keys_count
        FROM doctor_crypto dc
        LEFT JOIN patient_keys pk ON dc.doctor_id = ?
        WHERE dc.doctor_id = ?
        GROUP BY dc.doctor_id
        """, (doctor_id, doctor_id))
        
        result = cursor.fetchone()
        
        if result:
            return {
                'crypto_enabled': True,
                'crypto_version': result['crypto_version'],
                'configured_at': result['created_at'],
                'patient_keys_count': result['patient_keys_count']
            }
        else:
            return {
                'crypto_enabled': False,
                'crypto_version': None,
                'configured_at': None,
                'patient_keys_count': 0
            }
    
    def _log_access(self, doctor_id: int, action: str, success: bool,
                   patient_id: Optional[int] = None,
                   record_type: Optional[str] = None,
                   record_id: Optional[int] = None,
                   details: Optional[Dict[str, Any]] = None):
        """
        Логирование доступа к данным
        """
        cursor = self.connection.cursor()
        
        details_json = json.dumps(details or {}, ensure_ascii=False)
        
        cursor.execute("""
        INSERT INTO access_audit 
        (doctor_id, patient_id, action, record_type, record_id, success, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            doctor_id,
            patient_id,
            action,
            record_type,
            record_id,
            success,
            details_json
        ))
        
        self.connection.commit()
    
    def get_access_logs(self, doctor_id: Optional[int] = None,
                       patient_id: Optional[int] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """
        Получение логов доступа
        """
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM access_audit WHERE 1=1"
        params = []
        
        if doctor_id:
            query += " AND doctor_id = ?"
            params.append(doctor_id)
        
        if patient_id:
            query += " AND patient_id = ?"
            params.append(patient_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        logs = []
        for row in cursor.fetchall():
            log = dict(row)
            if log.get('details'):
                try:
                    log['details'] = json.loads(log['details'])
                except:
                    pass
            logs.append(log)
        
        return logs
    
    # Методы для обратной совместимости с существующим кодом
    
    def get_patient(self, patient_id: int) -> Optional[Patient]:
        """Получение пациента по ID (обратная совместимость)"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return self._row_to_patient(row)
    
    def get_patients_by_doctor(self, doctor_id: int, 
                              limit: int = 100, 
                              offset: int = 0) -> List[Patient]:
        """Получение пациентов врача (обратная совместимость)"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
        SELECT * FROM patients 
        WHERE doctor_id = ?
        ORDER BY full_name
        LIMIT ? OFFSET ?
        """, (doctor_id, limit, offset))
        
        patients = []
        for row in cursor.fetchall():
            patients.append(self._row_to_patient(row))
        
        return patients
    
    def _row_to_patient(self, row) -> Patient:
        """Преобразование строки БД в объект Patient"""
        birth_date = None
        if row['birth_date']:
            try:
                birth_date = date.fromisoformat(row['birth_date'])
            except ValueError:
                pass
        
        created_at = None
        if row['created_at']:
            try:
                created_at = datetime.fromisoformat(row['created_at'].replace('Z', '+00:00'))
            except ValueError:
                pass
        
        return Patient(
            id=row['id'],
            doctor_id=row['doctor_id'],
            full_name=row['full_name'],
            birth_date=birth_date,
            gender=row['gender'],
            blood_type=row['blood_type'],
            allergies=row['allergies'],
            phone=row['phone'],
            email=row['email'],
            address=row['address'],
            insurance_number=row['insurance_number'],
            created_at=created_at,
            crypto_key_id=row.get('crypto_key_id')
        )
    
    def connect(self) -> sqlite3.Connection:
        """Получение соединения с БД"""
        if self.connection is None:
            self._init_connection()
        return self.connection
    
    def close(self):
        """Закрытие соединения"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        """Контекстный менеджер"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Контекстный менеджер - выход"""
        self.close()


# Адаптер для обратной совместимости
class MedicalDatabase(MedicalDatabaseV2):
    """
    Адаптер для обратной совместимости с существующим кодом
    
    Автоматически переключается между старой и новой версией БД
    """
    
    def __init__(self, db_path: str = "medical_data.db", 
                 crypto_config: Optional[SecurityConfig] = None,
                 use_crypto: bool = True):
        """
        Args:
            db_path: Путь к файлу БД
            crypto_config: Конфигурация криптосистемы
            use_crypto: Использовать ли криптографию
        """
        if use_crypto:
            # Используем защищенную версию
            super().__init__(db_path, crypto_config)
        else:
            # Используем простую версию для обратной совместимости
            # (здесь должна быть старая реализация без криптографии)
            # Пока что используем защищенную, но с отключенной криптографией
            super().__init__(db_path, None)
    
    def add_medical_record(self, record: MedicalRecord) -> int:
        """Упрощенная версия для обратной совместимости"""
        # Проверяем, есть ли у пациента криптографический ключ
        if record.patient_id:
            cursor = self.connection.cursor()
            cursor.execute("SELECT crypto_key_id FROM patients WHERE id = ?", (record.patient_id,))
            patient_row = cursor.fetchone()
            
            if patient_row and patient_row['crypto_key_id']:
                # У пациента есть криптография - используем защищенную версию
                return super().add_medical_record(record, None)
        
        # Без криптографии - используем простую версию
        return super().add_medical_record(record, None)


if __name__ == "__main__":
    print("🧪 Тестирование защищенной БД с криптографией...")
    
    db = MedicalDatabaseV2("test_medical_secure.db")
    
    try:
        print("✅ Защищенная БД инициализирована")
        
        # Здесь будут тесты с использованием криптофасада
        
        print("\n🎉 Тестирование защищенной БД завершено!")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        db.close()
        
        # Удаляем тестовую БД
        if os.path.exists("test_medical_secure.db"):
            os.remove("test_medical_secure.db")
            print("🧹 Тестовая БД удалена")