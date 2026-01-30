# core/database.py (исправленная версия)
"""
Медицинская база данных с оптимизацией для врачебной практики
"""

import sqlite3
import json
from datetime import datetime, date
from typing import Optional, List, Dict, Any, Tuple
import os
from dataclasses import dataclass
from enum import Enum

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
    """Медицинская запись"""
    id: Optional[int] = None
    patient_id: int = 0
    doctor_id: int = 0
    record_type: str = ""
    encrypted_content: str = ""
    tags: List[str] = None
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

class MedicalDatabase:
    """Оптимизированная база данных для медицинских записей"""
    
    def __init__(self, db_path: str = "medical_data.db"):
        """
        Инициализация базы данных
        
        Args:
            db_path: Путь к файлу БД
        """
        self.db_path = db_path
        self.connection = None
        self._init_connection()
    
    def _init_connection(self):
        """Инициализация подключения с настройками"""
        # Создаём директорию если нет
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        
        # Включаем внешние ключи и оптимизации
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA cache_size = -2000")  # 2MB кэш
        
        # Создаём таблицы
        self._create_tables()
        
        # Создаём индексы (после таблиц!)
        self._create_indexes()
    
    def _create_tables(self):
        """Создание таблиц"""
        cursor = self.connection.cursor()
        
        # Таблица врачей
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
        
        # Таблица пациентов
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
            
            -- Внешние ключи
            FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
        )
        """)
        
        # Таблица медицинских записей
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            tags_json TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            -- Внешние ключи
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
            FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
        )
        """)
        
        # Таблица измерений (давление, сахар, температура и т.д.)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS measurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            measurement_type TEXT NOT NULL,
            value REAL NOT NULL,
            unit TEXT NOT NULL,
            notes TEXT,
            taken_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
        )
        """)
        
        # Таблица назначений (лекарства, процедуры)
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
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
            FOREIGN KEY (doctor_id) REFERENCES doctors (id)
        )
        """)
        
        # Таблица напоминаний
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            prescription_id INTEGER,
            reminder_time TIME NOT NULL,
            days_of_week TEXT DEFAULT '1111111',  -- 7 бит для дней недели
            is_active BOOLEAN DEFAULT 1,
            last_triggered TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
            FOREIGN KEY (prescription_id) REFERENCES prescriptions (id) ON DELETE SET NULL
        )
        """)
        
        # Таблица прикреплённых файлов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT,
            file_size INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (record_id) REFERENCES medical_records (id) ON DELETE CASCADE
        )
        """)
        
        self.connection.commit()
        print("✅ Таблицы созданы успешно")
    
    def _create_indexes(self):
        """Создание индексов для оптимизации запросов"""
        cursor = self.connection.cursor()
        
        # Индексы для пациентов
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patients_doctor ON patients(doctor_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(full_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_patients_birthdate ON patients(birth_date)")
        
        # Индексы для медицинских записей
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_patient_doctor ON medical_records(patient_id, doctor_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_type ON medical_records(record_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_created ON medical_records(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_patient_created ON medical_records(patient_id, created_at DESC)")
        
        # Индексы для измерений
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_measurements_patient_type ON measurements(patient_id, measurement_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_measurements_taken ON measurements(taken_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_measurements_patient_taken ON measurements(patient_id, taken_at DESC)")
        
        # Индексы для назначений
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prescriptions_patient ON prescriptions(patient_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prescriptions_active ON prescriptions(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prescriptions_dates ON prescriptions(start_date, end_date)")
        
        # Индексы для вложений
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attachments_record ON attachments(record_id)")
        
        self.connection.commit()
        print("✅ Индексы созданы успешно")
    
    def add_patient(self, patient: Patient) -> int:
        """Добавление нового пациента"""
        cursor = self.connection.cursor()
        
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
        self.connection.commit()
        return patient_id
    
    def get_patient(self, patient_id: int) -> Optional[Patient]:
        """Получение пациента по ID"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
        SELECT * FROM patients WHERE id = ?
        """, (patient_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        return self._row_to_patient(row)
    
    def get_patients_by_doctor(self, doctor_id: int, 
                              limit: int = 100, 
                              offset: int = 0) -> List[Patient]:
        """Получение списка пациентов врача с пагинацией"""
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
    
    def search_patients(self, doctor_id: int, 
                       query: str,
                       limit: int = 50) -> List[Patient]:
        """Поиск пациентов по имени или другим данным"""
        cursor = self.connection.cursor()
        
        search_term = f"%{query}%"
        cursor.execute("""
        SELECT * FROM patients 
        WHERE doctor_id = ? AND (
            full_name LIKE ? OR
            phone LIKE ? OR
            email LIKE ? OR
            insurance_number LIKE ?
        )
        ORDER BY full_name
        LIMIT ?
        """, (doctor_id, search_term, search_term, search_term, search_term, limit))
        
        patients = []
        for row in cursor.fetchall():
            patients.append(self._row_to_patient(row))
        
        return patients
    
    def add_medical_record(self, record: MedicalRecord) -> int:
        """Добавление медицинской записи"""
        cursor = self.connection.cursor()
        
        tags_json = json.dumps(record.tags, ensure_ascii=False)
        
        cursor.execute("""
        INSERT INTO medical_records 
        (patient_id, doctor_id, record_type, encrypted_content, tags_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record.patient_id,
            record.doctor_id,
            record.record_type,
            record.encrypted_content,
            tags_json,
            record.created_at.isoformat() if record.created_at else None
        ))
        
        record_id = cursor.lastrowid
        self.connection.commit()
        return record_id
    
    def get_patient_records(self, patient_id: int,
                          record_type: Optional[str] = None,
                          limit: int = 100,
                          offset: int = 0) -> List[Dict[str, Any]]:
        """Получение записей пациента"""
        cursor = self.connection.cursor()
        
        query = """
        SELECT mr.*, p.full_name as patient_name, d.full_name as doctor_name
        FROM medical_records mr
        JOIN patients p ON mr.patient_id = p.id
        JOIN doctors d ON mr.doctor_id = d.id
        WHERE mr.patient_id = ?
        """
        params = [patient_id]
        
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
            records.append(record)
        
        return records
    
    def add_measurement(self, patient_id: int,
                       measurement_type: str,
                       value: float,
                       unit: str,
                       notes: str = "") -> int:
        """Добавление измерения"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
        INSERT INTO measurements 
        (patient_id, measurement_type, value, unit, notes)
        VALUES (?, ?, ?, ?, ?)
        """, (patient_id, measurement_type, value, unit, notes))
        
        measurement_id = cursor.lastrowid
        self.connection.commit()
        return measurement_id
    
    def get_measurements(self, patient_id: int,
                        measurement_type: Optional[str] = None,
                        start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None,
                        limit: int = 500) -> List[Dict[str, Any]]:
        """Получение измерений пациента"""
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM measurements WHERE patient_id = ?"
        params = [patient_id]
        
        if measurement_type:
            query += " AND measurement_type = ?"
            params.append(measurement_type)
        
        if start_date:
            query += " AND taken_at >= ?"
            params.append(start_date.isoformat())
        
        if end_date:
            query += " AND taken_at <= ?"
            params.append(end_date.isoformat())
        
        query += " ORDER BY taken_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        measurements = []
        for row in cursor.fetchall():
            measurements.append(dict(row))
        
        return measurements
    
    def get_statistics(self, doctor_id: int) -> Dict[str, Any]:
        """Статистика для врача"""
        cursor = self.connection.cursor()
        
        stats = {}
        
        # Количество пациентов
        cursor.execute("SELECT COUNT(*) FROM patients WHERE doctor_id = ?", (doctor_id,))
        stats['total_patients'] = cursor.fetchone()[0]
        
        # Количество записей за последний месяц
        from datetime import datetime, timedelta
        month_ago = datetime.now() - timedelta(days=30)
        cursor.execute("""
        SELECT COUNT(*) FROM medical_records 
        WHERE doctor_id = ? AND created_at >= ?
        """, (doctor_id, month_ago.isoformat()))
        stats['records_last_month'] = cursor.fetchone()[0]
        
        # Распределение по типам записей
        cursor.execute("""
        SELECT record_type, COUNT(*) as count 
        FROM medical_records 
        WHERE doctor_id = ?
        GROUP BY record_type
        """, (doctor_id,))
        
        stats['records_by_type'] = {row['record_type']: row['count'] 
                                   for row in cursor.fetchall()}
        
        # Активные назначения
        cursor.execute("""
        SELECT COUNT(*) FROM prescriptions 
        WHERE doctor_id = ? AND is_active = 1
        """, (doctor_id,))
        stats['active_prescriptions'] = cursor.fetchone()[0]
        
        return stats
    
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
            created_at=created_at
        )
    
    def connect(self) -> sqlite3.Connection:
        """Получение соединения с БД (удобный метод)"""
        if self.connection is None:
            self._init_connection()
        return self.connection
    
    def close(self):
        """Закрытие соединения с БД"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        """Контекстный менеджер"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Контекстный менеджер - выход"""
        self.close()


if __name__ == "__main__":
    # Тест базы данных
    print("🧪 Тестирование исправленной базы данных...")
    
    db = MedicalDatabase("test_medical_fixed.db")
    
    try:
        # Тест соединения
        print("✅ Соединение с БД установлено")
        
        # Тест добавления пациента
        patient = Patient(
            doctor_id=1,
            full_name="Иванов Петр Сидорович",
            birth_date=date(1980, 5, 15),
            gender="M",
            blood_type="A+",
            allergies="Пенициллин, аспирин",
            phone="+79161234567",
            email="ivanov@example.com",
            address="ул. Ленина, д. 10, кв. 5"
        )
        
        patient_id = db.add_patient(patient)
        print(f"✅ Пациент добавлен, ID: {patient_id}")
        
        # Тест получения пациента
        retrieved = db.get_patient(patient_id)
        print(f"✅ Пациент получен: {retrieved.full_name}, возраст: {retrieved.age}")
        
        # Тест поиска
        patients = db.search_patients(1, "Иванов")
        print(f"✅ Найдено пациентов по поиску: {len(patients)}")
        
        print("\n🎉 Все тесты базы данных пройдены успешно!")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        db.close()
        
        # Удаляем тестовую БД
        if os.path.exists("test_medical_fixed.db"):
            os.remove("test_medical_fixed.db")
            print("🧹 Тестовая БД удалена")