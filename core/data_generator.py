#!/usr/bin/env python3
"""
Генератор медицинских тестовых данных - БЕЗ криптографии
Для быстрого создания тестовых баз данных при разработке
"""

import sys
import os
import random
import json
from datetime import datetime, timedelta, date
from typing import List, Dict, Any

# Добавляем путь для импорта модулей
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Импортируем старую версию БД без криптографии
try:
    from core.database_old import MedicalDatabase, Patient, MedicalRecord
except ImportError:
    # Пробуем стандартный импорт
    try:
        from core.database import MedicalDatabase, Patient, MedicalRecord
    except ImportError:
        # Создаем простые классы напрямую
        from dataclasses import dataclass, field
        from typing import Optional
        import sqlite3
        
        @dataclass
        class Patient:
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
                if not self.birth_date:
                    return 0
                today = date.today()
                age = today.year - self.birth_date.year
                if (today.month, today.day) < (self.birth_date.month, self.birth_date.day):
                    age -= 1
                return age
        
        @dataclass
        class MedicalRecord:
            id: Optional[int] = None
            patient_id: int = 0
            doctor_id: int = 0
            record_type: str = ""
            encrypted_content: str = ""
            tags: List[str] = field(default_factory=list)
            created_at: Optional[datetime] = None
        
        class MedicalDatabase:
            """Упрощенная версия БД без криптографии"""
            def __init__(self, db_path: str):
                self.db_path = db_path
                self.connection = sqlite3.connect(db_path)
                self.connection.row_factory = sqlite3.Row
                self._create_tables()
            
            def _create_tables(self):
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
                    FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE,
                    FOREIGN KEY (doctor_id) REFERENCES doctors (id) ON DELETE CASCADE
                )
                """)
                
                # Таблица измерений
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
                
                # Таблица назначений
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
                
                self.connection.commit()
                print("✅ Таблицы созданы успешно")
            
            def add_patient(self, patient: Patient) -> int:
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
            
            def add_medical_record(self, record: MedicalRecord) -> int:
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
            
            def get_patients_by_doctor(self, doctor_id: int) -> List[Patient]:
                cursor = self.connection.cursor()
                cursor.execute("SELECT * FROM patients WHERE doctor_id = ?", (doctor_id,))
                
                patients = []
                for row in cursor.fetchall():
                    birth_date = None
                    if row['birth_date']:
                        try:
                            birth_date = date.fromisoformat(row['birth_date'])
                        except:
                            pass
                    
                    created_at = None
                    if row['created_at']:
                        try:
                            created_at = datetime.fromisoformat(row['created_at'].replace('Z', '+00:00'))
                        except:
                            pass
                    
                    patients.append(Patient(
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
                    ))
                
                return patients
            
            def close(self):
                if self.connection:
                    self.connection.close()


class MedicalDataGenerator:
    """Генератор реалистичных медицинских тестовых данных"""
    
    def __init__(self):
        # Загружаем русские имена
        self.names = self._load_russian_names()
        
        # Медицинские данные
        self.diagnoses = [
            {"name": "Эссенциальная гипертензия", "category": "Кардиология"},
            {"name": "Сахарный диабет 2 типа", "category": "Эндокринология"},
            {"name": "Бронхиальная астма", "category": "Пульмонология"},
            {"name": "Хронический гастрит", "category": "Гастроэнтерология"},
            {"name": "Остеохондроз", "category": "Неврология"},
            {"name": "ОРВИ", "category": "Терапия"},
            {"name": "Артериальная гипертензия", "category": "Кардиология"},
            {"name": "Хроническая сердечная недостаточность", "category": "Кардиология"},
        ]
        
        self.medications = [
            {"name": "Метформин", "dosage": "500 мг", "category": "Гипогликемическое"},
            {"name": "Лизиноприл", "dosage": "10 мг", "category": "Гипотензивное"},
            {"name": "Амлодипин", "dosage": "5 мг", "category": "Гипотензивное"},
            {"name": "Аторвастатин", "dosage": "20 мг", "category": "Гиполипидемическое"},
            {"name": "Сальбутамол", "dosage": "100 мкг", "category": "Бронхолитическое"},
            {"name": "Омепразол", "dosage": "20 мг", "category": "Антацидное"},
            {"name": "Ибупрофен", "dosage": "200 мг", "category": "Обезболивающее"},
            {"name": "Амоксициллин", "dosage": "500 мг", "category": "Антибиотик"},
        ]
        
        self.symptoms = [
            "Головная боль", "Головокружение", "Тошнота", "Слабость",
            "Боль в груди", "Одышка", "Кашель", "Температура",
            "Боль в животе", "Боль в суставах", "Насморк", "Боль в горле",
            "Повышенное давление", "Учащенное сердцебиение", "Отеки",
            "Потеря веса", "Повышенная утомляемость", "Бессонница"
        ]
        
        self.blood_types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
        self.cities = ['Москва', 'Санкт-Петербург', 'Новосибирск', 'Екатеринбург', 'Казань']
        self.streets = ['Ленина', 'Пушкина', 'Гагарина', 'Советская', 'Мира', 'Центральная']
        
    def _load_russian_names(self) -> Dict[str, List[str]]:
        """Загрузка русских имен с женскими фамилиями"""
        return {
            'male_first': [
                'Александр', 'Андрей', 'Дмитрий', 'Сергей', 'Иван', 'Михаил',
                'Алексей', 'Владимир', 'Евгений', 'Николай', 'Павел', 'Роман'
            ],
            'female_first': [
                'Елена', 'Ольга', 'Наталья', 'Ирина', 'Мария', 'Анна',
                'Татьяна', 'Светлана', 'Екатерина', 'Юлия', 'Людмила', 'Галина'
            ],
            'last': [
                'Иванов', 'Петров', 'Сидоров', 'Смирнов', 'Кузнецов', 'Попов',
                'Васильев', 'Соколов', 'Михайлов', 'Новиков', 'Федоров', 'Морозов'
            ],
            'male_middle': [
                'Александрович', 'Алексеевич', 'Андреевич', 'Дмитриевич',
                'Сергеевич', 'Иванович', 'Михайлович', 'Владимирович'
            ],
            'female_middle': [
                'Александровна', 'Алексеевна', 'Андреевна', 'Дмитриевна',
                'Сергеевна', 'Ивановна', 'Михайловна', 'Владимировна'
            ]
        }
    
    def _get_female_last_name(self, male_last: str) -> str:
        """Преобразование мужской фамилии в женскую"""
        if male_last.endswith(('ов', 'ев', 'ёв')):
            return male_last + 'а'
        elif male_last.endswith('ин'):
            return male_last[:-1] + 'на'
        elif male_last.endswith('ский'):
            return male_last[:-2] + 'ая'
        elif male_last.endswith('ой'):
            return male_last[:-2] + 'ая'
        else:
            return male_last + 'а'
    
    def generate_patient(self, patient_num: int, doctor_id: int = 1) -> Patient:
        """Генерация данных пациента с корректными женскими фамилиями"""
        gender = random.choice(['M', 'F'])
        
        if gender == 'M':
            first_name = random.choice(self.names['male_first'])
            middle_name = random.choice(self.names['male_middle'])
            last_name = random.choice(self.names['last'])
        else:
            first_name = random.choice(self.names['female_first'])
            middle_name = random.choice(self.names['female_middle'])
            male_last = random.choice(self.names['last'])
            last_name = self._get_female_last_name(male_last)
        
        full_name = f"{last_name} {first_name} {middle_name}"
        
        # Возраст 18-85 лет
        age = random.randint(18, 85)
        birth_date = date.today() - timedelta(days=age * 365 + random.randint(0, 364))
        
        # Генерация контактов
        phone = f"+7{random.randint(900, 999)}{random.randint(1000000, 9999999)}"
        email = f"{first_name.lower()}.{last_name.lower()}@example.com"
        
        # Адрес
        city = random.choice(self.cities)
        street = random.choice(self.streets)
        house = random.randint(1, 100)
        apartment = random.randint(1, 200)
        address = f"г. {city}, ул. {street}, д. {house}, кв. {apartment}"
        
        # Аллергии (30% пациентов)
        allergies = ""
        if random.random() < 0.3:
            allergies = random.choice(['Пенициллин', 'Аспирин', 'Йод', 'Пыльца', 'Арахис', 'Молоко'])
        
        return Patient(
            id=patient_num,
            doctor_id=doctor_id,
            full_name=full_name,
            birth_date=birth_date,
            gender=gender,
            blood_type=random.choice(self.blood_types),
            allergies=allergies,
            phone=phone,
            email=email,
            address=address,
            insurance_number=f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
            created_at=datetime.now() - timedelta(days=random.randint(1, 365))
        )
    
    def generate_medical_record(self, patient: Patient, record_num: int) -> str:
        """Генерация содержания медицинской записи"""
        diagnosis = random.choice(self.diagnoses)
        medication = random.choice(self.medications)
        
        # Генерация симптомов
        num_symptoms = random.randint(1, 4)
        selected_symptoms = random.sample(self.symptoms, num_symptoms)
        
        # Жалобы на основе диагноза
        if "гипертензия" in diagnosis["name"].lower():
            complaints = "жалуется на головную боль, головокружение, повышение артериального давления"
            findings = f"АД: {random.randint(130, 180)}/{random.randint(80, 110)} мм рт.ст., пульс: {random.randint(60, 100)} уд/мин"
        elif "диабет" in diagnosis["name"].lower():
            complaints = "жалуется на жажду, частое мочеиспускание, слабость"
            findings = f"Глюкоза крови: {random.uniform(6.0, 15.0):.1f} ммоль/л, HbA1c: {random.uniform(6.0, 10.0):.1f}%"
        elif "астма" in diagnosis["name"].lower():
            complaints = "жалуется на одышку, кашель, затрудненное дыхание"
            findings = f"ЧД: {random.randint(18, 30)} в мин, SpO2: {random.randint(92, 99)}%"
        else:
            complaints = f"жалуется на {', '.join(selected_symptoms).lower()}"
            findings = f"Состояние удовлетворительное. {random.choice(['Патологии не выявлено.', 'Требуется дополнительное обследование.'])}"
        
        record_text = f"""МЕДИЦИНСКАЯ ЗАПИСЬ №{record_num}
Дата: {(datetime.now() - timedelta(days=random.randint(0, 30))).strftime('%d.%m.%Y %H:%M')}
Пациент: {patient.full_name}
Возраст: {patient.age} лет
Пол: {'Мужской' if patient.gender == 'M' else 'Женский'}

ЖАЛОБЫ:
{complaints}.

АНАМНЕЗ:
Заболевание началось {random.choice(['остро', 'постепенно'])}, длительность {random.randint(1, 14)} дней.
Сопутствующие заболевания: {random.choice(['гипертоническая болезнь', 'сахарный диабет', 'ИБС', 'отсутствуют'])}.
Аллергии: {patient.allergies if patient.allergies else 'не выявлены'}.

ОБЪЕКТИВНО:
{findings}.

ДИАГНОЗ:
Основной: {diagnosis['name']} ({diagnosis['category']})

НАЗНАЧЕНИЯ:
{medication['name']} {medication['dosage']}, {random.randint(1, 3)} раза в день в течение {random.choice(['7', '10', '14', '30'])} дней.

РЕКОМЕНДАЦИИ:
{random.choice(['Амбулаторное лечение', 'Контроль через неделю', 'Стационарное лечение', 'Консультация специалиста'])}.

Врач: {random.choice(['Иванов И.И.', 'Петрова А.С.', 'Сидоров В.П.'])}
"""
        
        return record_text
    
    def create_test_doctor(self, db: MedicalDatabase) -> int:
        """Создание тестового врача"""
        cursor = db.connection.cursor()
        
        # Проверяем есть ли тестовый врач
        cursor.execute("SELECT id FROM doctors WHERE username = 'test_doctor'")
        existing = cursor.fetchone()
        
        if existing:
            print(f"✅ Используем существующего врача (ID: {existing['id']})")
            return existing['id']
        
        # Создаем тестового врача
        try:
            from bcrypt import hashpw, gensalt
            password_hash = hashpw(b"doctor123", gensalt()).decode()
            
            cursor.execute("""
            INSERT INTO doctors (username, password_hash, full_name, specialization, license_number)
            VALUES (?, ?, ?, ?, ?)
            """, (
                "test_doctor",
                password_hash,
                "Иванов Иван Иванович",
                "Терапевт",
                f"ЛО-{random.randint(100000, 999999)}"
            ))
            
            doctor_id = cursor.lastrowid
            db.connection.commit()
            
            print(f"✅ Создан тестовый врач (ID: {doctor_id})")
            print(f"   Логин: test_doctor")
            print(f"   Пароль: doctor123")
            print(f"   Имя: Иванов Иван Иванович")
            print(f"   Специализация: Терапевт")
            
            return doctor_id
            
        except Exception as e:
            print(f"⚠️ Ошибка создания врача: {e}")
            # Возвращаем ID 1 по умолчанию
            return 1
    
    def populate_database(self, db_path: str, num_patients: int = 20) -> Dict[str, int]:
        """Основной метод заполнения базы данных"""
        print(f"🧬 Генерация тестовых данных для {num_patients} пациентов...")
        print("=" * 60)
        
        # Создаем/подключаемся к БД (старая версия без криптографии)
        db = MedicalDatabase(db_path)
        
        stats = {
            'patients': 0,
            'records': 0,
            'measurements': 0,
            'prescriptions': 0,
            'doctor_id': None
        }
        
        try:
            # Создаем тестового врача
            doctor_id = self.create_test_doctor(db)
            stats['doctor_id'] = doctor_id
            
            # Генерируем пациентов
            for patient_num in range(1, num_patients + 1):
                try:
                    # Генерируем пациента
                    patient = self.generate_patient(patient_num, doctor_id)
                    
                    # Добавляем пациента в БД (простая версия без криптографии)
                    patient_id = db.add_patient(patient)
                    stats['patients'] += 1
                    
                    # Прогресс
                    if patient_num % 10 == 0 or patient_num == num_patients:
                        gender_symbol = '👨' if patient.gender == 'M' else '👩'
                        print(f"   {gender_symbol} Пациент {patient_num}: {patient.full_name} ({patient.age} лет)")
                    
                    # Медицинские записи (1-4 на пациента)
                    num_records = random.randint(1, 4)
                    for record_num in range(1, num_records + 1):
                        record_content = self.generate_medical_record(patient, record_num)
                        
                        record = MedicalRecord(
                            patient_id=patient_id,
                            doctor_id=doctor_id,
                            record_type=random.choice(['examination', 'diagnosis', 'consultation', 'test_result']),
                            encrypted_content=record_content,  # Без шифрования, просто текст
                            tags=[random.choice(['осмотр', 'диагностика', 'лечение'])],
                            created_at=datetime.now() - timedelta(days=random.randint(0, 30))
                        )
                        
                        db.add_medical_record(record)
                        stats['records'] += 1
                    
                    # Измерения (2-8 на пациента)
                    cursor = db.connection.cursor()
                    num_measurements = random.randint(2, 8)
                    
                    for _ in range(num_measurements):
                        measurement_type = random.choice(['blood_pressure', 'heart_rate', 'temperature', 'weight', 'glucose'])
                        
                        if measurement_type == 'blood_pressure':
                            value = random.randint(110, 180)
                            unit = 'mmHg'
                            notes = f"{value}/{random.randint(70, 110)} мм рт.ст."
                        elif measurement_type == 'heart_rate':
                            value = random.randint(50, 120)
                            unit = 'bpm'
                            notes = ''
                        elif measurement_type == 'temperature':
                            value = round(random.uniform(36.0, 39.0), 1)
                            unit = '°C'
                            notes = ''
                        elif measurement_type == 'glucose':
                            value = round(random.uniform(3.5, 12.0), 1)
                            unit = 'mmol/L'
                            notes = ''
                        else:  # weight
                            value = round(random.uniform(50.0, 120.0), 1)
                            unit = 'kg'
                            notes = ''
                        
                        cursor.execute("""
                        INSERT INTO measurements 
                        (patient_id, measurement_type, value, unit, notes, taken_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            patient_id,
                            measurement_type,
                            value,
                            unit,
                            notes,
                            (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
                        ))
                        stats['measurements'] += 1
                    
                    # Назначения (70% пациентов)
                    if random.random() < 0.7:
                        medication = random.choice(self.medications)
                        start_date = date.today() - timedelta(days=random.randint(0, 14))
                        end_date = start_date + timedelta(days=random.choice([7, 10, 14, 30]))
                        
                        cursor.execute("""
                        INSERT INTO prescriptions 
                        (patient_id, doctor_id, medication_name, dosage, frequency, 
                         start_date, end_date, is_active, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            patient_id,
                            doctor_id,
                            medication['name'],
                            medication['dosage'],
                            f"{random.randint(1, 3)} раза в день",
                            start_date.isoformat(),
                            end_date.isoformat(),
                            end_date >= date.today(),
                            f"Принимать {random.choice(['до', 'после'])} еды"
                        ))
                        stats['prescriptions'] += 1
                    
                except Exception as e:
                    print(f"⚠️ Ошибка при генерации пациента {patient_num}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            
            db.connection.commit()
            
            print("=" * 60)
            print("✅ ТЕСТОВЫЕ ДАННЫЕ УСПЕШНО СОЗДАНЫ!")
            print("=" * 60)
            
            return stats
            
        except Exception as e:
            print(f"❌ Ошибка при заполнении БД: {e}")
            import traceback
            traceback.print_exc()
            raise
            
        finally:
            db.close()
    
    def export_all_data_to_json(self, db_path: str, json_filename: str = None):
        """
        Полный экспорт всех данных из БД в JSON файл
        """
        if json_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_filename = f"medical_data_export_{timestamp}.json"
        
        print(f"📁 Экспорт всех данных в {json_filename}...")
        
        # Используем упрощенную БД для экспорта
        db = MedicalDatabase(db_path)
        
        try:
            # Собираем все данные
            all_data = {
                'export_info': {
                    'export_date': datetime.now().isoformat(),
                    'source_database': db_path,
                    'exported_by': 'MedicalDataGenerator',
                    'note': 'Тестовые данные для разработки. Без криптографии.'
                },
                'doctors': [],
                'patients': [],
                'medical_records': [],
                'measurements': [],
                'prescriptions': [],
                'statistics': {}
            }
            
            cursor = db.connection.cursor()
            
            # 1. Врачи
            cursor.execute("SELECT * FROM doctors ORDER BY id")
            for row in cursor.fetchall():
                doctor = dict(row)
                # Убираем хэш пароля из экспорта
                if 'password_hash' in doctor:
                    doctor['password_hash'] = '***HIDDEN***'
                all_data['doctors'].append(doctor)
            
            # 2. Пациенты
            cursor.execute("SELECT * FROM patients ORDER BY id")
            for row in cursor.fetchall():
                patient = dict(row)
                # Добавляем возраст
                if patient.get('birth_date'):
                    try:
                        birth_date = date.fromisoformat(patient['birth_date'])
                        patient['age'] = (date.today() - birth_date).days // 365
                    except:
                        pass
                all_data['patients'].append(patient)
            
            # 3. Медицинские записи
            cursor.execute("SELECT * FROM medical_records ORDER BY id")
            for row in cursor.fetchall():
                record = dict(row)
                if record.get('tags_json'):
                    try:
                        record['tags'] = json.loads(record['tags_json'])
                    except:
                        record['tags'] = []
                    del record['tags_json']
                all_data['medical_records'].append(record)
            
            # 4. Измерения
            cursor.execute("SELECT * FROM measurements ORDER BY id")
            for row in cursor.fetchall():
                all_data['measurements'].append(dict(row))
            
            # 5. Назначения
            cursor.execute("SELECT * FROM prescriptions ORDER BY id")
            for row in cursor.fetchall():
                all_data['prescriptions'].append(dict(row))
            
            # 6. Статистика
            all_data['statistics'] = {
                'total_doctors': len(all_data['doctors']),
                'total_patients': len(all_data['patients']),
                'total_medical_records': len(all_data['medical_records']),
                'total_measurements': len(all_data['measurements']),
                'total_prescriptions': len(all_data['prescriptions']),
                'patients_by_gender': {
                    'male': sum(1 for p in all_data['patients'] if p.get('gender') == 'M'),
                    'female': sum(1 for p in all_data['patients'] if p.get('gender') == 'F')
                }
            }
            
            # Сохраняем в файл
            with open(json_filename, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"✅ Все данные экспортированы в {json_filename}")
            print(f"   👨‍⚕️  Врачей: {all_data['statistics']['total_doctors']}")
            print(f"   👥 Пациентов: {all_data['statistics']['total_patients']}")
            print(f"   📝 Записей: {all_data['statistics']['total_medical_records']}")
            print(f"   📊 Измерений: {all_data['statistics']['total_measurements']}")
            print(f"   💊 Назначений: {all_data['statistics']['total_prescriptions']}")
            print(f"\n📄 Файл: {os.path.abspath(json_filename)}")
            
        except Exception as e:
            print(f"❌ Ошибка экспорта: {e}")
            import traceback
            traceback.print_exc()
        finally:
            db.close()


def main():
    """Основная функция для запуска из командной строки"""
    print("=" * 60)
    print("MEDICAL DIARY PRO - Генератор тестовых данных")
    print("=" * 60)
    print("Без криптографии - для быстрой разработки и тестирования")
    print("=" * 60)
    
    # Параметры командной строки
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
        num_patients = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    else:
        # Интерактивный режим
        db_path = input("\nВведите имя файла БД (по умолчанию: medical_data.db): ").strip()
        if not db_path:
            db_path = "medical_data.db"
        
        num_input = input("Количество пациентов (по умолчанию: 20): ").strip()
        num_patients = int(num_input) if num_input.isdigit() else 20
    
    # Проверка существования файла
    if os.path.exists(db_path):
        print(f"\n⚠️ Файл {db_path} уже существует.")
        choice = input("Выберите действие:\n1. Перезаписать\n2. Добавить данные\n3. Отмена\n\nВаш выбор (1-3): ").strip()
        
        if choice == '3':
            print("Отменено")
            return
        elif choice == '1':
            print(f"🗑️ Удаляю существующий файл {db_path}...")
            os.remove(db_path)
    
    try:
        # Создаем генератор
        generator = MedicalDataGenerator()
        
        # Заполняем БД
        stats = generator.populate_database(db_path, num_patients)
        
        # Экспортируем все данные в JSON
        json_filename = f"{db_path.replace('.db', '')}_export.json"
        generator.export_all_data_to_json(db_path, json_filename)
        
        # Итоговая информация
        print(f"\n📋 СТАТИСТИКА СОЗДАННОЙ БАЗЫ ДАННЫХ:")
        print(f"   👨‍⚕️  Врач: test_doctor / doctor123 (ID: {stats['doctor_id']})")
        print(f"   👥 Пациентов: {stats['patients']}")
        print(f"   📝 Медицинских записей: {stats['records']}")
        print(f"   📊 Измерений: {stats['measurements']}")
        print(f"   💊 Назначений: {stats['prescriptions']}")
        print(f"\n📁 Файлы:")
        print(f"   База данных: {os.path.abspath(db_path)}")
        print(f"   Полный JSON экспорт: {json_filename}")
        
        print("\n🔧 Пример использования в коде:")
        print(f'''from core.database import MedicalDatabase
db = MedicalDatabase("{db_path}")
patients = db.get_patients_by_doctor(1)
print(f"Найдено {{len(patients)}} пациентов")''')
        
        print("\n🎉 Генерация завершена успешно!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Генерация прервана пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())