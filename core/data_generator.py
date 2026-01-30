# core/data_generator.py
"""
Генератор реалистичных медицинских тестовых данных для приложения
"""

from core.database import MedicalDatabase, Patient, MedicalRecord
from core.crypto import DataCrypto

import random
import string
from datetime import datetime, timedelta, date
from typing import List, Dict, Any, Optional
import json
import sqlite3
from dataclasses import dataclass, asdict
import os


class MedicalDataGenerator:
    """Генератор медицинских тестовых данных"""
    
    def __init__(self, locale: str = 'ru_RU'):
        self.locale = locale
        self.crypto = DataCrypto()
        
        # Загружаем русские имена
        self.names = self._load_russian_names()
        
        # Медицинские данные
        self.diagnoses = [
            {"code": "I10", "name": "Эссенциальная гипертензия", "category": "Кардиология"},
            {"code": "I20", "name": "Стенокардия", "category": "Кардиология"},
            {"code": "E11", "name": "Сахарный диабет 2 типа", "category": "Эндокринология"},
            {"code": "J45", "name": "Астма", "category": "Пульмонология"},
            {"code": "K29", "name": "Гастрит", "category": "Гастроэнтерология"},
            {"code": "M54", "name": "Дорсалгия", "category": "Неврология"},
            {"code": "F32", "name": "Депрессивный эпизод", "category": "Психиатрия"},
            {"code": "J06", "name": "ОРВИ", "category": "Терапия"},
        ]
        
        self.medications = [
            {"name": "Метформин", "dosage": "500 мг", "for_diagnosis": "E11"},
            {"name": "Лизиноприл", "dosage": "10 мг", "for_diagnosis": "I10"},
            {"name": "Амлодипин", "dosage": "5 мг", "for_diagnosis": "I10"},
            {"name": "Аторвастатин", "dosage": "20 мг", "for_diagnosis": "I10"},
            {"name": "Сальбутамол", "dosage": "100 мкг", "for_diagnosis": "J45"},
            {"name": "Омепразол", "dosage": "20 мг", "for_diagnosis": "K29"},
            {"name": "Ибупрофен", "dosage": "200 мг", "for_diagnosis": "M54"},
            {"name": "Парацетамол", "dosage": "500 мг", "for_diagnosis": "J06"},
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
        """Загрузка русских имен и фамилий"""
        return {
            'male_first': [
                'Александр', 'Алексей', 'Андрей', 'Антон', 'Артём', 
                'Борис', 'Вадим', 'Валентин', 'Валерий', 'Виктор',
                'Виталий', 'Владимир', 'Владислав', 'Геннадий', 'Георгий',
                'Дмитрий', 'Евгений', 'Иван', 'Игорь', 'Кирилл'
            ],
            'female_first': [
                'Александра', 'Алина', 'Анастасия', 'Анна', 'Валентина',
                'Валерия', 'Вера', 'Виктория', 'Галина', 'Дарья',
                'Евгения', 'Екатерина', 'Елена', 'Ирина', 'Ксения',
                'Лариса', 'Марина', 'Мария', 'Наталья', 'Ольга'
            ],
            'last': [
                'Иванов', 'Смирнов', 'Кузнецов', 'Попов', 'Васильев',
                'Петров', 'Соколов', 'Михайлов', 'Новиков', 'Фёдоров',
                'Морозов', 'Волков', 'Алексеев', 'Лебедев', 'Семёнов',
                'Егоров', 'Павлов', 'Козлов', 'Степанов', 'Николаев',
                'Орлов', 'Андреев', 'Макаров', 'Никитин', 'Захаров'
            ],
            'male_middle': [
                'Александрович', 'Алексеевич', 'Андреевич', 'Антонович',
                'Борисович', 'Вадимович', 'Валентинович', 'Валерьевич',
                'Викторович', 'Витальевич', 'Владимирович', 'Геннадьевич'
            ],
            'female_middle': [
                'Александровна', 'Алексеевна', 'Андреевна', 'Антоновна',
                'Борисовна', 'Вадимовна', 'Валентиновна', 'Валерьевна',
                'Викторовна', 'Витальевна', 'Владимировна', 'Геннадьевна'
            ]
        }
    
    def generate_patient(self, patient_id: int, doctor_id: int = 1) -> Patient:
        """Генерация данных пациента"""
        gender = random.choice(['M', 'F'])
        
        if gender == 'M':
            first_name = random.choice(self.names['male_first'])
            middle_name = random.choice(self.names['male_middle'])
        else:
            first_name = random.choice(self.names['female_first'])
            middle_name = random.choice(self.names['female_middle'])
        
        last_name = random.choice(self.names['last'])
        full_name = f"{last_name} {first_name} {middle_name}"
        
        # Дата рождения (18-90 лет)
        years_old = random.randint(18, 90)
        birth_date = date.today() - timedelta(days=years_old*365 + random.randint(0, 364))
        
        # Генерация контактов
        phone = f"+7{random.randint(900, 999)}{random.randint(1000000, 9999999)}"
        email = f"{first_name.lower()}.{last_name.lower()}@example.com"
        
        # Адрес
        city = random.choice(self.cities)
        street = random.choice(self.streets)
        house = random.randint(1, 100)
        apartment = random.randint(1, 200)
        address = f"г. {city}, ул. {street}, д. {house}, кв. {apartment}"
        
        # Аллергии (30% пациентов имеют аллергии)
        allergies = ""
        if random.random() < 0.3:
            allergies = random.choice(['Пенициллин', 'Аспирин', 'Йод', 'Пыльца', 'Арахис', 'Молоко'])
        
        return Patient(
            id=patient_id,
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
    
    def generate_medical_record(self, patient_id: int, doctor_id: int, crypto_key: bytes) -> MedicalRecord:
        """Генерация медицинской записи"""
        record_types = ['examination', 'complaint', 'diagnosis', 'prescription', 'test_result']
        record_type = random.choice(record_types)
        
        # Выбираем случайный диагноз
        diagnosis = random.choice(self.diagnoses)
        
        # Генерируем симптомы
        num_symptoms = random.randint(1, 4)
        selected_symptoms = random.sample(self.symptoms, num_symptoms)
        
        # Определяем жалобы на основе диагноза
        if diagnosis["code"] == "I10":  # Гипертензия
            complaints = "жалуется на головную боль, головокружение, повышенное давление"
            findings = f"АД: {random.randint(130, 180)}/{random.randint(80, 110)} мм рт.ст., ЧСС: {random.randint(70, 100)} уд/мин"
        elif diagnosis["code"] == "E11":  # Диабет
            complaints = "жалуется на жажду, частое мочеиспускание, слабость"
            findings = f"Глюкоза крови: {random.uniform(7.0, 15.0):.1f} ммоль/л"
        elif diagnosis["code"] == "J45":  # Астма
            complaints = "жалуется на одышку, кашель, затрудненное дыхание"
            findings = f"ЧД: {random.randint(18, 30)} в мин, SpO2: {random.randint(92, 99)}%"
        else:
            complaints = f"жалуется на {', '.join(selected_symptoms).lower()}"
            findings = "Состояние удовлетворительное"
        
        # Генерируем текст записи
        record_text = f"""
ПАЦИЕНТ: {complaints}.

Анамнез заболевания: {random.choice(['заболевание началось остро', 'симптомы нарастали постепенно', 'хроническое течение'])}.

Объективно: {findings}.

Данные обследования: {random.choice(['в пределах нормы', 'требуется дообследование', 'патологические изменения'])}.

ДИАГНОЗ: {diagnosis['name']} ({diagnosis['code']}).

РЕКОМЕНДАЦИИ: {random.choice(['амбулаторное наблюдение', 'консультация специалиста', 'стационарное лечение'])}.

Назначения: {random.choice(self.medications)['name']}, {random.randint(1, 3)} раза в день.
        """.strip()
        
        # Шифруем содержимое
        encrypted_content = self.crypto.encrypt(record_text, crypto_key)
        
        # Теги для поиска
        tags = [diagnosis['category'], diagnosis['code']] + selected_symptoms
        
        return MedicalRecord(
            patient_id=patient_id,
            doctor_id=doctor_id,
            record_type=record_type,
            encrypted_content=encrypted_content,
            tags=tags,
            created_at=datetime.now() - timedelta(days=random.randint(0, 30))
        )
    
    def generate_measurement(self, patient_id: int, measurement_type: str = None) -> Dict[str, Any]:
        """Генерация одного измерения"""
        if not measurement_type:
            measurement_type = random.choice(['blood_pressure', 'glucose', 'temperature', 'heart_rate', 'weight', 'spo2'])
        
        base_date = datetime.now() - timedelta(days=30)
        taken_at = base_date + timedelta(days=random.randint(0, 30), hours=random.randint(8, 18))
        
        if measurement_type == 'blood_pressure':
            systolic = random.randint(110, 180)
            diastolic = random.randint(70, 110)
            return {
                'patient_id': patient_id,
                'measurement_type': measurement_type,
                'value': systolic,
                'unit': 'mmHg',
                'notes': f"{systolic}/{diastolic} мм рт.ст.",
                'taken_at': taken_at
            }
        elif measurement_type == 'glucose':
            value = random.uniform(3.5, 15.0)
            return {
                'patient_id': patient_id,
                'measurement_type': measurement_type,
                'value': round(value, 1),
                'unit': 'mmol/L',
                'notes': '',
                'taken_at': taken_at
            }
        elif measurement_type == 'temperature':
            value = random.uniform(36.0, 39.5)
            return {
                'patient_id': patient_id,
                'measurement_type': measurement_type,
                'value': round(value, 1),
                'unit': '°C',
                'notes': '',
                'taken_at': taken_at
            }
        elif measurement_type == 'heart_rate':
            value = random.randint(50, 120)
            return {
                'patient_id': patient_id,
                'measurement_type': measurement_type,
                'value': value,
                'unit': 'bpm',
                'notes': '',
                'taken_at': taken_at
            }
        else:  # weight или spo2
            if measurement_type == 'weight':
                value = random.uniform(50.0, 120.0)
                unit = 'kg'
            else:  # spo2
                value = random.randint(92, 100)
                unit = '%'
            
            return {
                'patient_id': patient_id,
                'measurement_type': measurement_type,
                'value': round(value, 1),
                'unit': unit,
                'notes': '',
                'taken_at': taken_at
            }
    
    def generate_prescription(self, patient_id: int, doctor_id: int) -> Dict[str, Any]:
        """Генерация назначения"""
        medication = random.choice(self.medications)
        
        frequencies = ['1 раз в день', '2 раза в день', '3 раза в день', 'по необходимости']
        times = ['утром', 'днем', 'вечером', 'перед сном', 'после еды', 'до еды']
        
        start_date = date.today() - timedelta(days=random.randint(0, 30))
        duration_days = random.choice([7, 14, 30, 60, 90])
        end_date = start_date + timedelta(days=duration_days)
        
        return {
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'medication_name': medication['name'],
            'dosage': medication['dosage'],
            'frequency': f"{random.choice(frequencies)} {random.choice(times)}",
            'start_date': start_date,
            'end_date': end_date,
            'is_active': end_date >= date.today(),
            'notes': f"Принимать {random.choice(['до', 'после', 'во время'])} еды",
            'created_at': datetime.now() - timedelta(days=random.randint(0, duration_days))
        }
    
    def populate_database(self, db: MedicalDatabase, 
                         num_patients: int = 20,
                         crypto_key: bytes = None) -> Dict[str, int]:
        """
        Заполнение базы данных тестовыми данными
        
        Args:
            db: Экземпляр базы данных
            num_patients: Количество пациентов для генерации
            crypto_key: Ключ для шифрования записей
            
        Returns:
            Dict: Статистика добавленных данных
        """
        if crypto_key is None:
            crypto_key = self.crypto.derive_key("test_doctor_password")
        
        print(f"🧬 Генерация тестовых данных для {num_patients} пациентов...")
        print("=" * 50)
        
        stats = {
            'patients': 0,
            'records': 0,
            'measurements': 0,
            'prescriptions': 0
        }
        
        # Используем connection напрямую (метода connect() нет)
        conn = db.connection  # ← ИЗМЕНИЛИ ЗДЕСЬ
        cursor = conn.cursor()
        
        # Проверяем есть ли тестовый врач
        cursor.execute("SELECT COUNT(*) FROM doctors WHERE id = 1")
        if cursor.fetchone()[0] == 0:
            from bcrypt import hashpw, gensalt
            password_hash = hashpw("doctor123".encode(), gensalt()).decode()
            cursor.execute("""
            INSERT INTO doctors (id, username, password_hash, full_name, specialization)
            VALUES (1, 'test_doctor', ?, 'Иванов Иван Иванович', 'Терапевт')
            """, (password_hash,))
            conn.commit()
            print("✅ Создан тестовый врач (логин: test_doctor, пароль: doctor123)")
        
        # Генерируем пациентов
        for patient_id in range(1, num_patients + 1):
            # Генерируем пациента
            patient = self.generate_patient(patient_id, doctor_id=1)
            
            try:
                # Добавляем пациента в БД
                db.add_patient(patient)
                stats['patients'] += 1
                
                # Генерируем медицинские записи (2-5 на пациента)
                num_records = random.randint(2, 5)
                for _ in range(num_records):
                    record = self.generate_medical_record(patient_id, 1, crypto_key)
                    db.add_medical_record(record)
                    stats['records'] += 1
                
                # Генерируем измерения (5-15 на пациента)
                num_measurements = random.randint(5, 15)
                measurement_types = ['blood_pressure', 'glucose', 'temperature', 'heart_rate']
                
                for _ in range(num_measurements):
                    measurement = self.generate_measurement(patient_id, 
                                                          random.choice(measurement_types))
                    db.add_measurement(
                        patient_id=measurement['patient_id'],
                        measurement_type=measurement['measurement_type'],
                        value=measurement['value'],
                        unit=measurement['unit'],
                        notes=measurement['notes']
                    )
                    stats['measurements'] += 1
                
                # Генерируем назначения (0-3 на пациента)
                if random.random() < 0.8:  # 80% пациентов получают назначения
                    num_prescriptions = random.randint(0, 3)
                    for _ in range(num_prescriptions):
                        prescription = self.generate_prescription(patient_id, 1)
                        cursor.execute("""
                        INSERT INTO prescriptions 
                        (patient_id, doctor_id, medication_name, dosage, frequency, 
                         start_date, end_date, is_active, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            prescription['patient_id'],
                            prescription['doctor_id'],
                            prescription['medication_name'],
                            prescription['dosage'],
                            prescription['frequency'],
                            prescription['start_date'].isoformat(),
                            prescription['end_date'].isoformat(),
                            prescription['is_active'],
                            prescription['notes']
                        ))
                        stats['prescriptions'] += 1
                
                # Прогресс
                if patient_id % 5 == 0:
                    print(f"   Обработано пациентов: {patient_id}/{num_patients}")
                    
            except Exception as e:
                print(f"⚠️ Ошибка при генерации пациента {patient_id}: {e}")
                continue
        
        conn.commit()
        
        print("=" * 50)
        print("✅ Тестовые данные успешно сгенерированы!")
        print(f"   👥 Пациентов: {stats['patients']}")
        print(f"   📝 Медицинских записей: {stats['records']}")
        print(f"   📊 Измерений: {stats['measurements']}")
        print(f"   💊 Назначений: {stats['prescriptions']}")
        print("=" * 50)
        print("🔑 Тестовые учетные данные:")
        print("   Врач: test_doctor / doctor123")
        print("   Пациенты: сгенерированы с ID 1..{num_patients}")
        
        return stats
    
    def export_to_json(self, db: MedicalDatabase, filename: str = "test_data_export.json"):
        """Экспорт тестовых данных в JSON файл"""
        print(f"📁 Экспорт данных в {filename}...")
        
        data = {
            'patients': [],
            'records': [],
            'measurements': [],
            'prescriptions': []
        }
        
        # Используем connection напрямую
        conn = db.connection  # ← ИЗМЕНИЛИ ЗДЕСЬ
        cursor = conn.cursor()
        
        # Экспорт пациентов
        cursor.execute("SELECT * FROM patients ORDER BY id")
        for row in cursor.fetchall():
            data['patients'].append(dict(row))
        
        # Экспорт записей
        cursor.execute("SELECT * FROM medical_records ORDER BY patient_id, created_at")
        for row in cursor.fetchall():
            record = dict(row)
            record['tags'] = json.loads(record['tags_json']) if record['tags_json'] else []
            data['records'].append(record)
        
        # Экспорт измерений
        cursor.execute("SELECT * FROM measurements ORDER BY patient_id, taken_at")
        for row in cursor.fetchall():
            data['measurements'].append(dict(row))
        
        # Экспорт назначений
        cursor.execute("SELECT * FROM prescriptions ORDER BY patient_id, start_date")
        for row in cursor.fetchall():
            data['prescriptions'].append(dict(row))
        
        # Сохраняем в файл
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"✅ Данные экспортированы в {filename}")
        print(f"   Пациентов: {len(data['patients'])}")
        print(f"   Записей: {len(data['records'])}")
        print(f"   Измерений: {len(data['measurements'])}")
        print(f"   Назначений: {len(data['prescriptions'])}")


def test_generator():
    """Тестирование генератора"""
    print("🧪 Тестирование генератора медицинских данных...")
    print("=" * 50)
    
    # Создаём тестовую БД
    test_db_path = "test_generator.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = MedicalDatabase(test_db_path)
    
    # Инициализируем генератор
    generator = MedicalDataGenerator()
    
    try:
        # Генерируем данные
        stats = generator.populate_database(db, num_patients=10)
        
        # Проверяем что данные есть в БД
        conn = db.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM patients")
        patient_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM medical_records")
        record_count = cursor.fetchone()[0]
        
        print("\n📊 Проверка данных в БД:")
        print(f"   Пациентов в БД: {patient_count}")
        print(f"   Записей в БД: {record_count}")
        
        if patient_count == stats['patients'] and record_count > 0:
            print("✅ Генератор работает корректно!")
        else:
            print("❌ Ошибка в генераторе!")
        
        # Экспортируем для проверки
        generator.export_to_json(db, "test_generator_export.json")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        db.close()
        
        # Удаляем тестовую БД
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print("\n🧹 Тестовая БД удалена")


if __name__ == "__main__":
    test_generator()