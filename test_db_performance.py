# test_db_performance.py
"""
Тест производительности базы данных
"""
import time
import random
from datetime import datetime, timedelta
import os

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import MedicalDatabase, Patient, MedicalRecord
from core.crypto import DataCrypto

def test_performance():
    print("🧪 Тест производительности базы данных")
    print("=" * 60)
    
    # Создаём тестовую БД
    test_db_path = "performance_test.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = MedicalDatabase(test_db_path)
    crypto = DataCrypto()
    key = crypto.derive_key("test")
    
    try:
        # 0. Сначала создаём тестового врача
        print("0. Создаем тестового врача...")
        cursor = db.connection.cursor()
        
        # Проверяем есть ли врач с ID=1
        cursor.execute("SELECT COUNT(*) FROM doctors WHERE id = 1")
        if cursor.fetchone()[0] == 0:
            # Создаём тестового врача
            import hashlib
            password_hash = hashlib.sha256("test123".encode()).hexdigest()
            cursor.execute("""
            INSERT INTO doctors (id, username, password_hash, full_name)
            VALUES (1, 'test_doctor', ?, 'Тестовый врач')
            """, (password_hash,))
            db.connection.commit()
            print("   ✅ Тестовый врач создан")
        
        # 1. Тест массового добавления пациентов
        print("\n1. Тест массового добавления пациентов...")
        start = time.time()
        
        for i in range(100):
            patient = Patient(
                doctor_id=1,  # Используем существующего врача
                full_name=f"Пациент {i}",
                birth_date=datetime(1960 + random.randint(0, 40), 
                                  random.randint(1, 12), 
                                  random.randint(1, 28)),
                gender=random.choice(["M", "F"]),
                phone=f"+7916{random.randint(1000000, 9999999)}"
            )
            db.add_patient(patient)
        
        elapsed = time.time() - start
        print(f"   ✅ 100 пациентов за {elapsed:.2f} сек ({100/elapsed:.1f} зап/сек)")
        
        # 2. Тест поиска
        print("\n2. Тест поиска пациентов...")
        start = time.time()
        
        patients = db.search_patients(1, "Пациент", limit=50)
        
        elapsed = time.time() - start
        print(f"   ✅ Поиск 50 пациентов за {elapsed:.4f} сек")
        
        # 3. Тест добавления записей
        print("\n3. Тест добавления медицинских записей...")
        start = time.time()
        
        for patient_id in range(1, 101):
            for j in range(10):  # 10 записей на пациента
                record = MedicalRecord(
                    patient_id=patient_id,
                    doctor_id=1,  # Используем существующего врача
                    record_type=random.choice(["examination", "complaint", "diagnosis"]),
                    encrypted_content=crypto.encrypt(f"Запись {j} для пациента {patient_id}", key),
                    tags=[f"тег_{k}" for k in range(3)]
                )
                db.add_medical_record(record)
        
        elapsed = time.time() - start
        print(f"   ✅ 1000 записей за {elapsed:.2f} сек ({1000/elapsed:.1f} зап/сек)")
        
        # 4. Тест получения записей с пагинацией
        print("\n4. Тест получения записей с пагинацией...")
        start = time.time()
        
        records = db.get_patient_records(1, limit=100)
        
        elapsed = time.time() - start
        print(f"   ✅ 100 записей пациента за {elapsed:.4f} сек")
        
        # 5. Тест статистики
        print("\n5. Тест получения статистики...")
        start = time.time()
        
        stats = db.get_statistics(1)
        
        elapsed = time.time() - start
        print(f"   ✅ Статистика за {elapsed:.4f} сек")
        print(f"   📊 Пациентов: {stats['total_patients']}")
        print(f"   📊 Записей за месяц: {stats['records_last_month']}")
        
        print("\n" + "=" * 60)
        print("🎉 Все тесты производительности завершены успешно!")
        
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        
        # Выводим отладочную информацию
        print("\n🔧 Отладочная информация:")
        cursor = db.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM doctors")
        print(f"   Врачей в БД: {cursor.fetchone()[0]}")
        cursor.execute("SELECT id, username FROM doctors")
        for row in cursor.fetchall():
            print(f"   Врач: ID={row['id']}, username={row['username']}")
    
    finally:
        db.close()
        
        # Удаляем тестовую БД
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print("\n🧹 Тестовая БД удалена")

if __name__ == "__main__":
    test_performance()