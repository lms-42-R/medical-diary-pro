#!/usr/bin/env python3
"""
Тестирование генератора медицинских данных
"""

import sys
import os

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    print("=" * 60)
    print("Medical Diary Pro - Генератор тестовых данных")
    print("=" * 60)
    
    # Проверяем зависимости
    try:
        from core.data_generator import MedicalDataGenerator
        from core.database import MedicalDatabase
        from core.crypto import DataCrypto
        
        print("✅ Все модули загружены успешно")
        
    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        print("\nУбедитесь что:")
        print("1. Вы в корневой папке проекта")
        print("2. Все модули существуют")
        return 1
    
    # Создаём БД для теста
    test_db = "test_medical_data.db"
    
    if os.path.exists(test_db):
        choice = input(f"\nФайл {test_db} уже существует. Удалить? (y/n): ")
        if choice.lower() == 'y':
            os.remove(test_db)
            print("🗑️ Старая БД удалена")
        else:
            print("ℹ️ Используем существующую БД")
    
    print("\n🧬 Создание тестовой базы данных...")
    
    try:
        # Создаём БД
        db = MedicalDatabase(test_db)
        
        # Создаём генератор
        generator = MedicalDataGenerator()
        
        # Заполняем БД данными
        print("\n" + "=" * 50)
        print("ГЕНЕРАЦИЯ ТЕСТОВЫХ ДАННЫХ")
        print("=" * 50)
        
        num_patients = input("Сколько пациентов сгенерировать? (по умолчанию 20): ").strip()
        num_patients = int(num_patients) if num_patients.isdigit() else 20
        
        stats = generator.populate_database(db, num_patients=num_patients)
        
        # Экспортируем в JSON для проверки
        print("\n📁 Экспорт данных в JSON...")
        generator.export_to_json(db, "test_data_sample.json")
        
        # Показываем пример данных
        print("\n👁️ Просмотр примеров данных:")
        
        conn = db.connect()
        cursor = conn.cursor()
        
        # Пример пациента
        cursor.execute("SELECT full_name, birth_date, gender FROM patients LIMIT 1")
        patient = cursor.fetchone()
        print(f"👤 Пример пациента: {patient['full_name']}, {patient['gender']}, {patient['birth_date']}")
        
        # Пример записи
        cursor.execute("""
        SELECT mr.id, p.full_name, mr.record_type, mr.created_at 
        FROM medical_records mr
        JOIN patients p ON mr.patient_id = p.id
        LIMIT 1
        """)
        record = cursor.fetchone()
        print(f"📝 Пример записи: {record['full_name']}, {record['record_type']}, {record['created_at']}")
        
        # Пример измерения
        cursor.execute("""
        SELECT m.measurement_type, m.value, m.unit, p.full_name
        FROM measurements m
        JOIN patients p ON m.patient_id = p.id
        LIMIT 1
        """)
        measurement = cursor.fetchone()
        print(f"📊 Пример измерения: {measurement['full_name']}, {measurement['measurement_type']}: {measurement['value']} {measurement['unit']}")
        
        db.close()
        
        print("\n" + "=" * 50)
        print("✅ ТЕСТОВЫЕ ДАННЫЕ УСПЕШНО СОЗДАНЫ!")
        print("=" * 50)
        print(f"\n📋 Итоги:")
        print(f"   Файл БД: {test_db}")
        print(f"   Файл экспорта: test_data_sample.json")
        print(f"   Пациентов: {stats['patients']}")
        print(f"   Записей: {stats['records']}")
        print(f"   Измерений: {stats['measurements']}")
        print(f"   Назначений: {stats['prescriptions']}")
        
        print("\n🔧 Для использования в разработке:")
        print(f"   db = MedicalDatabase('{test_db}')")
        print("   patients = db.get_patients_by_doctor(1)")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())