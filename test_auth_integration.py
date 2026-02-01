# test_auth_integration.py
"""
Интеграционный тест аутентификации с существующей БД
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.auth import AuthManager, get_auth_manager
from core.database import MedicalDatabase

def test_auth_integration():
    print("🔐 Интеграционный тест аутентификации с БД")
    print("=" * 60)
    
    # Используем существующую тестовую БД или создаём новую
    test_db = "auth_integration_test.db"
    
    if os.path.exists(test_db):
        choice = input(f"Файл {test_db} уже существует. Удалить? (y/n): ")
        if choice.lower() == 'y':
            os.remove(test_db)
            print("🗑️ Старая БД удалена")
        else:
            print("ℹ️ Используем существующую БД")
    
    # Создаём БД
    db = MedicalDatabase(test_db)
    
    # Получаем менеджер аутентификации
    auth = get_auth_manager()
    
    try:
        print("\n1. Регистрация тестового врача...")
        
        # Регистрируем врача
        doctor_id = auth.register_doctor(
            db.connection,
            username="integration_test_doctor",
            password="TestPass123!",
            full_name="Доктор Интеграционный Тест",
            specialization="Интеграционная терапия"
        )
        
        print(f"   ✅ Врач зарегистрирован: ID={doctor_id}")
        
        print("\n2. Аутентификация врача...")
        
        # Аутентифицируем
        doc_id, username, token = auth.authenticate_doctor(
            db.connection,
            username="integration_test_doctor",
            password="TestPass123!"
        )
        
        print(f"   ✅ Аутентификация успешна")
        print(f"   Получен токен: {token[:50]}...")
        
        print("\n3. Проверка токена...")
        
        # Проверяем токен
        payload = auth.verify_token(token)
        print(f"   ✅ Токен валиден")
        print(f"   Doctor ID в токене: {payload['doctor_id']}")
        print(f"   Username в токене: {payload['username']}")
        
        print("\n4. Интеграция с генератором данных...")
        
        # Импортируем генератор
        from core.data_generator import MedicalDataGenerator
        from core.crypto import DataCrypto
        
        generator = MedicalDataGenerator()
        crypto = DataCrypto()
        crypto_key = crypto.derive_key("test_key")
        
        # Генерируем пациента для этого врача
        patient = generator.generate_patient(1, doctor_id=doctor_id)
        patient_id = db.add_patient(patient)
        
        print(f"   ✅ Пациент создан для врача {doctor_id}")
        print(f"   Имя пациента: {patient.full_name}")
        
        print("\n5. Проверка доступа к данным...")
        
        # Получаем пациентов врача
        patients = db.get_patients_by_doctor(doctor_id)
        print(f"   ✅ Пациенты получены: {len(patients)} пациент(ов)")
        
        for p in patients[:3]:  # Показываем первых 3
            print(f"      - {p.full_name} (возраст: {p.age})")
        
        print("\n6. Тест смены пароля...")
        
        try:
            success = auth.change_password(
                db.connection,
                doctor_id=doctor_id,
                old_password="TestPass123!",
                new_password="NewSecurePass456!"
            )
            
            if success:
                print("   ✅ Пароль успешно изменён")
                
                # Пробуем аутентифицироваться с новым паролем
                try:
                    auth.authenticate_doctor(
                        db.connection,
                        username="integration_test_doctor",
                        password="NewSecurePass456!"
                    )
                    print("   ✅ Аутентификация с новым паролем успешна")
                except Exception as e:
                    print(f"   ❌ Ошибка аутентификации: {e}")
        
        except Exception as e:
            print(f"   ❌ Ошибка смены пароля: {e}")
        
        print("\n7. Тест сложности пароля...")
        
        test_cases = [
            ("123", "Слишком короткий"),
            ("password", "Слишком простой"),
            ("PASSWORD123", "Нет строчных букв"),
            ("password123", "Нет заглавных букв"),
            ("GoodPass123", "Валидный пароль")
        ]
        
        for password, description in test_cases:
            is_valid, message = auth.validate_password_strength(password)
            status = "✅" if is_valid else "❌"
            print(f"   {status} '{password}': {message} ({description})")
        
        print("\n" + "=" * 60)
        print("🎉 Интеграционный тест пройден успешно!")
        
        # Сохраняем тестовые данные
        print(f"\n📋 Тестовые данные:")
        print(f"   БД: {test_db}")
        print(f"   Врач: integration_test_doctor / NewSecurePass456!")
        print(f"   Пациентов: {len(patients)}")
        
        # Предлагаем оставить БД для дальнейших тестов
        choice = input(f"\nСохранить тестовую БД {test_db}? (y/n): ")
        if choice.lower() != 'y':
            db.close()
            os.remove(test_db)
            print("🗑️ Тестовая БД удалена")
        else:
            print("💾 Тестовая БД сохранена")
        
    except Exception as e:
        print(f"\n❌ Ошибка: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        
        # Убираем за собой в случае ошибки
        db.close()
        if os.path.exists(test_db):
            os.remove(test_db)
    
    finally:
        if 'db' in locals():
            db.close()

if __name__ == "__main__":
    test_auth_integration()