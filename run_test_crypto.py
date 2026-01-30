#!/usr/bin/env python3
"""
Medical Diary Pro - Простая проверка
"""

import sys
import os

# ВСЁ ГЕНИАЛЬНОЕ - ПРОСТО
# Просто добавляем текущую папку в путь поиска модулей
sys.path.append('.')  # ← ВОТ И ВСЁ!

print("=" * 60)
print("Medical Diary Pro - Проверка")
print("=" * 60)

# 1. Проверяем cryptography
print("\n1. Проверяем cryptography:")
try:
    import cryptography
    print(f"   ✅ cryptography {cryptography.__version__} - OK")
except ImportError:
    print("   ❌ cryptography НЕ УСТАНОВЛЕН")
    print("   Установите: pip install cryptography")
    sys.exit(1)

# 2. Проверяем наш модуль
print("\n2. Проверяем наш crypto модуль:")
try:
    # Просто импортируем
    from core.crypto import DataCrypto
    
    # Тестируем
    crypto = DataCrypto()
    if crypto.test_encryption():
        print("   ✅ Криптомодуль работает!")
    else:
        print("   ❌ Криптомодуль не работает!")
        sys.exit(1)
        
except ImportError as e:
    print(f"   ❌ Ошибка импорта: {e}")
    print(f"\n   Проверьте структуру проекта:")
    print(f"   Текущая папка: {os.getcwd()}")
    print(f"   Файлы в папке: {os.listdir('.')}")
    
    if 'core' in os.listdir('.'):
        print(f"   Файлы в core/: {os.listdir('core')}")
    
    sys.exit(1)
except Exception as e:
    print(f"   ❌ Ошибка: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ ВСЁ РАБОТАЕТ! Можно продолжать разработку.")
print("=" * 60)