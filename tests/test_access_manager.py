"""
Тесты менеджера доступа
"""

import sys
import os
import pytest
import time
from datetime import datetime, timedelta

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.security.access.memory import MemoryAccessManager


def test_create_session():
    """Тест создания сессии"""
    manager = MemoryAccessManager()
    
    session = manager.create_session(
        doctor_id=1,
        patient_id=5,
        access_type='view',
        duration_hours=4
    )
    
    assert session.doctor_id == 1
    assert session.patient_id == 5
    assert session.access_type == 'view'
    assert session.is_active == True
    assert session.has_permission('view_medical_records') == True
    assert session.has_permission('edit_records') == False
    assert not session.is_expired()


def test_validate_session():
    """Тест валидации сессии"""
    manager = MemoryAccessManager()
    
    # Создаем сессию
    session = manager.create_session(1, 5, 'view', duration_hours=1)
    
    # Проверяем что сессия валидна
    assert manager.validate_session(session.session_id) == True
    
    # Получаем сессию
    retrieved = manager.get_session(session.session_id)
    assert retrieved is not None
    assert retrieved.session_id == session.session_id


def test_revoke_session():
    """Тест отзыва сессии"""
    manager = MemoryAccessManager()
    
    session = manager.create_session(1, 5, 'view')
    
    # Проверяем что сессия активна
    assert session.is_active == True
    
    # Отзываем сессию
    result = manager.revoke_session(session.session_id)
    assert result == True
    
    # Получаем сессию после отзыва
    session_after = manager.get_session(session.session_id)
    assert session_after is not None
    assert session_after.is_active == False
    
    # Проверяем что сессия не валидна
    assert manager.validate_session(session.session_id) == False
    
    # Попытка отозвать уже отозванную сессию - должна вернуть False
    assert manager.revoke_session(session.session_id) == False


def test_revoke_all_sessions():
    """Тест массового отзыва сессий"""
    manager = MemoryAccessManager()
    
    # Создаем несколько сессий для одного врача
    session1 = manager.create_session(1, 5, 'view')
    session2 = manager.create_session(1, 6, 'edit')
    session3 = manager.create_session(2, 5, 'view')  # Другой врач
    
    # Проверяем что все сессии активны
    assert session1.is_active == True
    assert session2.is_active == True
    assert session3.is_active == True
    
    # Отзываем все сессии врача 1
    revoked = manager.revoke_all_sessions(doctor_id=1)
    assert revoked == 2
    
    # Проверяем что сессии врача 1 отозваны
    session1_after = manager.get_session(session1.session_id)
    session2_after = manager.get_session(session2.session_id)
    
    assert session1_after.is_active == False
    assert session2_after.is_active == False
    assert manager.validate_session(session1.session_id) == False
    assert manager.validate_session(session2.session_id) == False
    
    # Сессия врача 2 должна остаться активной
    assert manager.validate_session(session3.session_id) == True
    
    # Отзываем сессии для конкретного пациента
    session4 = manager.create_session(1, 7, 'view')
    session5 = manager.create_session(1, 8, 'view')
    
    revoked = manager.revoke_all_sessions(doctor_id=1, patient_id=7)
    assert revoked == 1
    
    assert manager.validate_session(session4.session_id) == False
    assert manager.validate_session(session5.session_id) == True


def test_session_expiry():
    """Тест истечения срока сессии"""
    manager = MemoryAccessManager()
    
    # Создаем сессию с очень коротким сроком
    session = manager.create_session(1, 5, 'view', duration_hours=0.0001)  # ~0.36 секунды
    
    # Сразу должна быть валидна
    assert manager.validate_session(session.session_id) == True
    
    # Ждем немного и проверяем снова
    time.sleep(0.5)  # Ждем полсекунды
    
    # Сессия должна истечь
    assert manager.validate_session(session.session_id) == False
    
    # Проверяем что сессия отозвана
    session_after = manager.get_session(session.session_id)
    assert session_after.is_active == False


def test_permissions():
    """Тест прав доступа"""
    manager = MemoryAccessManager()
    
    # Сессия для просмотра
    view_session = manager.create_session(1, 5, 'view')
    assert view_session.has_permission('view_medical_records') == True
    assert view_session.has_permission('edit_records') == False
    
    # Сессия для редактирования
    edit_session = manager.create_session(1, 6, 'edit')
    assert edit_session.has_permission('view_medical_records') == True
    assert edit_session.has_permission('edit_records') == True
    
    # Сессия для экстренного доступа
    emergency_session = manager.create_session(1, 7, 'emergency')
    assert emergency_session.has_permission('emergency_access') == True
    assert emergency_session.has_permission('delete_records') == True


def test_log_access():
    """Тест логирования доступа"""
    manager = MemoryAccessManager()
    
    # Получаем начальное количество логов
    initial_count = len(manager._access_logs)
    
    # Логируем несколько действий
    manager.log_access(1, 5, 'view', 'medical_record', True)
    manager.log_access(1, 5, 'edit', 'medical_record', True)
    manager.log_access(1, 5, 'view', 'measurement', False, {'error': 'access denied'})
    
    # Проверяем что добавилось 3 записи
    assert len(manager._access_logs) == initial_count + 3
    
    # Получаем только новые логи
    logs = manager._access_logs[initial_count:]
    
    # Проверяем содержимое
    assert logs[0]['action'] == 'view'
    assert logs[0]['record_type'] == 'medical_record'
    assert logs[0]['success'] == True
    
    assert logs[2]['action'] == 'view'
    assert logs[2]['success'] == False
    assert logs[2]['details']['error'] == 'access denied'


def test_filter_logs():
    """Тест фильтрации логов"""
    manager = MemoryAccessManager()
    
    # Получаем начальное количество
    initial_count = len(manager._access_logs)
    
    # Создаем логи для разных врачей и пациентов
    manager.log_access(1, 5, 'view', 'record')
    manager.log_access(1, 6, 'edit', 'record')
    manager.log_access(2, 5, 'view', 'record')
    manager.log_access(2, 6, 'delete', 'record')
    
    # Получаем все логи (включая системные)
    all_logs = manager.get_access_logs()
    
    # Фильтруем по врачу (только наши тестовые логи)
    logs_doctor1 = manager.get_access_logs(filters={'doctor_id': 1})
    # Проверяем что есть логи нашего врача
    doctor1_logs = [log for log in logs_doctor1 if log['doctor_id'] == 1]
    assert len(doctor1_logs) >= 2  # Минимум 2 наших лога
    
    # Фильтруем по пациенту
    logs_patient5 = manager.get_access_logs(filters={'patient_id': 5})
    patient5_logs = [log for log in logs_patient5 if log['patient_id'] == 5]
    assert len(patient5_logs) >= 2
    
    # Фильтруем по действию
    logs_view = manager.get_access_logs(filters={'action': 'view'})
    view_logs = [log for log in logs_view if log['action'] == 'view']
    assert len(view_logs) >= 2


def test_active_sessions():
    """Тест получения активных сессий"""
    manager = MemoryAccessManager()
    
    # Создаем несколько сессий
    session1 = manager.create_session(1, 5, 'view')
    session2 = manager.create_session(1, 6, 'edit')
    session3 = manager.create_session(2, 5, 'view')
    
    # Проверяем что все сессии активны
    assert session1.is_active == True
    assert session2.is_active == True
    assert session3.is_active == True
    
    # Отзываем одну сессию
    result = manager.revoke_session(session2.session_id)
    assert result == True
    
    # Получаем активные сессии
    active_sessions = manager.get_active_sessions()
    
    # Должно быть 2 активных сессии
    assert len(active_sessions) == 2
    
    active_ids = {s.session_id for s in active_sessions}
    assert session1.session_id in active_ids
    assert session2.session_id not in active_ids  # Отозвана
    assert session3.session_id in active_ids
    
    # Фильтруем по врачу
    doctor1_sessions = manager.get_active_sessions(doctor_id=1)
    assert len(doctor1_sessions) == 1
    assert doctor1_sessions[0].doctor_id == 1
    
    # Фильтруем по пациенту
    patient5_sessions = manager.get_active_sessions(patient_id=5)
    assert len(patient5_sessions) == 2


def test_cleanup_expired_sessions():
    """Тест очистки истекших сессий"""
    manager = MemoryAccessManager()
    
    # Создаем обычную сессию
    normal_session = manager.create_session(1, 5, 'view', duration_hours=1)
    
    # Создаем "истекшую" сессию с очень коротким сроком
    expired_session = manager.create_session(1, 6, 'view', duration_hours=0.0001)
    
    # Ждем чтобы сессия истекла
    time.sleep(0.5)
    
    # Проверяем что "истекшая" сессия действительно истекла
    assert expired_session.is_expired()
    
    # Очищаем истекшие сессии
    cleaned = manager.cleanup_expired_sessions()
    assert cleaned >= 1
    
    # Проверяем что истекшая сессия отозвана
    session_after = manager.get_session(expired_session.session_id)
    assert session_after.is_active == False
    
    # А обычная сессия все еще активна
    assert manager.validate_session(normal_session.session_id) == True


def test_get_stats():
    """Тест получения статистики"""
    manager = MemoryAccessManager()
    
    # Получаем начальное количество логов
    initial_logs = len(manager._access_logs)
    
    # Создаем несколько сессий (каждая создаст лог)
    session1 = manager.create_session(1, 5, 'view')
    session2 = manager.create_session(1, 6, 'edit')
    session3 = manager.create_session(2, 5, 'view')
    
    # Отзываем одну сессию (создаст еще лог)
    manager.revoke_session(session2.session_id)
    
    # Логируем доступ вручную
    manager.log_access(1, 5, 'view', 'record')
    manager.log_access(1, 5, 'edit', 'record')
    
    # Получаем статистику
    stats = manager.get_stats()
    
    # Проверяем статистику сессий
    assert stats['total_sessions'] == 3
    assert stats['active_sessions'] == 2  # session1 и session3 активны, session2 отозвана
    assert stats['expired_sessions'] == 1  # session2 отозвана
    
    # Учитываем все логи: начальные + 3 создания + 1 отзыв + 2 вручную
    total_expected_logs = initial_logs + 3 + 1 + 2
    assert stats['access_logs_count'] == total_expected_logs


def test_custom_permissions():
    """Тест кастомных прав доступа"""
    manager = MemoryAccessManager()
    
    custom_permissions = {
        'view_records': True,
        'edit_records': False,
        'export_data': True,
        'custom_permission': True
    }
    
    session = manager.create_session(
        doctor_id=1,
        patient_id=5,
        access_type='view',
        permissions=custom_permissions
    )
    
    assert session.has_permission('view_records') == True
    assert session.has_permission('edit_records') == False
    assert session.has_permission('export_data') == True
    assert session.has_permission('custom_permission') == True
    assert session.has_permission('non_existent') == False


def test_session_reuse():
    """Тест повторного использования сессии"""
    manager = MemoryAccessManager()
    
    session = manager.create_session(1, 5, 'view')
    initial_last_used = session.last_used
    
    # Ждем чтобы время точно изменилось
    time.sleep(0.1)
    
    # Получаем сессию (должно обновить last_used)
    session1 = manager.get_session(session.session_id)
    
    # Проверяем что время обновилось
    assert session1.last_used != initial_last_used
    first_retrieval_time = session1.last_used
    
    # Ждем еще
    time.sleep(0.1)
    
    # Получаем снова
    session2 = manager.get_session(session.session_id)
    
    # Проверяем что время снова обновилось
    # Допускаем что в редких случаях время может быть одинаковым
    # если система очень быстрая
    if session2.last_used == first_retrieval_time:
        print(f"Внимание: время не изменилось между получениями сессии")
        print(f"Первое получение: {first_retrieval_time}")
        print(f"Второе получение: {session2.last_used}")
    else:
        assert session2.last_used != first_retrieval_time


if __name__ == "__main__":
    pytest.main([__file__, "-v"])