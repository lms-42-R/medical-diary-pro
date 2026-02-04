"""
Менеджер доступа в памяти (для тестирования и разработки)

В production следует использовать DatabaseAccessManager
"""

import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from ..interfaces import AccessManager
from ..types import AccessSession


class MemoryAccessManager(AccessManager):
    """
    Менеджер доступа в памяти (не сохраняется между запусками)
    
    Используется для:
    - Тестирования
    - Разработки
    - Демонстрации
    
    Не использовать в production!
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация менеджера доступа в памяти
        
        Args:
            config: Конфигурация менеджера
        """
        self.config = config or {}
        
        # Хранилище сессий в памяти
        self._sessions: Dict[str, AccessSession] = {}
        
        # Хранилище логов доступа в памяти
        self._access_logs: List[Dict[str, Any]] = []
        
        # Параметры по умолчанию
        self.default_session_hours = self.config.get('default_session_hours', 8)
        self.max_log_entries = self.config.get('max_log_entries', 10000)
    
    def create_session(self, doctor_id: int, patient_id: int, 
                      access_type: str = 'view',
                      permissions: Optional[Dict[str, bool]] = None,
                      duration_hours: int = 8) -> AccessSession:
        """
        Создание сессии доступа врача к данным пациента
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            access_type: Тип доступа ('view', 'edit', 'emergency')
            permissions: Специфичные права доступа
            duration_hours: Длительность сессии в часах
            
        Returns:
            AccessSession: Созданная сессия доступа
        """
        # Генерация ID сессии
        session_id = f"session_{doctor_id}_{patient_id}_{secrets.token_hex(8)}"
        
        # Права доступа по умолчанию
        if permissions is None:
            permissions = self._get_default_permissions(access_type)
        
        # Создаем сессию
        session = AccessSession(
            session_id=session_id,
            doctor_id=doctor_id,
            patient_id=patient_id,
            encrypted_session_key=secrets.token_bytes(32),  # Временный ключ
            access_type=access_type,
            permissions=permissions,
            expires_at=datetime.now() + timedelta(hours=duration_hours)
        )
        
        # Сохраняем в хранилище
        self._sessions[session_id] = session
        
        # Логируем создание сессии
        self.log_access(
            doctor_id=doctor_id,
            patient_id=patient_id,
            action='create_session',
            details={
                'session_id': session_id,
                'access_type': access_type,
                'duration_hours': duration_hours
            }
        )
        
        return session
    
    def validate_session(self, session_id: str) -> bool:
        """
        Проверка валидности сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия активна и не истекла
        """
        session = self.get_session(session_id)
        
        if not session:
            return False
        
        if not session.is_active:
            return False
        
        if session.is_expired():
            # Автоматически отзываем истекшие сессии
            self.revoke_session(session_id)
            return False
        
        return True
    
    def get_session(self, session_id: str) -> Optional[AccessSession]:
        """
        Получение сессии по ID
        
        Args:
            session_id: ID сессии
            
        Returns:
            Optional[AccessSession]: Сессия или None если не найдена
        """
        session = self._sessions.get(session_id)
        
        if session and session.is_active:
            # Обновляем время последнего использования только для активных сессий
            session.last_used = datetime.now()
        
        return session
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Отзыв (завершение) сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            bool: True если сессия была активна и успешно отозвана
        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            
            # Проверяем что сессия еще активна
            if not session.is_active:
                return False
            
            # Деактивируем сессию
            session.is_active = False
            
            # Логируем отзыв
            self.log_access(
                doctor_id=session.doctor_id,
                patient_id=session.patient_id,
                action='revoke_session',
                details={'session_id': session_id}
            )
            
            return True
        
        return False
    
    def revoke_all_sessions(self, doctor_id: int, patient_id: Optional[int] = None) -> int:
        """
        Отзыв всех сессий врача (при смене пароля и т.д.)
        
        Args:
            doctor_id: ID врача
            patient_id: Опционально - конкретный пациент
            
        Returns:
            int: Количество отозванных сессий
        """
        revoked_count = 0
        
        # Находим все активные сессии врача
        for session_id, session in self._sessions.items():
            if session.doctor_id == doctor_id and session.is_active:
                if patient_id is None or session.patient_id == patient_id:
                    if self.revoke_session(session_id):
                        revoked_count += 1
        
        # Логируем массовый отзыв
        self.log_access(
            doctor_id=doctor_id,
            patient_id=patient_id or 0,
            action='revoke_all_sessions',
            details={
                'patient_specific': patient_id is not None,
                'revoked_count': revoked_count
            }
        )
        
        return revoked_count
    
    def log_access(self, doctor_id: int, patient_id: int, 
                  action: str, record_type: Optional[str] = None,
                  success: bool = True, details: Optional[Dict] = None):
        """
        Логирование доступа к данным
        
        Args:
            doctor_id: ID врача
            patient_id: ID пациента
            action: Действие ('view', 'edit', 'delete', 'export')
            record_type: Тип записи (если применимо)
            success: Успешно ли действие
            details: Дополнительные детали
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'doctor_id': doctor_id,
            'patient_id': patient_id,
            'action': action,
            'record_type': record_type,
            'success': success,
            'details': details or {},
            'ip_address': '127.0.0.1',  # В production брать из запроса
            'user_agent': 'test'  # В production брать из запроса
        }
        
        self._access_logs.append(log_entry)
        
        # Ограничиваем размер логов
        if len(self._access_logs) > self.max_log_entries:
            self._access_logs = self._access_logs[-self.max_log_entries:]
    
    def get_access_logs(self, filters: Optional[Dict[str, Any]] = None,
                       limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Получение логов доступа с фильтрацией
        
        Args:
            filters: Фильтры
            limit: Максимальное количество записей
            offset: Смещение
            
        Returns:
            List[Dict]: Отфильтрованные логи доступа
        """
        filtered_logs = self._access_logs
        
        if filters:
            for key, value in filters.items():
                if key == 'doctor_id':
                    filtered_logs = [log for log in filtered_logs if log['doctor_id'] == value]
                elif key == 'patient_id':
                    filtered_logs = [log for log in filtered_logs if log['patient_id'] == value]
                elif key == 'action':
                    filtered_logs = [log for log in filtered_logs if log['action'] == value]
                elif key == 'date_from':
                    date_from = datetime.fromisoformat(value)
                    filtered_logs = [log for log in filtered_logs 
                                   if datetime.fromisoformat(log['timestamp']) >= date_from]
                elif key == 'date_to':
                    date_to = datetime.fromisoformat(value)
                    filtered_logs = [log for log in filtered_logs 
                                   if datetime.fromisoformat(log['timestamp']) <= date_to]
        
        # Применяем пагинацию
        start = offset
        end = offset + limit
        
        return filtered_logs[start:end]
    
    def get_active_sessions(self, doctor_id: Optional[int] = None,
                           patient_id: Optional[int] = None) -> List[AccessSession]:
        """
        Получение активных сессий
        
        Args:
            doctor_id: Опционально - фильтр по врачу
            patient_id: Опционально - фильтр по пациенту
            
        Returns:
            List[AccessSession]: Список активных сессий
        """
        active_sessions = []
        
        for session in self._sessions.values():
            # Проверяем что сессия активна и не истекла
            if not session.is_active:
                continue
            
            if session.is_expired():
                # Автоматически отзываем истекшие сессии
                self.revoke_session(session.session_id)
                continue
            
            if doctor_id is not None and session.doctor_id != doctor_id:
                continue
            
            if patient_id is not None and session.patient_id != patient_id:
                continue
            
            active_sessions.append(session)
        
        return active_sessions
    
    def cleanup_expired_sessions(self) -> int:
        """
        Очистка истекших сессий
        
        Returns:
            int: Количество очищенных сессий
        """
        expired_count = 0
        
        for session_id, session in list(self._sessions.items()):
            if session.is_expired() and session.is_active:
                if self.revoke_session(session_id):
                    expired_count += 1
        
        return expired_count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Получение статистики менеджера доступа
        
        Returns:
            Dict: Статистика
        """
        active_sessions = self.get_active_sessions()
        active_count = len(active_sessions)
        total_count = len(self._sessions)
        
        return {
            'total_sessions': total_count,
            'active_sessions': active_count,
            'expired_sessions': total_count - active_count,
            'access_logs_count': len(self._access_logs),
            'max_log_entries': self.max_log_entries
        }
    
    def _get_default_permissions(self, access_type: str) -> Dict[str, bool]:
        """
        Получение прав доступа по умолчанию для типа доступа
        
        Args:
            access_type: Тип доступа
            
        Returns:
            Dict: Права доступа
        """
        if access_type == 'view':
            return {
                'view_patient_info': True,
                'view_medical_records': True,
                'view_measurements': True,
                'view_prescriptions': True,
                'edit_records': False,
                'create_records': False,
                'delete_records': False,
                'export_data': False
            }
        elif access_type == 'edit':
            return {
                'view_patient_info': True,
                'view_medical_records': True,
                'view_measurements': True,
                'view_prescriptions': True,
                'edit_records': True,
                'create_records': True,
                'delete_records': False,
                'export_data': True
            }
        elif access_type == 'emergency':
            return {
                'view_patient_info': True,
                'view_medical_records': True,
                'view_measurements': True,
                'view_prescriptions': True,
                'edit_records': True,
                'create_records': True,
                'delete_records': True,
                'export_data': True,
                'emergency_access': True
            }
        else:
            return {}