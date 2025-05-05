import pickle
from multiprocessing import Process, Queue
from queue import Empty
from time import sleep
from pathlib import Path
from typing import Optional
from geopy import Point as GeoPoint

from cryptography.fernet import Fernet

from src.config import (
    COMMUNICATION_GATEWAY_QUEUE_NAME,
    CONTROL_SYSTEM_QUEUE_NAME,
    SAFETY_BLOCK_QUEUE_NAME,
    CRITICALITY_STR,
    DEFAULT_LOG_LEVEL,
    LOG_DEBUG, LOG_INFO, LOG_ERROR,
)
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission


class BaseCommunicationGateway(Process):
    """Компонент связи, получающий и расшифровывающий зашифрованные маршрутные задания"""

    log_prefix = "[COMMUNICATION]"
    events_q_name = COMMUNICATION_GATEWAY_QUEUE_NAME
    SECRET_KEY_PATH = "secret_key"

    def __init__(self, queues_dir: QueuesDirectory, log_level=DEFAULT_LOG_LEVEL):
        super().__init__()
        self._queues_dir = queues_dir
        self.log_level = log_level

        self._events_q = Queue()
        self._queues_dir.register(self._events_q, name=self.events_q_name)

        self._cipher_key = self._initialize_cipher_key()
        self._cipher = Fernet(self._cipher_key)

        self._control_q = Queue()
        self._quit = False
        self._mission: Optional[Mission] = None

        self._log_message(LOG_INFO, "Компонент связи создан")

    def _log_message(self, criticality: int, message: str):
        """_log_message печатает сообщение заданного уровня критичности

        Args:
            criticality (int): уровень критичности
            message (str): текст сообщения
        """
        if criticality <= self.log_level + 1:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")

    def _initialize_cipher_key(self) -> bytes:
        try:
            with open(self.SECRET_KEY_PATH, 'rb') as f:
                key = f.read()
                self._log_message(LOG_INFO, "Ключ дешифрования загружен")
                return key
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка загрузки ключа: {e}")
            raise

    def _decrypt_mission(self, encrypted_data: bytes) -> Mission:
        try:
            decrypted = self._cipher.decrypt(encrypted_data)
            mission = pickle.loads(decrypted)
            self._log_message(LOG_INFO, "Задание дешифровано")
            return mission
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка при дешифровании: {e}")
            raise

    # def _ensure_waypoints_are_geopoints(self, mission: Mission) -> Mission:
    #     """Проверяет и преобразует точки waypoints в GeoPoint если необходимо"""
    #     if not hasattr(mission, 'waypoints') or not mission.waypoints:
    #         self._log_message(LOG_ERROR, "Миссия не содержит точек маршрута")
    #         return mission
            
    #     for i, wp in enumerate(mission.waypoints):
    #         # Если точка не является GeoPoint, но имеет атрибуты latitude и longitude
    #         if not isinstance(wp, GeoPoint):
    #             try:
    #                 if hasattr(wp, 'latitude') and hasattr(wp, 'longitude'):
    #                     # Создаем новый GeoPoint из существующих координат
    #                     mission.waypoints[i] = GeoPoint(latitude=wp.latitude, longitude=wp.longitude)
    #                     self._log_message(LOG_INFO, f"Точка {i} преобразована в GeoPoint: {mission.waypoints[i]}")
    #                 elif isinstance(wp, (list, tuple)) and len(wp) >= 2:
    #                     # Если точка - список или кортеж координат
    #                     mission.waypoints[i] = GeoPoint(latitude=wp[0], longitude=wp[1])
    #                     self._log_message(LOG_INFO, f"Точка {i} (список/кортеж) преобразована в GeoPoint: {mission.waypoints[i]}")
    #                 elif hasattr(wp, '__getitem__') and 'latitude' in wp and 'longitude' in wp:
    #                     # Если точка - словарь или объект с доступом по ключу
    #                     mission.waypoints[i] = GeoPoint(latitude=wp['latitude'], longitude=wp['longitude'])
    #                     self._log_message(LOG_INFO, f"Точка {i} (словарь) преобразована в GeoPoint: {mission.waypoints[i]}")
    #                 else:
    #                     self._log_message(LOG_ERROR, f"Невозможно преобразовать точку {i}: {wp} (тип {type(wp)})")
    #             except Exception as e:
    #                 self._log_message(LOG_ERROR, f"Ошибка при преобразовании точки {i}: {e}")
        
    #     return mission

    def _handle_event(self, event: Event):
        if event.operation == "set_mission":
            try:
                mission = self._decrypt_mission(event.parameters)
                
                # Проверяем и преобразуем точки в GeoPoint если необходимо
                # mission = self._ensure_waypoints_are_geopoints(mission)
                self._mission = mission
                
                # Подробный лог о миссии после обработки
                self._log_message(LOG_INFO, f"Mission после обработки: {mission}")
                
                # Проверка содержимого waypoints
                if not isinstance(mission.waypoints, list):
                    self._log_message(LOG_ERROR, "mission.waypoints не является списком!")
                else:
                    for i, wp in enumerate(mission.waypoints):
                        if not isinstance(wp, GeoPoint):
                            self._log_message(LOG_ERROR, f"Точка {i} в waypoints не GeoPoint: {wp} (тип {type(wp)})")
                        else:
                            self._log_message(LOG_INFO, f"Точка {i} корректна: {wp}")

                # ВАЖНО: сначала отправляем миссию в модуль безопасности, затем в систему управления
                # Это гарантирует, что safety сможет проверять все команды control
                self._forward_mission_to_safety(mission)
                self._forward_to_control_system(mission)
                
            except Exception as e:
                self._log_message(LOG_ERROR, f"Не удалось обработать задание: {e}")
        else:
            self._log_message(LOG_ERROR, f"Неизвестная операция: {event.operation}")

    def _forward_to_control_system(self, mission: Mission):
        """Отправляет миссию в систему управления"""
        ctrl_q = self._queues_dir.get_queue(CONTROL_SYSTEM_QUEUE_NAME)
        if ctrl_q:
            event = Event(
                source=self.events_q_name,
                destination=CONTROL_SYSTEM_QUEUE_NAME,
                operation="set_mission",
                parameters=mission,
            )
            ctrl_q.put(event)
            self._log_message(LOG_INFO, "Маршрут передан в систему управления")
        else:
            self._log_message(LOG_ERROR, "Очередь CONTROL_SYSTEM не найдена")
    
    def _forward_mission_to_safety(self, mission: Mission):
        """Отправляет полную миссию в модуль safety для инициализации"""
        try:
            safety_q = self._queues_dir.get_queue(SAFETY_BLOCK_QUEUE_NAME)
            if safety_q:
                # Отправляем полную миссию в safety
                event = Event(
                    source=self.events_q_name,
                    destination=SAFETY_BLOCK_QUEUE_NAME,
                    operation="set_mission",  # Согласно политике безопасности
                    parameters=mission,
                )
                safety_q.put(event)
                self._log_message(LOG_INFO, "Миссия передана в модуль безопасности")
                
                # Также отправляем начальную позицию, если есть
                if mission.waypoints and len(mission.waypoints) > 0:
                    initial_position = mission.waypoints[0]
                    position_event = Event(
                        source=self.events_q_name,
                        destination=SAFETY_BLOCK_QUEUE_NAME,
                        operation="position_update",
                        parameters=initial_position,
                    )
                    safety_q.put(position_event)
                    self._log_message(LOG_INFO, f"Начальная позиция {initial_position} передана в модуль безопасности")
            else:
                self._log_message(LOG_ERROR, "Очередь SAFETY не найдена")
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка при отправке в модуль безопасности: {e}")

    def _check_events_q(self):
        try:
            event = self._events_q.get_nowait()
            if isinstance(event, Event):
                self._handle_event(event)
        except Empty:
            pass

    def _check_control_q(self):
        try:
            cmd = self._control_q.get_nowait()
            if isinstance(cmd, ControlEvent) and cmd.operation == "stop":
                self._quit = True
                self._log_message(LOG_INFO, "Получен сигнал остановки")
        except Empty:
            pass

    def stop(self):
        self._control_q.put(ControlEvent(operation="stop"))

    def run(self):
        self._log_message(LOG_INFO, "Компонент связи запущен")
        while not self._quit:
            self._check_events_q()
            self._check_control_q()
        self._log_message(LOG_INFO, "Компонент связи остановлен")