""" модуль работы с маршрутным заданием
"""
from time import sleep
from queue import Empty
from typing import Optional, List
from multiprocessing import Queue, Process
from geopy import Point

from src.config import CRITICALITY_STR, LOG_DEBUG, \
    LOG_ERROR, LOG_INFO, PLANNER_QUEUE_NAME, DEFAULT_LOG_LEVEL, MISSION_SENDER_QUEUE_NAME
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission


class MissionPlanner(Process):
    """MissionPlanner обработчик и хранитель маршрутного задания
       как и остальные компоненты работает в отдельном процессе
    """
    log_prefix = "[MISSION PLANNER]"
    event_source_name = PLANNER_QUEUE_NAME
    event_q_name = event_source_name
    log_level = DEFAULT_LOG_LEVEL

    def __init__(
            self, queues_dir: QueuesDirectory, afcs_present: bool = False, mission: Mission = None):
        # вызываем конструктор базового класса
        super().__init__()

        self._queues_dir = queues_dir

        # создаём очередь для сообщений на обработку
        self._events_q = Queue()
        self._events_q_name = MissionPlanner.event_q_name
        self._queues_dir.register(
            queue=self._events_q, name=self._events_q_name)
        # инициализируем интервал обновления
        self._recalc_interval_sec = 0.1

        self._quit = False
        # очередь управляющих команд (например, для остановки работы модуля)
        self._control_q = Queue()

        # есть ли система управления парком автомобилей
        # (нужно ли отправлять туда маршрутное задание)
        self._is_afcs_present = afcs_present

        # маршрут для движения
        self._mission: Optional[Mission] = None

        if mission is not None:
            # устанавливаем правильным образом
            self.set_new_mission(mission)

        self._log_message(LOG_INFO, "создана система планирования заданий")

    def _log_message(self, criticality: int, message: str):
        """_log_message печатает сообщение заданного уровня критичности

        Args:
            criticality (int): уровень критичности
            message (str): текст сообщения
        """
        if criticality <= self.log_level:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")

    def _get_mission(self) -> Optional[Mission]:
        self._log_message(LOG_INFO, "получен запрос новой миссии")
        return self._mission

    def _status_update(self, telemetry):
        self._log_message(LOG_INFO, f"получен новый статус: {telemetry}")

    def set_new_mission(
            self, mission: Mission = None, home: Point = None,
            waypoints: Optional[List] = None,
            speed_limits: Optional[List] = None,
            arm: bool = False):
        """set_new_mission установка нового маршрутного задания

        Args:
            mission (Mission): полное описание маршрутного задания

            альтернативный способ задания:

            home (Point): стартовая точка
            waypoints (List[Point]): путевые точки
            speed_limits (List[): скоростные ограничения

            arm (bool, optional): разрешение на выезд. Defaults to False.
        """
        if mission is None:
            mission = Mission(home=home, waypoints=waypoints,
                              speed_limits=speed_limits, armed=arm)

        event = Event(source=MissionPlanner.event_source_name,
                      destination=MissionPlanner.event_q_name, operation="set_mission",
                      parameters=mission)
        self._events_q.put(event)
        self._log_message(LOG_DEBUG, f"запрошена новая задача: {mission}")

    def _set_mission(self, mission: Mission):
        self._mission = mission
        self._log_message(
            LOG_DEBUG, f"установлена новая задача: {self._mission}")
        self._log_message(
            LOG_INFO, "запрошена новая задача, отправляем получателям")
        self._send_mission_to_communication_gateway()
        if self._is_afcs_present:
            # если есть система управления парком автомобилей,
            # отправим туда полученное маршрутное задание
            self._send_mission_to_afcs(mission)

    def _send_mission_to_afcs(self, mission: Mission):
        """ отправить новую миссию в СУПА
        """
        try:
            afcs_q = self._queues_dir.get_queue(MISSION_SENDER_QUEUE_NAME)
            event = Event(source=self.event_source_name,
                          destination=MISSION_SENDER_QUEUE_NAME, operation="post_mission",
                          parameters=mission)
            afcs_q.put(event)
        except Exception as e:
            self._log_message(
                LOG_ERROR, f"ошибка отправки миссии по mqtt: {e}")

    def _send_mission_to_communication_gateway(self):
        tls_terminator_q_name = "tls_terminator"
        event = Event(source=MissionPlanner.event_source_name,
                    destination=tls_terminator_q_name,
                    operation="set_mission", parameters=self._mission
                    )
        tls_terminator_q: Queue = self._queues_dir.get_queue(
            tls_terminator_q_name)
        try:
            tls_terminator_q.put(event)
            self._log_message(
                LOG_INFO, "новая задача отправлена в TLS терминатор")
        except Exception as e:
            self._log_message(
                LOG_ERROR, f"ошибка отправки задачи в TLS терминатор: {e}")
            
    # проверка наличия новых управляющих команд
    def _check_control_q(self):
        try:
            request: ControlEvent = self._control_q.get_nowait()
            self._log_message(LOG_DEBUG, f"проверяем запрос {request}")
            if isinstance(request, ControlEvent) and request.operation == 'stop':
                # поступил запрос на остановку монитора, поднимаем "красный флаг"
                self._quit = True
        except Empty:
            # никаких команд не поступило, ну и ладно
            pass

    def _check_events_q(self):
        try:
            event: Event = self._events_q.get_nowait()
            if not isinstance(event, Event):
                return
            if event.operation == 'set_mission':
                try:
                    self._set_mission(event.parameters)
                except Exception as e:
                    self._log_message(
                        LOG_ERROR, f"ошибка отправки координат: {e}")
        except Empty:
            # никаких команд не поступило, ну и ладно
            pass

    def stop(self):
        """ запрос на остановку работы """
        self._control_q.put(ControlEvent(operation='stop'))

    def run(self):
        """ начало работы """
        self._log_message(LOG_INFO, "старт системы планирования заданий")

        while self._quit is False:
            sleep(self._recalc_interval_sec)
            try:
                self._check_events_q()
                self._check_control_q()
            except Exception as e:
                self._log_message(
                    LOG_ERROR, f"ошибка обновления координат: {e}")
