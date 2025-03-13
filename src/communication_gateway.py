""" модуль реализации взаимодействия с системой планирования заданий """
from multiprocessing import Queue, Process
from typing import Optional
from queue import Empty
from abc import abstractmethod

from time import sleep

from src.config import COMMUNICATION_GATEWAY_QUEUE_NAME, CRITICALITY_STR, \
    DEFAULT_LOG_LEVEL, LOG_DEBUG, LOG_ERROR, LOG_INFO
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission


class BaseCommunicationGateway(Process):
    """BaseCommunicationGateway базовый класс для реализации логики взаимодействия
    с системой планирования заданий

    Работает в отдельном процессе, поэтому создаётся как наследник класса Process
    """
    log_prefix = "[COMMUNICATION]"
    event_source_name = COMMUNICATION_GATEWAY_QUEUE_NAME
    events_q_name = event_source_name    

    def __init__(self, queues_dir: QueuesDirectory, log_level = DEFAULT_LOG_LEVEL):
        # вызываем конструктор базового класса
        super().__init__()

        # запоминаем каталог очередей -
        # позже он понадобится для отправки маршрутного задания в систему управления
        self._queues_dir = queues_dir

        # создаём очередь для сообщений на обработку
        self._events_q = Queue()
        self._events_q_name = self.event_source_name

        # регистрируем очередь в каталоге
        self._queues_dir.register(
            queue=self._events_q, name=self._events_q_name)

        # инициализируем интервал обновления
        self._recalc_interval_sec = 0.5

        self._quit = False
        # очередь управляющих команд (например, для остановки работы модуля)
        self._control_q = Queue()

        # координаты пункта назначения
        self._mission: Optional[Mission] = None

        self.log_level = log_level
        self._log_message(LOG_INFO, "создан компонент связи")

    def _log_message(self, criticality: int, message: str):
        """_log_message печатает сообщение заданного уровня критичности

        Args:
            criticality (int): уровень критичности
            message (str): текст сообщения
        """
        if criticality <= self.log_level:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")

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
                    self._log_message(LOG_ERROR, f"ошибка отправки координат: {e}")
        except Empty:
            # никаких команд не поступило, ну и ладно
            pass

    def _set_mission(self, mission: Mission):
        self._mission = mission
        self._log_message(LOG_DEBUG, f"получена новая задача: {self._mission}")
        self._log_message(LOG_INFO, "получен новый маршрут, отправляем получателям")
        self._send_mission_to_consumers()

    @abstractmethod
    def _send_mission_to_consumers(self):
        pass

    def stop(self):
        self._control_q.put(ControlEvent(operation='stop'))

    def run(self):
        self._log_message(LOG_INFO, "старт системы планирования заданий")

        while self._quit is False:
            sleep(self._recalc_interval_sec)
            try:
                self._check_events_q()
                self._check_control_q()
            except Exception as e:
                self._log_message(LOG_ERROR, f"ошибка обновления координат: {e}")

