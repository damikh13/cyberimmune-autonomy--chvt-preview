import os
import pickle
import inspect
from multiprocessing import Process, Queue
from queue import Empty
from time import sleep
from pathlib import Path

from cryptography.fernet import Fernet

from src.config import (
    CRITICALITY_STR, LOG_DEBUG, LOG_ERROR, LOG_INFO,
    DEFAULT_LOG_LEVEL,
    TLS_TERMINATOR_QUEUE_NAME,
    COMMUNICATION_GATEWAY_QUEUE_NAME,
)
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission


class TLSTerminator(Process):
    """Безопасный TLS-прокси между планировщиком и связью с шифрованием."""

    log_prefix = "[TLS TERMINATOR]"
    event_q_name = TLS_TERMINATOR_QUEUE_NAME
    SECRET_KEY_PATH = "secret_key"

    def __init__(self, queues_dir: QueuesDirectory, cert_path: str = None, key_path: str = None, log_level: int = DEFAULT_LOG_LEVEL):
        super().__init__()
        self._queues_dir = queues_dir
        self._cert_path = cert_path
        self._key_path = key_path
        self.log_level = log_level

        self._cipher_key = self._initialize_cipher_key()
        self._cipher = Fernet(self._cipher_key)

        self._events_q = Queue()
        self._queues_dir.register(self._events_q, name=self.event_q_name)

        self._control_q = Queue()
        self._check_interval_sec = 0.1
        self._quit = False

        self._log_message(LOG_INFO, "TLS терминатор инициализирован")

    def _log_message(self, criticality: int, message: str):
        if criticality <= self.log_level:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")

    def _initialize_cipher_key(self) -> bytes:
        path = Path(self.SECRET_KEY_PATH)
        try:
            if path.exists():
                with open(path, 'rb') as f:
                    key = f.read()
                    self._log_message(LOG_INFO, "Загружен существующий ключ")
            else:
                key = Fernet.generate_key()
                with open(path, 'wb') as f:
                    f.write(key)
                self._log_message(LOG_INFO, "Создан и сохранён новый ключ")
            return key
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка инициализации ключа: {e}")
            return Fernet.generate_key()

    def _encrypt_mission(self, mission: Mission) -> bytes:
        try:
            
            # Используем высокий протокол для сохранения всех типов данных
            data = pickle.dumps(mission, protocol=pickle.HIGHEST_PROTOCOL)
            encrypted = self._cipher.encrypt(data)
            self._log_message(LOG_DEBUG, "Задание зашифровано")
            return encrypted
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка при шифровании: {e}")
            raise

    def _process_event(self, event: Event):
        self._log_message(LOG_DEBUG, f"Обработка события: {event}")
        if event.operation == "set_mission":
            self._forward_mission_to_communication_gateway(event.parameters)
        else:
            self._log_message(LOG_ERROR, f"Неизвестная операция: {event.operation}")

    def _forward_mission_to_communication_gateway(self, mission: Mission):
        try:
            # Проверяем содержимое миссии и логируем его
            self._log_message(LOG_INFO, f"Пересылаем задание: {mission}")
            
            encrypted = self._encrypt_mission(mission)
            event = Event(
                source=self.event_q_name,
                destination=COMMUNICATION_GATEWAY_QUEUE_NAME,
                operation="set_mission",
                parameters=encrypted,
            )
            comm_q = self._queues_dir.get_queue(COMMUNICATION_GATEWAY_QUEUE_NAME)
            if comm_q:
                comm_q.put(event)
                self._log_message(LOG_INFO, "Задание передано в Communication Gateway")
            else:
                self._log_message(LOG_ERROR, "Очередь Communication Gateway не найдена")
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка пересылки задания: {e}")

    def _check_events_q(self):
        try:
            event = self._events_q.get_nowait()
            if isinstance(event, Event):
                self._process_event(event)
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
        self._log_message(LOG_INFO, "TLS терминатор запущен")
        while not self._quit:
            sleep(self._check_interval_sec)
            self._check_events_q()
            self._check_control_q()
        self._log_message(LOG_INFO, "TLS терминатор остановлен")