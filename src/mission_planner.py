""" модуль работы с маршрутным заданием со встроенным шифрованием
"""
from time import sleep
from queue import Empty
from typing import Optional, List
from multiprocessing import Queue, Process
from geopy import Point
import pickle
import os
from pathlib import Path
from cryptography.fernet import Fernet
from src.config import CRITICALITY_STR, LOG_DEBUG, \
    LOG_ERROR, LOG_INFO, PLANNER_QUEUE_NAME, DEFAULT_LOG_LEVEL, MISSION_SENDER_QUEUE_NAME, \
    TLS_TERMINATOR_QUEUE_NAME
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import json
import base64

class MissionPlanner(Process):
    """MissionPlanner обработчик и хранитель маршрутного задания
       как и остальные компоненты работает в отдельном процессе
       теперь также шифрует маршрутные задания перед отправкой в TLS терминатор
    """
    log_prefix = "[MISSION PLANNER]"
    event_source_name = PLANNER_QUEUE_NAME
    event_q_name = event_source_name
    log_level = DEFAULT_LOG_LEVEL
    TRUSTED_ROOT_CERT = "certs/ca_root.crt"
    CLIENT_SECRET_C = 3

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

        self._pending_missions = []
        self._server_public_key = None
        self._ssl_connection_established = False

        self._cipher: Optional[Fernet] = None

        # инициализация SSL-соединения с TLS терминатором
        self._initialize_ssl_connection()

        with open(self.TRUSTED_ROOT_CERT, "rb") as f:
            self._trusted_root = x509.load_pem_x509_certificate(f.read())
        self._trusted_pubkey = self._trusted_root.public_key()

        # маршрут для движения
        self._mission: Optional[Mission] = None

        if mission is not None:
            # если есть маршрутное задание, устанавливаем его
            self._set_mission(mission)

        self._log_message(LOG_INFO, "создана система планирования заданий с шифрованием")

    def _initialize_ssl_connection(self):
        # send client_hello to TLS terminator
        self._log_message(LOG_INFO, "пытаемся установить SSL-соединение с TLS терминатором")
        self._log_message(LOG_DEBUG, "отправляем client_hello в TLS терминатор")

        # формируем сообщение client_hello
        client_hello_message = {
            "ssl_version": "TLSv1.0",
            "random": os.urandom(32), # for now, unused
            "session_id": "0", # new session
            "cipher_suites": ["TLS_AES_128_CBC_SHA256"],  # should match Fernet's AES-128-CBC
            "compression_methods": ["null"],
        }

        client_hello_event = Event(
            source=self.event_source_name,
            destination=TLS_TERMINATOR_QUEUE_NAME,
            operation="client_hello",
            parameters=client_hello_message
        )

        tls_terminator_q: Queue = self._queues_dir.get_queue(TLS_TERMINATOR_QUEUE_NAME)
        tls_terminator_q.put(client_hello_event)
        self._log_message(LOG_INFO, "отправлен client_hello в TLS терминатор")
    def _process_server_hello(self, server_hello):
        self._log_message(LOG_INFO, "получен server_hello от TLS терминатора")
        
        # 1. Extract the certificate bytes from the server_hello
        cert_pem = server_hello["certificate_chain"][0]  # assuming single cert
        cert = x509.load_pem_x509_certificate(cert_pem)

        # 2. Verify the signature on the server cert against the trusted root
        try:
            self._trusted_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                # Padding & hash must match how the CA signed it:
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            self._log_message(LOG_ERROR, f"certificate signature invalid: {e}")
            raise ValueError("invalid server certificate signature")
        self._log_message(LOG_INFO, "server certificate signature is valid")

        # 3. Check validity dates
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            self._log_message(LOG_ERROR, "certificate expired or not yet valid")
            raise ValueError("cerver certificate is not valid at this time")
        self._log_message(LOG_INFO, "server certificate is within valid date range")

        self._log_message(LOG_INFO, "server certificate is trusted and valid")

        # 5. Extract server’s public key to use for the next handshake step
        # server_public_key = cert.public_key()
        self._server_public_key = cert.public_key()
    def _process_server_key_exchange(self, key_exchange_message):
        self._log_message(LOG_INFO, "получен server_key_exchange от TLS терминатора")
        
        payload = key_exchange_message["payload"]
        signature = key_exchange_message["signature"]

        data = pickle.dumps(payload)

        try:
            self._server_public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            self._log_message(LOG_ERROR, f"invalid server_key_exchange signature: {e}")
            raise

        self._log_message(LOG_INFO, "server_key_exchange signature is valid")

        P1 = payload["P1"]
        P2 = payload["P2"]
        S  = payload["S"]

        c = self.CLIENT_SECRET_C
        C = P1**c % P2
        K = S**c % P2

        digest = hashes.Hash(hashes.SHA256())
        digest.update(K.to_bytes((K.bit_length()+7)//8, byteorder="big"))
        sym_key = digest.finalize()              # 32 bytes

        fernet_key = base64.urlsafe_b64encode(sym_key)
        self._cipher = Fernet(fernet_key)

        self._log_message(LOG_INFO, f"client secret C: {C}, shared secret K: {K}")

        # encrypt the calculated C with the server's public key
        C_bytes = C.to_bytes((C.bit_length() + 7)//8, byteorder="big")
        encrypted_C = self._server_public_key.encrypt(
            C_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
 
        client_key_exchange_message = {
            "encrypted_C": encrypted_C,
        }
 
        event = Event(
            source=self.event_source_name,
            destination=TLS_TERMINATOR_QUEUE_NAME,
            operation="client_key_exchange",
            parameters=client_key_exchange_message
        )

        tls_terminator_q: Queue = self._queues_dir.get_queue(TLS_TERMINATOR_QUEUE_NAME)
        tls_terminator_q.put(event)
        self._log_message(LOG_INFO, "отправлен client_key_exchange в TLS терминатор")
    def _process_finish_handshake(self, finish_handshake_message):
        self._log_message(LOG_INFO, "получен finish_handshake от TLS терминатора")
        
        self._ssl_connection_established = True
        self._log_message(LOG_INFO, "SSL-соединение успешно установлено")
        for pending_mission in self._pending_missions:
            self._log_message(LOG_INFO, "отправляем отложенную миссию")
            self.set_new_mission(*pending_mission)

    def _encrypt_mission(self, mission: Mission) -> bytes:
        """Шифрует маршрутное задание"""
        try:
            # Используем высокий протокол для сохранения всех типов данных
            # print(mission)
            data = pickle.dumps(mission, protocol=pickle.HIGHEST_PROTOCOL)
            encrypted = self._cipher.encrypt(data)
            self._log_message(LOG_INFO, "Задание зашифровано")
            # print(encrypted)
            return encrypted
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка при шифровании: {e}")
            raise
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

        # if self._ssl_connection_established is False:
        #     self._log_message(LOG_ERROR, "SSL-соединение не установлено, невозможно установить новую миссию")
        #     return
        if not self._ssl_connection_established:
            self._log_message(LOG_ERROR, "SSL-соединение не установлено, невозможно установить новую миссию")
            self._pending_missions.append(
                (mission, home, waypoints, speed_limits, arm))
            self._log_message(LOG_INFO, "миссия отложена до установления SSL-соединения")

        if mission is None:
            mission = Mission(home=home, waypoints=waypoints,
                              speed_limits=speed_limits, armed=arm)

        event = Event(source=MissionPlanner.event_source_name,
                      destination=MissionPlanner.event_q_name, operation="set_mission",
                      parameters=mission)
        self._events_q.put(event)
        self._log_message(LOG_DEBUG, f"запрошена новая задача: {mission}")
    def _set_mission(self, mission: Mission):
        if not self._ssl_connection_established:
            self._log_message(LOG_ERROR, "SSL-соединение не установлено, невозможно установить новую миссию")
            self._pending_missions.append((mission,))
            self._log_message(LOG_INFO, "миссия отложена до установления SSL-соединения")
            return

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
        """Шифрует и отправляет задание в TLS терминатор"""
        try:
            # Шифруем задание
            encrypted_mission = self._encrypt_mission(self._mission)
            
            # Создаем событие с зашифрованными данными
            event = Event(source=MissionPlanner.event_source_name,
                        destination=TLS_TERMINATOR_QUEUE_NAME,
                        operation="set_mission", parameters=encrypted_mission
                        )
                        
            # Получаем очередь TLS терминатора и отправляем событие
            tls_terminator_q: Queue = self._queues_dir.get_queue(TLS_TERMINATOR_QUEUE_NAME)
            tls_terminator_q.put(event)
            self._log_message(LOG_INFO, "зашифрованная задача отправлена в TLS терминатор")
        except Exception as e:
            self._log_message(LOG_ERROR, f"ошибка отправки зашифрованной задачи в TLS терминатор: {e}")

    # проверка наличия новых управляющих команд
    def _process_event(self, event: Event):
        self._log_message(LOG_INFO, f"обработка события: {event}")
        if event.operation == 'set_mission':
            try:
                # если пришло новое маршрутное задание, устанавливаем его
                self._set_mission(event.parameters)
            except Exception as e:
                self._log_message(
                    LOG_ERROR, f"ошибка установки новой миссии: {e}")
        elif event.operation == 'server_hello':
            self._process_server_hello(event.parameters)
        elif event.operation == 'server_key_exchange':
            self._process_server_key_exchange(event.parameters)
        elif event.operation == 'finish_handshake':
            self._process_finish_handshake(event.parameters)
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
            # if event.operation == 'set_mission':
            #     try:
            #         self._set_mission(event.parameters)
            #     except Exception as e:
            #         self._log_message(
            #             LOG_ERROR, f"ошибка отправки координат: {e}")
            self._process_event(event)

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