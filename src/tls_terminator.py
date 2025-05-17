import os
import pickle
import inspect
from multiprocessing import Process, Queue
from queue import Empty
from time import sleep
from pathlib import Path
from cryptography.fernet import Fernet

from src.config import (
    CRITICALITY_STR, LOG_ERROR, LOG_INFO,
    DEFAULT_LOG_LEVEL,
    TLS_TERMINATOR_QUEUE_NAME,
    COMMUNICATION_GATEWAY_QUEUE_NAME,
)
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import json
import base64

class TLSTerminator(Process):
    """TLS-терминатор между планировщиком и связью с дешифрованием данных."""

    log_prefix = "[TLS TERMINATOR]"
    event_q_name = TLS_TERMINATOR_QUEUE_NAME
    cipher_suites = ["TLS_AES_128_CBC_SHA256"] # add more as needed

    def __init__(self, queues_dir: QueuesDirectory, cert_path: str = None, key_path: str = None, log_level: int = DEFAULT_LOG_LEVEL):
        super().__init__()
        self._queues_dir = queues_dir
        self._cert_path = cert_path
        self._key_path = key_path
        self.log_level = log_level

        self._ensure_certificate()
        # Load them once so we don’t have to re‐read from disk each time:
        self._cert_bytes = self._load_certificate_bytes()
        self._private_key = self._load_private_key()

        self._P1 = 7
        self._P2 = 11
        self._s = 5
        self._S = self._P1 ** self._s % self._P2


        self._events_q = Queue()
        self._queues_dir.register(self._events_q, name=self.event_q_name)
        self._log_message(LOG_INFO, f"регистрируем очередь {self.event_q_name}")

        self._control_q = Queue()
        self._check_interval_sec = 0.1
        self._quit = False

        self._log_message(LOG_INFO, "TLS терминатор инициализирован")
    def _log_message(self, criticality: int, message: str):
        if criticality <= self.log_level:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")
    def _decrypt_mission(self, encrypted_data: bytes) -> Mission:
        """Расшифровывает маршрутное задание"""
        try:
            decrypted = self._cipher.decrypt(encrypted_data)
            mission = pickle.loads(decrypted)
            self._log_message(LOG_INFO, "Задание расшифровано")
            return mission
        except Exception as e:
            self._log_message(LOG_ERROR, f"Ошибка при расшифровке: {e}")
            raise
    def _process_event(self, event: Event):
        self._log_message(LOG_INFO, f"Обработка события: {event}")
        if event.operation == "set_mission":
            self._forward_mission_to_communication_gateway(event.parameters)
        elif event.operation == "client_hello":
            self._process_client_hello(event)
        elif event.operation == "client_key_exchange":
            self._process_client_key_exchange(event)
        else:
            self._log_message(LOG_ERROR, f"Неизвестная операция: {event.operation}")
    def _process_client_hello(self, event: Event):
        """Обрабатывает событие client_hello, пока не реализовано"""
        self._log_message(LOG_INFO, f"получено событие client_hello: {event.parameters}")
        # choose a cipher suite based on client cipher preferences and our supported suites
        if not event.parameters or "cipher_suites" not in event.parameters:
            self._log_message(LOG_ERROR, "не указана шифровальная система в client_hello")
            return
        client_ciphers = event.parameters["cipher_suites"]
        self._log_message(LOG_INFO, f"клиентские шифры: {client_ciphers}")
        chosen_cipher = None
        for cipher in self.cipher_suites:
            if cipher in client_ciphers:
                chosen_cipher = cipher
                break
        if chosen_cipher:
            self._log_message(LOG_INFO, f"выбран шифр: {chosen_cipher}")
        else:
            self._log_message(LOG_ERROR, "не удалось выбрать шифр из предложенных клиентом")
            return
        # здесь можно добавить логику для дальнейшей обработки client_hello

        self._generate_and_send_server_hello(event.source, chosen_cipher)
        self._generate_and_send_server_key_exchange(event.source)
    def _ensure_certificate(self):
        """If cert/key files don’t exist, create a self-signed cert."""
        if Path(self._cert_path).exists() and Path(self._key_path).exists():
            return

        # 1. Generate a new RSA key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # 2. Build a self-signed X.509 certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"my.server.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # 3. Save key and cert to files
        with open(self._key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(self._cert_path, "wb") as f:
            f.write(
                cert.public_bytes(serialization.Encoding.PEM)
            )
    def _load_certificate_bytes(self) -> bytes:
        """Read the server certificate from disk as bytes (PEM)."""
        with open(self._cert_path, "rb") as f:
            return f.read()
    def _load_private_key(self):
        """Read the private key (if you need it later)."""
        with open(self._key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    def _generate_and_send_server_hello(self, source: str, cipher_suite: str):
        self._log_message(LOG_INFO, f"генерация server_hello с шифром {cipher_suite}")
        server_hello_message = {
            "your_ssl_version_is_good": True,  # should be determined by actual checks
            "random": os.urandom(32),          # server random
            "cipher_suite": cipher_suite,
            # **New**: include the certificate chain
            "certificate_chain": [
                # If you had intermediates, you'd append them here
                self._cert_bytes
            ],
        }

        # Serialize the message however you do (pickle/json/etc), then send:
        event = Event(
            source=self.event_q_name,
            destination=source,
            operation="server_hello",
            parameters=server_hello_message,
        )
        dest_q = self._queues_dir.get_queue(source)
        if dest_q:
            dest_q.put(event)
            self._log_message(LOG_INFO, "отправлен server_hello с сертификатом")
        else:
            self._log_message(LOG_ERROR, f"Не найдена очередь для {source}")
    def _generate_and_send_server_key_exchange(self, source: str):
        self._log_message(LOG_INFO, "генерация server_key_exchange")

        payload = {
            "P1": self._P1,
            "P2": self._P2,
            "S": self._S,
        }

        data = pickle.dumps(payload)
        signature = self._private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        server_key_exchange_message = {
            "payload": payload,
            "signature": signature,
        }

        event = Event(
            source=self.event_q_name,
            destination=source,
            operation="server_key_exchange",
            parameters=server_key_exchange_message,
        )

        dest_q = self._queues_dir.get_queue(source)
        if dest_q:
            dest_q.put(event)
            self._log_message(LOG_INFO, "отправлен server_key_exchange")
        else:
            self._log_message(LOG_ERROR, f"Не найдена очередь для {source}") 
    def _process_client_key_exchange(self, event: Event):
        self._log_message(LOG_INFO, f"получено событие client_key_exchange: {event.parameters}")

        encrypted_C = event.parameters.get("encrypted_C")
        if not encrypted_C:
            self._log_message(LOG_ERROR, "Нет поля encrypted_C в client_key_exchange")
            return

        # 1) Decrypt C with our RSA private key
        try:
            C_bytes = self._private_key.decrypt(
                encrypted_C,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            self._log_message(LOG_ERROR, f"Не удалось расшифровать C: {e}")
            return

        # 2) Convert back to integer
        C = int.from_bytes(C_bytes, byteorder="big")
        self._log_message(LOG_INFO, f"Дешифрован C={C}")

        # 3) Compute shared secret K = Cˢ mod P2
        #    (make sure you saved self._P2 and your exponent self._s earlier)
        K = pow(C, self._s, self._P2)
        self._log_message(LOG_INFO, f"Вычислен общий секрет K={K}")

        # 4) Derive a symmetric key from K
        #    For example, hash it down to 32 bytes for Fernet/AES-256:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(K.to_bytes((K.bit_length()+7)//8, byteorder="big"))
        sym_key = digest.finalize()              # 32 bytes

        #    If you’re using Fernet, you need 32 url-safe base64 bytes:
        fernet_key = base64.urlsafe_b64encode(sym_key)
        self._cipher = Fernet(fernet_key)
        self._log_message(LOG_INFO, "установлен симметричный шифр на основе K")

        finish_evt = Event(
            source=self.event_q_name,
            destination=event.source,
            operation="finish_handshake",
            parameters={}
        )
        q = self._queues_dir.get_queue(event.source)
        if q:
            q.put(finish_evt)
            self._log_message(LOG_INFO, "отправлен handshake_finished клиенту")
        else:
            self._log_message(LOG_ERROR, f"Не найдена очередь для {event.source}")

    def _forward_mission_to_communication_gateway(self, encrypted_mission: bytes):
        try:
            # Расшифровываем задание
            mission = self._decrypt_mission(encrypted_mission)
            
            # Проверяем содержимое миссии и логируем его
            self._log_message(LOG_INFO, f"Расшифрованное задание: {mission}")
            
            # Создаем событие с расшифрованными данными
            event = Event(
                source=self.event_q_name,
                destination=COMMUNICATION_GATEWAY_QUEUE_NAME,
                operation="set_mission",
                parameters=mission,
            )
            
            # Получаем очередь Communication Gateway и отправляем
            comm_q = self._queues_dir.get_queue(COMMUNICATION_GATEWAY_QUEUE_NAME)
            if comm_q:
                comm_q.put(event)
                self._log_message(LOG_INFO, "Расшифрованное задание передано в Communication Gateway")
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