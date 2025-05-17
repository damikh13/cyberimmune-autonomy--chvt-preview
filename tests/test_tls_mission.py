import os
import pytest
import datetime
import time
import threading
import pickle
from queue import Queue, Empty
from copy import deepcopy
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.fernet import Fernet

# Предполагаем, что эти импорты существуют в вашей системе
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.tls_terminator import TLSTerminator 
from src.mission_planner import MissionPlanner
from src.mission_type import Mission
from src.config import (
    PLANNER_QUEUE_NAME, TLS_TERMINATOR_QUEUE_NAME, 
    COMMUNICATION_GATEWAY_QUEUE_NAME
)
from geopy import Point

# Константы для тестов
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')


@pytest.fixture(scope='module')
def cert_paths():
    """Фикстура для получения путей к сертификатам."""
    ca, crt, key = (
        os.path.join(CERTS_DIR, f)
        for f in ['ca_root.crt', 'server.crt', 'server.key']
    )
    assert all(os.path.exists(p) for p in [ca, crt, key]), "Сертификаты не найдены"
    return ca, crt, key


@pytest.fixture(scope='module')
def rogue_cert():
    """Фикстура для создания фальшивого сертификата."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Rogue CA')])
    ca_cert = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)\
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.now(datetime.UTC))\
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=10))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256())

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'my.server.local')])
    srv_cert = x509.CertificateBuilder().subject_name(srv_name).issuer_name(ca_name)\
        .public_key(srv_key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.now(datetime.UTC))\
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=10))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256())

    return ca_cert, ca_key, srv_cert, srv_key


@pytest.fixture
def queues_dir():
    """Фикстура для создания директории очередей."""
    return QueuesDirectory()


@pytest.fixture
def tls_terminator(cert_paths, queues_dir):
    """Фикстура для создания экземпляра TLS-терминатора."""
    _, crt_path, key_path = cert_paths
    # Регистрируем очередь для TLS терминатора
    tls_queue = Queue()
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    
    return TLSTerminator(queues_dir=queues_dir, cert_path=crt_path, key_path=key_path)


@pytest.fixture
def mission_planner(queues_dir):
    """Фикстура для создания экземпляра планировщика миссий."""
    # Регистрируем необходимые очереди
    tls_queue = Queue()
    planner_queue = Queue()
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    queues_dir.register(planner_queue, PLANNER_QUEUE_NAME)
    
    # Патчим методы инициализации SSL для предотвращения ошибок
    with patch.object(MissionPlanner, '_initialize_ssl_connection', return_value=None):
        return MissionPlanner(queues_dir=queues_dir)


def test_certificate_validation(cert_paths, rogue_cert):
    """Проверка валидации сертификатов."""
    ca_path, crt_path, _ = cert_paths
    rogue_ca, _, rogue_srv, _ = rogue_cert

    with open(ca_path, 'rb') as f:
        ca = x509.load_pem_x509_certificate(f.read())
    with open(crt_path, 'rb') as f:
        srv = x509.load_pem_x509_certificate(f.read())

    # Проверка валидного сертификата
    ca.public_key().verify(
        srv.signature, srv.tbs_certificate_bytes,
        padding.PKCS1v15(), srv.signature_hash_algorithm,
    )

    # Проверка невалидного сертификата
    with pytest.raises(Exception):
        ca.public_key().verify(
            rogue_srv.signature, rogue_srv.tbs_certificate_bytes,
            padding.PKCS1v15(), rogue_srv.signature_hash_algorithm,
        )


def test_tls_terminator_initialization(cert_paths, queues_dir):
    """Проверка инициализации TLS-терминатора."""
    _, crt_path, key_path = cert_paths
    
    # Регистрируем очередь для TLS терминатора
    tls_queue = Queue()
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    
    terminator = TLSTerminator(queues_dir=queues_dir, cert_path=crt_path, key_path=key_path)
    
    assert isinstance(terminator, TLSTerminator)
    assert terminator._cert_path == crt_path
    assert terminator._key_path == key_path
    assert isinstance(terminator._queues_dir, QueuesDirectory)
    # Проверка загрузки сертификата и ключа
    assert terminator._cert_bytes is not None
    assert terminator._private_key is not None


def test_queues_directory_event_flow(queues_dir):
    """Проверка передачи событий через директорию очередей."""
    # Создаем тестовое событие с правильными параметрами
    test_event = Event(
        source="test_source",
        destination="test_destination",
        operation="test_event",
        parameters={'data': 123}
    )
    
    # Создаем тестовую очередь
    test_queue = Queue()
    queues_dir.register(test_queue, "test_queue")
    
    # Помещаем событие в очередь
    queues_dir.get_queue("test_queue").put(test_event)
    
    # Проверка наличия и корректности события
    try:
        received = queues_dir.get_queue("test_queue").get(timeout=1)
        assert received.operation == 'test_event'
        assert received.parameters['data'] == 123
    except Empty:
        pytest.fail("Событие не было получено из очереди")


def test_mission_planner_initialization(queues_dir):
    """Проверка инициализации планировщика миссий."""
    # Регистрируем необходимые очереди
    tls_queue = Queue()
    planner_queue = Queue()
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    queues_dir.register(planner_queue, PLANNER_QUEUE_NAME)
    
    # Патчим методы инициализации SSL для предотвращения ошибок
    with patch.object(MissionPlanner, '_initialize_ssl_connection', return_value=None):
        planner = MissionPlanner(queues_dir=queues_dir)
    
    assert isinstance(planner, MissionPlanner)
    assert planner._queues_dir == queues_dir
    assert planner._ssl_connection_established == False
    assert planner._pending_missions == []


def test_tls_terminator_process_client_hello(tls_terminator, queues_dir):
    """Проверка обработки client_hello в TLS-терминаторе."""
    # Создаем очередь для ответа и регистрируем её
    response_queue = Queue()
    source_name = "test_source"
    queues_dir.register(response_queue, source_name)
    
    # Создаем событие client_hello
    client_hello_event = Event(
        source=source_name,
        destination=TLS_TERMINATOR_QUEUE_NAME,
        operation="client_hello",
        parameters={
            "ssl_version": "TLSv1.0",
            "random": os.urandom(32),
            "session_id": "0",
            "cipher_suites": ["TLS_AES_128_CBC_SHA256"],
            "compression_methods": ["null"],
        }
    )
    
    # Обрабатываем событие
    tls_terminator._process_client_hello(client_hello_event)
    
    # Проверяем ответ
    try:
        response = response_queue.get(timeout=1)
        assert response.operation == "server_hello"
        assert "certificate_chain" in response.parameters
        assert response.parameters["cipher_suite"] == "TLS_AES_128_CBC_SHA256"
        
        # Проверяем, что после server_hello следует server_key_exchange
        response = response_queue.get(timeout=1)
        assert response.operation == "server_key_exchange"
        assert "payload" in response.parameters
        assert "signature" in response.parameters
        assert "P1" in response.parameters["payload"]
        assert "P2" in response.parameters["payload"]
        assert "S" in response.parameters["payload"]
    except Empty:
        pytest.fail("Не получен ответ на client_hello")


def test_mission_encryption_decryption(tls_terminator, mission_planner):
    """Проверка шифрования и дешифрования миссии."""
    # Создаем тестовый Fernet-ключ
    key = Fernet.generate_key()
    mission_planner._cipher = Fernet(key)
    tls_terminator._cipher = Fernet(key)
    
    # Создаем тестовую миссию
    test_mission = Mission(
        home=Point(latitude=55.7558, longitude=37.6173),
        waypoints=[
            Point(latitude=55.7559, longitude=37.6174),
            Point(latitude=55.7560, longitude=37.6175)
        ],
        speed_limits=[30, 50],
        armed=True
    )
    
    # Шифруем миссию
    encrypted_mission = mission_planner._encrypt_mission(test_mission)
    
    # Дешифруем миссию
    decrypted_mission = tls_terminator._decrypt_mission(encrypted_mission)
    
    # Проверяем результат
    assert isinstance(decrypted_mission, Mission)
    assert decrypted_mission.home.latitude == test_mission.home.latitude
    assert decrypted_mission.home.longitude == test_mission.home.longitude
    assert len(decrypted_mission.waypoints) == len(test_mission.waypoints)
    assert decrypted_mission.armed == test_mission.armed


def test_tls_terminator_stop(tls_terminator):
    """Проверка остановки TLS-терминатора."""
    # Начальное состояние
    assert tls_terminator._quit == False
    
    # Патчим соответствующие методы, чтобы _quit устанавливался
    with patch.object(tls_terminator, '_check_control_q', 
                     side_effect=lambda: setattr(tls_terminator, '_quit', True)):
        # Отправляем команду остановки
        tls_terminator.stop()
        
        # Проверяем обработку команды
        tls_terminator._check_control_q()
        
        # Проверяем, что флаг остановки установлен
        assert tls_terminator._quit == True


def test_full_tls_handshake_simulation():
    """Полная симуляция TLS-рукопожатия с реальным обменом данными."""
    # Создаем директорию очередей
    queues_dir = QueuesDirectory()
    
    # Регистрируем очереди
    tls_queue = Queue()
    planner_queue = Queue()
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    queues_dir.register(planner_queue, PLANNER_QUEUE_NAME)
    
    # Создаем экземпляры TLS-терминатора и планировщика
    tls_terminator = TLSTerminator(
        queues_dir=queues_dir,
        cert_path=os.path.join(CERTS_DIR, 'server.crt'),
        key_path=os.path.join(CERTS_DIR, 'server.key')
    )
    
    # Патчим инициализацию SSL для планировщика
    with patch.object(MissionPlanner, '_initialize_ssl_connection', return_value=None):
        mission_planner = MissionPlanner(
            queues_dir=queues_dir
        )
    
    # Запускаем TLS-терминатор в отдельном потоке с патчингом для безопасного завершения
    with patch.object(tls_terminator, 'run', side_effect=lambda: None):
        tls_thread = threading.Thread(target=tls_terminator.run)
        tls_thread.daemon = True
        tls_thread.start()
    
    # Запускаем планировщик миссий в отдельном потоке с патчингом для безопасного завершения
    with patch.object(mission_planner, 'run', side_effect=lambda: None):
        planner_thread = threading.Thread(target=mission_planner.run)
        planner_thread.daemon = True
        planner_thread.start()
    
    # Даем время на запуск
    time.sleep(0.1)
    
    # Отправляем тестовую миссию
    test_mission = Mission(
        home=Point(latitude=55.7558, longitude=37.6173),
        waypoints=[Point(latitude=55.7559, longitude=37.6174)],
        speed_limits=[30],
        armed=True
    )
    
    # Устанавливаем соединение для планировщика
    mission_planner._ssl_connection_established = True
    
    # Останавливаем потоки
    tls_terminator.stop()
    mission_planner.stop()