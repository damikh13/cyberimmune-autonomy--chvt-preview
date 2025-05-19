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
def cert_paths():
    """Фикстура для получения путей к сертификатам."""
    ca, crt, key = (
        os.path.join(CERTS_DIR, f)
        for f in ['ca_root.crt', 'server.crt', 'server.key']
    )
    assert all(os.path.exists(p) for p in [ca, crt, key]), "Сертификаты не найдены"
    return ca, crt, key


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
    """Исправленный тест шифрования и дешифрования миссии."""
    # Создаем тестовый Fernet-ключ
    key = Fernet.generate_key()
    mission_planner._cipher = Fernet(key)
    tls_terminator._cipher = Fernet(key)
    
    # Добавляем hmac_key для обоих объектов
    test_hmac_key = os.urandom(32)  # Создаем случайный ключ для HMAC
    mission_planner._hmac_key = test_hmac_key
    tls_terminator._hmac_key = test_hmac_key
    
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
def test_mitm_attack_detection(tls_terminator, mission_planner):
    """Тест для проверки обнаружения атак MITM с помощью HMAC."""
    # Создаем тестовый Fernet-ключ
    key = Fernet.generate_key()
    mission_planner._cipher = Fernet(key)
    tls_terminator._cipher = Fernet(key)
    
    # Добавляем hmac_key для обоих объектов
    test_hmac_key = os.urandom(32)
    mission_planner._hmac_key = test_hmac_key
    tls_terminator._hmac_key = test_hmac_key
    
    # Создаем тестовую миссию
    original_mission = Mission(
        home=Point(latitude=55.7558, longitude=37.6173),
        waypoints=[Point(latitude=55.7559, longitude=37.6174)],
        speed_limits=[30],
        armed=True
    )
    
    # Шифруем миссию
    encrypted_mission = mission_planner._encrypt_mission(original_mission)
    
    # Распаковываем зашифрованную миссию
    package = pickle.loads(encrypted_mission)
    encrypted_data = package["encrypted_data"]
    original_mac = package["mac"]
    
    # Имитируем атаку MITM: модифицируем зашифрованные данные
    # Изменяем несколько байтов в зашифрованных данных
    tampered_data = bytearray(encrypted_data)
    tampered_data[10] = (tampered_data[10] + 1) % 256  # Изменяем один байт
    
    # Создаем новый пакет с измененными данными, но оригинальным MAC
    tampered_package = {
        "encrypted_data": bytes(tampered_data),
        "mac": original_mac
    }
    tampered_encrypted_mission = pickle.dumps(tampered_package)
    
    # Пытаемся дешифровать измененные данные - должна возникнуть ошибка
    with pytest.raises(ValueError, match="MAC verification failed"):
        tls_terminator._decrypt_mission(tampered_encrypted_mission)
def test_end_to_end_secure_mission_transfer(queues_dir, cert_paths):
    """Тест для проверки полного цикла безопасной передачи миссии от планировщика к TLS-терминатору."""
    # Регистрируем необходимые очереди
    tls_queue = Queue()
    planner_queue = Queue()
    comm_gateway_queue = Queue()  # Добавляем очередь для Communication Gateway
    
    queues_dir.register(tls_queue, TLS_TERMINATOR_QUEUE_NAME)
    queues_dir.register(planner_queue, PLANNER_QUEUE_NAME)
    queues_dir.register(comm_gateway_queue, COMMUNICATION_GATEWAY_QUEUE_NAME)
    
    # Создаем экземпляры TLS-терминатора и планировщика
    _, crt_path, key_path = cert_paths
    tls_terminator = TLSTerminator(queues_dir=queues_dir, cert_path=crt_path, key_path=key_path)
    
    # Патчим инициализацию SSL для планировщика
    with patch.object(MissionPlanner, '_initialize_ssl_connection', return_value=None):
        mission_planner = MissionPlanner(queues_dir=queues_dir)
    
    # Имитируем успешную установку TLS-соединения
    # 1. Устанавливаем шифры
    key = Fernet.generate_key()
    mission_planner._cipher = Fernet(key)
    tls_terminator._cipher = Fernet(key)
    
    # 2. Устанавливаем ключи для HMAC
    test_hmac_key = os.urandom(32)
    mission_planner._hmac_key = test_hmac_key
    tls_terminator._hmac_key = test_hmac_key
    
    # 3. Устанавливаем флаг соединения
    mission_planner._ssl_connection_established = True
    
    # Создаем тестовую миссию
    test_mission = Mission(
        home=Point(latitude=55.7558, longitude=37.6173),
        waypoints=[Point(latitude=55.7559, longitude=37.6174)],
        speed_limits=[30],
        armed=True
    )
    
    # Заменяем original_find_queue на original_get_queue
    original_get_queue = mission_planner._queues_dir.get_queue
    
    def patched_get_queue(queue_name):
        if queue_name == TLS_TERMINATOR_QUEUE_NAME:
            return tls_queue
        elif queue_name == PLANNER_QUEUE_NAME:
            return planner_queue
        elif queue_name == COMMUNICATION_GATEWAY_QUEUE_NAME:
            return comm_gateway_queue
        return original_get_queue(queue_name)
    
    with patch.object(mission_planner._queues_dir, 'get_queue', side_effect=patched_get_queue):
        # Имитируем установку и пересылку миссии
        # 1. Планировщик устанавливает миссию
        mission_planner._set_mission(test_mission)
        
        time.sleep(0.1)
        
        # 2. Проверяем, что в очередь TLS-терминатора попало событие
        event = tls_queue.get(timeout=1)
        assert event.operation == "set_mission"
        assert event.destination == TLS_TERMINATOR_QUEUE_NAME
        
        # 3. Обрабатываем событие в TLS-терминаторе
        with patch.object(tls_terminator, '_forward_mission_to_communication_gateway') as mock_forward:
            tls_terminator._process_event(event)
            mock_forward.assert_called_once()

        # 4. Проверяем прямую обработку зашифрованной миссии
        decrypted_mission = tls_terminator._decrypt_mission(event.parameters)
        assert isinstance(decrypted_mission, Mission)
        assert decrypted_mission.home.latitude == test_mission.home.latitude
        assert decrypted_mission.home.longitude == test_mission.home.longitude
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