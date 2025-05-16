import os
import pickle
import pytest
import json
import base64
from queue import Queue
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet
from geopy import Point

# Import your modules (adjust paths as needed)
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission
from src.tls_terminator import TLSTerminator
from src.mission_planner import MissionPlanner

CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

@pytest.fixture(scope='module')
def ca_and_server_cert_paths():
    ca_crt = os.path.join(CERTS_DIR, 'ca_root.crt')
    server_crt = os.path.join(CERTS_DIR, 'server.crt')
    server_key = os.path.join(CERTS_DIR, 'server.key')
    assert os.path.exists(ca_crt)
    assert os.path.exists(server_crt)
    assert os.path.exists(server_key)
    return ca_crt, server_crt, server_key

@pytest.fixture(scope='module')
def ca_cert(ca_and_server_cert_paths):
    ca_crt, _, _ = ca_and_server_cert_paths
    with open(ca_crt, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())

@pytest.fixture(scope='module')
def server_cert_and_key(ca_and_server_cert_paths):
    _, server_crt, server_key = ca_and_server_cert_paths
    with open(server_crt, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(server_key, 'rb') as f:
        key = load_pem_private_key(f.read(), password=None)
    return cert, key

# 1. Test that CA signs server certificate
def test_root_signs_server(ca_cert, server_cert_and_key):
    server_cert, _ = server_cert_and_key
    # should verify without exception
    ca_cert.public_key().verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )

# 2. Test signing and verifying ServerKeyExchange payload
def test_sign_and_verify_rse(server_cert_and_key):
    _, priv_key = server_cert_and_key
    payload = {'P1': 7, 'P2': 11, 'S': 5}
    data = pickle.dumps(payload)
    sig = priv_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    pub_key = server_cert_and_key[0].public_key()
    # valid
    pub_key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    # tampered payload
    bad = pickle.dumps({'P1': 8, 'P2': 11, 'S': 5})
    with pytest.raises(Exception):
        pub_key.verify(sig, bad, padding.PKCS1v15(), hashes.SHA256())

# 3. Test Diffie-Hellman math
def test_dh_shared_secret():
    P1, P2, s, c = 7, 11, 5, 3
    S = pow(P1, s, P2)
    C = pow(P1, c, P2)
    K1 = pow(S, c, P2)
    K2 = pow(C, s, P2)
    assert K1 == K2 == 10

# 4. Test mission encryption/decryption
def test_encrypt_decrypt_mission(ca_and_server_cert_paths):
    class DummyPlanner(MissionPlanner):
        def _initialize_ssl_connection(self):
            self._ssl_connection_established = True

    queues = QueuesDirectory()
    planner = DummyPlanner(queues)
    # Create sample mission
    m = Mission(
        home=Point(0.0, 0.0),
        waypoints=[Point(1.0, 1.0)],
        speed_limits=[],
        armed=True
    )
    token = planner._encrypt_mission(m)
    # Ensure token is bytes
    assert isinstance(token, bytes)
    # Decrypt and load
    decrypted = planner._cipher.decrypt(token)
    recovered = pickle.loads(decrypted)
    assert recovered == m


# 5. Test handshake flow
def test_full_handshake_flow(ca_and_server_cert_paths):
    queues = QueuesDirectory()
    term = TLSTerminator(queues, cert_path=os.path.join(CERTS_DIR,'server.crt'),
                          key_path=os.path.join(CERTS_DIR,'server.key'))
    # Disable run loops
    plan = MissionPlanner(queues)

    # 1) client_hello
    plan._initialize_ssl_connection()
    evt = queues.get_queue('tls_terminator').get_nowait()
    term._process_event(evt)
    # 2) server_hello
    out = queues.get_queue('mission_planner').get_nowait()
    assert out.operation == 'server_hello'
    plan._process_event(out)
    # 3) server_key_exchange
    term._generate_and_send_server_key_exchange('mission_planner')
    ske = queues.get_queue('mission_planner').get_nowait()
    assert ske.operation == 'server_key_exchange'
    plan._process_event(ske)
    # 4) client_key_exchange
    cke = queues.get_queue('tls_terminator').get_nowait()
    assert cke.operation == 'client_key_exchange'
    term._process_event(cke)
    # 5) finish_handshake
    fin = queues.get_queue('mission_planner').get_nowait()
    assert fin.operation == 'finish_handshake'
    plan._process_event(fin)
    assert plan._ssl_connection_established

# 6. End-to-end mission delivery
def test_send_mission_after_handshake(ca_and_server_cert_paths):
    queues = QueuesDirectory()
    term = TLSTerminator(queues,
                          cert_path=os.path.join(CERTS_DIR,'server.crt'),
                          key_path=os.path.join(CERTS_DIR,'server.key'))
    class DummyPlanner(MissionPlanner):
        def _initialize_ssl_connection(self):
            self._ssl_connection_established = True
    plan = DummyPlanner(queues)

    m = Mission(home=Point(0,0), waypoints=[Point(1,1)], armed=False)
    plan.set_new_mission(mission=m)

    evt = queues.get_queue('tls_terminator').get_nowait()
    assert evt.operation == 'set_mission'
    # decrypt on terminator side
    recovered = pickle.loads(term._cipher.decrypt(evt.parameters))
    assert recovered == m
