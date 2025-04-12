from typing import Optional
from queue import Empty
from multiprocessing import Queue, Process
import time
import ssl
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

from src.config import (
    CRITICALITY_STR, LOG_DEBUG, LOG_ERROR, LOG_INFO, 
    DEFAULT_LOG_LEVEL, TLS_TERMINATOR_QUEUE_NAME, 
    PLANNER_QUEUE_NAME, COMMUNICATION_GATEWAY_QUEUE_NAME,
    SECURITY_MONITOR_QUEUE_NAME
)
from src.queues_dir import QueuesDirectory
from src.event_types import Event, ControlEvent
from src.mission_type import Mission
from src.security_policy_type import SecurityPolicy

class TLSTerminator(Process):
    """TLS Terminator class - serves as a secure proxy between 
    MissionPlanner and CommunicationGateway components.
    
    Implements TLS termination proxy pattern to provide:
    1. Encryption/decryption of data
    2. Certificate verification
    3. Secure communication between components
    """
    log_prefix = "[TLS TERMINATOR]"
    event_source_name = TLS_TERMINATOR_QUEUE_NAME
    event_q_name = event_source_name
    log_level = DEFAULT_LOG_LEVEL

    def __init__(self, queues_dir: QueuesDirectory, cert_path: str = None, key_path: str = None):
        # Call parent constructor
        super().__init__()

        self._queues_dir = queues_dir

        # Create queue for processing messages
        self._events_q = Queue()
        self._events_q_name = TLSTerminator.event_q_name
        self._queues_dir.register(
            queue=self._events_q, name=self._events_q_name)

        # Control queue for commands (e.g., to stop the module)
        self._control_q = Queue()
        
        # Set update interval
        self._recalc_interval_sec = 0.1
        self._quit = False

        # Certificate and key paths for TLS
        self._cert_path = cert_path
        self._key_path = key_path
        
        # Initialize SSL context
        self._ssl_context = self._init_ssl_context()
        
        # Initialize Diffie-Hellman parameters
        self._dh_params = dh.generate_parameters(generator=2, key_size=2048)
        
        # Session keys cache for different connections
        self._session_keys = {}
        
        # Register security policies for this component
        self._register_security_policies()
        
        self._log_message(LOG_INFO, "TLS Terminator created")
    def _init_ssl_context(self):
        """Initialize SSL context with proper configuration"""
        if not self._cert_path or not self._key_path:
            self._log_message(LOG_INFO, "Certificate paths not provided, using default configuration")
            return None
            
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            
            # Set secure protocol and cipher preferences
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
            
            self._log_message(LOG_INFO, "SSL context initialized successfully")
            return context
        except Exception as e:
            self._log_message(LOG_ERROR, f"Failed to initialize SSL context: {e}")
            return None
    def _register_security_policies(self):
        """Register security policies for TLS Terminator"""
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        
        # Define security policies for TLS Terminator
        policies = [
            SecurityPolicy(
                source=PLANNER_QUEUE_NAME,
                destination=TLS_TERMINATOR_QUEUE_NAME,
                operation='set_mission'
            ),
            SecurityPolicy(
                source=TLS_TERMINATOR_QUEUE_NAME,
                destination=COMMUNICATION_GATEWAY_QUEUE_NAME,
                operation='set_mission'
            ),
            # Additional policies as needed
        ]
        
        # Send policies to security monitor
        security_policy_event = Event(
            source=TLS_TERMINATOR_QUEUE_NAME,
            destination=SECURITY_MONITOR_QUEUE_NAME,
            operation="add_security_policies",
            parameters=policies
        )
        
        try:
            security_monitor_q.put(security_policy_event)
            self._log_message(LOG_INFO, "Security policies registered")
        except Exception as e:
            self._log_message(LOG_ERROR, f"Failed to register security policies: {e}")
    def _log_message(self, criticality: int, message: str):
        """Print log message with specified criticality level

        Args:
            criticality (int): Criticality level
            message (str): Message text
        """
        if criticality <= self.log_level:
            print(f"[{CRITICALITY_STR[criticality]}]{self.log_prefix} {message}")
    def _generate_session_key(self, client_id: str):
        """Generate a new session key using Diffie-Hellman key exchange

        Args:
            client_id (str): Client identifier

        Returns:
            bytes: Generated session key
        """
        try:
            # Generate private and public keys
            private_key = self._dh_params.generate_private_key()
            public_key = private_key.public_key()
            
            # Store for later use
            self._session_keys[client_id] = {
                'private_key': private_key,
                'public_key': public_key,
                'session_key': None
            }
            
            return public_key.public_numbers().y
        except Exception as e:
            self._log_message(LOG_ERROR, f"Error generating session key: {e}")
            return None
    def _complete_key_exchange(self, client_id: str, peer_public_key_value: int):
        """Complete Diffie-Hellman key exchange with peer

        Args:
            client_id (str): Client identifier
            peer_public_key_value (int): Peer's public key value

        Returns:
            bytes: Shared secret key
        """
        try:
            if client_id not in self._session_keys:
                self._log_message(LOG_ERROR, f"No key exchange in progress for {client_id}")
                return None
                
            # Reconstruct peer's public key
            peer_public_numbers = dh.DHPublicNumbers(
                peer_public_key_value, 
                self._dh_params.parameter_numbers()
            )
            peer_public_key = peer_public_numbers.public_key()
            
            # Derive shared key
            shared_key = self._session_keys[client_id]['private_key'].exchange(peer_public_key)
            
            # Derive final session key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'TLS terminator session key'
            ).derive(shared_key)
            
            self._session_keys[client_id]['session_key'] = derived_key
            
            self._log_message(LOG_INFO, f"Key exchange completed for {client_id}")
            return derived_key
        except Exception as e:
            self._log_message(LOG_ERROR, f"Error completing key exchange: {e}")
            return None
    def _encrypt_data(self, client_id: str, data: bytes) -> bytes:
        """Encrypt data using the session key for a specific client

        Args:
            client_id (str): Client identifier
            data (bytes): Data to encrypt

        Returns:
            bytes: Encrypted data with IV prepended
        """
        if client_id not in self._session_keys or not self._session_keys[client_id].get('session_key'):
            self._log_message(LOG_ERROR, f"No session key available for {client_id}")
            return None
            
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._session_keys[client_id]['session_key']),
                modes.CBC(iv)
            )
            
            encryptor = cipher.encryptor()
            
            # Ensure data is padded to block size
            padded_data = self._add_padding(data)
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + ciphertext
            return iv + ciphertext
        except Exception as e:
            self._log_message(LOG_ERROR, f"Encryption error: {e}")
            return None
    def _decrypt_data(self, client_id: str, encrypted_data: bytes) -> bytes:
        """Decrypt data using the session key for a specific client

        Args:
            client_id (str): Client identifier
            encrypted_data (bytes): Encrypted data with IV prepended

        Returns:
            bytes: Decrypted data
        """
        if client_id not in self._session_keys or not self._session_keys[client_id].get('session_key'):
            self._log_message(LOG_ERROR, f"No session key available for {client_id}")
            return None
            
        try:
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._session_keys[client_id]['session_key']),
                modes.CBC(iv)
            )
            
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadded_data = self._remove_padding(decrypted_data)
            
            return unpadded_data
        except Exception as e:
            self._log_message(LOG_ERROR, f"Decryption error: {e}")
            return None
    def _add_padding(self, data: bytes) -> bytes:
        """Add PKCS#7 padding to data"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    def _remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding from data"""
        padding_length = data[-1]
        return data[:-padding_length]
    def _handle_mission_from_planner(self, mission: Mission):
        """Process mission received from MissionPlanner and forward to CommunicationGateway

        Args:
            mission (Mission): Mission data
        """
        self._log_message(LOG_INFO, "Received mission from planner, processing securely")
        
        try:
            # In a real implementation, would encrypt the mission data here
            # For simulation, we're passing it through but logging the secure handling
            
            # Forward to communication gateway
            communication_q_name = COMMUNICATION_GATEWAY_QUEUE_NAME
            
            event = Event(
                source=TLSTerminator.event_source_name,
                destination=communication_q_name,
                operation="set_mission", 
                parameters=mission
            )
            
            communication_q = self._queues_dir.get_queue(communication_q_name)
            communication_q.put(event)
            
            self._log_message(LOG_INFO, "Mission securely forwarded to communication gateway")
        except Exception as e:
            self._log_message(LOG_ERROR, f"Error forwarding mission: {e}")
    def _check_events_q(self):
        """Check for new events in the queue"""
        try:
            event: Event = self._events_q.get_nowait()
            
            if not isinstance(event, Event):
                return
                
            if event.operation == 'set_mission':
                try:
                    # Handle mission from planner
                    self._handle_mission_from_planner(event.parameters)
                except Exception as e:
                    self._log_message(LOG_ERROR, f"Error handling mission: {e}")
            # Handle other operations as needed
                
        except Empty:
            # No events in queue, continue
            pass
    def _check_control_q(self):
        """Check for control commands"""
        try:
            request: ControlEvent = self._control_q.get_nowait()
            self._log_message(LOG_DEBUG, f"Processing control request: {request}")
            
            if isinstance(request, ControlEvent) and request.operation == 'stop':
                # Stop request received
                self._quit = True
                
        except Empty:
            # No control commands, continue
            pass
    def stop(self):
        """Request to stop operation"""
        self._control_q.put(ControlEvent(operation='stop'))
    def run(self):
        """Start operation of TLS terminator"""
        self._log_message(LOG_INFO, "Starting TLS terminator")
        
        while self._quit is False:
            time.sleep(self._recalc_interval_sec)
            try:
                self._check_events_q()
                self._check_control_q()
            except Exception as e:
                self._log_message(LOG_ERROR, f"Error in main loop: {e}")