PLANNER_QUEUE_NAME = "planner"
COMMUNICATION_GATEWAY_QUEUE_NAME = "communication"
CONTROL_SYSTEM_QUEUE_NAME = "control"
SENSORS_QUEUE_NAME = "sensors"
SERVOS_QUEUE_NAME = "servos"
NAVIGATION_QUEUE_NAME = "navigation"
SITL_QUEUE_NAME = "sitl"
CARGO_BAY_QUEUE_NAME = "cargo"
SITL_TELEMETRY_QUEUE_NAME = "sitl.mqtt"
MISSION_SENDER_QUEUE_NAME = "planner.mqtt"
SAFETY_BLOCK_QUEUE_NAME = "safety"
SECURITY_MONITOR_QUEUE_NAME = "security"
TLS_TERMINATOR_QUEUE_NAME = "tls_terminator"

DEFAULT_LOG_LEVEL = 2  # 1 - errors, 2 - verbose, 3 - debug
LOG_FAILURE = 0
LOG_ERROR = 1
LOG_INFO  = 2
LOG_DEBUG = 3
CRITICALITY_STR = [
    "ОТКАЗ", "ОШИБКА", "ИНФО", "ОТЛАДКА"
]

TLS_CERT_PATH = "certs/server.crt"
TLS_KEY_PATH = "certs/server.key"
TRUSTED_ROOT_CA_PATH = "certs/ca_root.crt"