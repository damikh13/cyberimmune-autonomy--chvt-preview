from geopy import Point as GeoPoint
import math
from time import sleep
from src.config import CONTROL_SYSTEM_QUEUE_NAME,CARGO_BAY_QUEUE_NAME,COMMUNICATION_GATEWAY_QUEUE_NAME,NAVIGATION_QUEUE_NAME, SAFETY_BLOCK_QUEUE_NAME, SECURITY_MONITOR_QUEUE_NAME, SERVOS_QUEUE_NAME, LOG_DEBUG, LOG_ERROR, LOG_INFO
from src.communication_gateway import BaseCommunicationGateway
from src.control_system import BaseControlSystem
from src.navigation_system import BaseNavigationSystem
from src.queues_dir import QueuesDirectory
from src.safety_block import BaseSafetyBlock
from src.event_types import Event
from src.security_policy_type import SecurityPolicy
from src.security_monitory import BaseSecurityMonitor
from src.servos import Servos
from src.sitl import SITL
from src.cargo_bay import CargoBay
from src.mission_planner import MissionPlanner
from src.mission_planner_mqtt import MissionSender
from src.mission_planner import Mission
from src.sitl_mqtt import TelemetrySender
from src.system_wrapper import SystemComponentsContainer
from src.wpl_parser import WPLParser
from src.mission_type import GeoSpecificSpeedLimit
from src.tls_terminator import TLSTerminator
from src.config import TLS_CERT_PATH, TLS_KEY_PATH

class SecurityMonitor(BaseSecurityMonitor):
    """ класс монитора безопасности """

    def __init__(self, queues_dir):
        super().__init__(queues_dir)
        self._init_set_security_policies()
    def _init_set_security_policies(self):
        """ инициализация политик безопасности """
        default_policies = [
            SecurityPolicy(
                source=COMMUNICATION_GATEWAY_QUEUE_NAME,
                destination=CONTROL_SYSTEM_QUEUE_NAME,
                operation='set_mission'
            ),
            SecurityPolicy(
                source=COMMUNICATION_GATEWAY_QUEUE_NAME,
                destination=SAFETY_BLOCK_QUEUE_NAME,
                operation='set_mission'
            ),
            SecurityPolicy(
                source=CONTROL_SYSTEM_QUEUE_NAME,
                destination=SAFETY_BLOCK_QUEUE_NAME,
                operation='set_speed'
            ),
            SecurityPolicy(
                source=SAFETY_BLOCK_QUEUE_NAME,
                destination=SERVOS_QUEUE_NAME,
                operation='set_speed'
            ),
            SecurityPolicy(
                source=CONTROL_SYSTEM_QUEUE_NAME,
                destination=SAFETY_BLOCK_QUEUE_NAME,
                operation='set_direction'
            ),
            SecurityPolicy(
                source=SAFETY_BLOCK_QUEUE_NAME,
                destination=SERVOS_QUEUE_NAME,
                operation='set_direction'
            ),
            SecurityPolicy(
                source=SAFETY_BLOCK_QUEUE_NAME,
                destination=CARGO_BAY_QUEUE_NAME,
                operation='lock_cargo'
            ),
            SecurityPolicy(
                source=SAFETY_BLOCK_QUEUE_NAME,
                destination=CARGO_BAY_QUEUE_NAME,
                operation='release_cargo'
            ),
            SecurityPolicy(
                source=CONTROL_SYSTEM_QUEUE_NAME,
                destination=NAVIGATION_QUEUE_NAME,
                operation="request_position"),
            SecurityPolicy(
                source=NAVIGATION_QUEUE_NAME,
                destination=SAFETY_BLOCK_QUEUE_NAME,
                operation="position_update"),
            SecurityPolicy(
                source=NAVIGATION_QUEUE_NAME,
                destination=CONTROL_SYSTEM_QUEUE_NAME,
                operation="position_update"),
            SecurityPolicy(
                source=CONTROL_SYSTEM_QUEUE_NAME,
                destination=SAFETY_BLOCK_QUEUE_NAME,
                operation="release_cargo"),
            SecurityPolicy(
                source=CONTROL_SYSTEM_QUEUE_NAME,  # "control"
                destination=SAFETY_BLOCK_QUEUE_NAME,  # "safety"
                operation='lock_cargo'
            )
        ]
        self.set_security_policies(policies=default_policies)        
    def set_security_policies(self, policies):
        """ установка новых политик безопасности """
        self._security_policies = policies
        self._log_message(
            LOG_INFO, f"изменение политик безопасности: {policies}")
    def _check_event(self, event: Event):
        """ проверка входящих событий """
        self._log_message(
            LOG_DEBUG, f"проверка события {event}, по умолчанию выполнение запрещено")

        authorized = False
        request = SecurityPolicy(
            source=event.source,
            destination=event.destination,
            operation=event.operation)

        if request in self._security_policies:
            self._log_message(
                LOG_DEBUG, "событие разрешено политиками, выполняем")
            authorized = True

        if authorized is False:
            self._log_message(LOG_ERROR, f"событие не разрешено политиками безопасности! {event}")
        return authorized
class CommunicationGateway(BaseCommunicationGateway):
    """CommunicationGateway класс для реализации логики взаимодействия
    с системой планирования заданий

    Работает в отдельном процессе, поэтому создаётся как наследник класса Process
    """
    def _send_mission_to_consumers(self):
        """ метод для отправки сообщения с маршрутным заданием в систему управления """
        
        control_q_name = CONTROL_SYSTEM_QUEUE_NAME
        safety_q_name = SAFETY_BLOCK_QUEUE_NAME

        event = Event(source=BaseCommunicationGateway.event_source_name,
                      destination=control_q_name,
                      operation="set_mission", parameters=self._mission)
        safety_event = Event(source=BaseCommunicationGateway.event_source_name,
                      destination=safety_q_name,
                      operation="set_mission", parameters=self._mission)

        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event)
        security_monitor_q.put(safety_event)
class ControlSystem(BaseControlSystem):
    """ControlSystem блок расчёта управления """

    def _send_speed_and_direction_to_consumers(self, speed, direction):        
        safety_q_name = SAFETY_BLOCK_QUEUE_NAME

        event_speed = Event(source=BaseControlSystem.event_source_name,
                            destination=safety_q_name,
                            operation="set_speed",
                            parameters=speed
                            )
        event_direction = Event(source=BaseControlSystem.event_source_name,
                                destination=safety_q_name,
                                operation="set_direction",
                                parameters=direction
                                )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event_direction)
        security_monitor_q.put(event_speed)
    def _lock_cargo(self):
        """ заблокировать грузовой отсек """
        safety_q_name = SAFETY_BLOCK_QUEUE_NAME

        safety_event = Event(source=BaseControlSystem.event_source_name,
                            destination=safety_q_name,
                            operation="lock_cargo",
                            parameters=None
                            )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(safety_event)
    def _release_cargo(self):
        """ открыть грузовой отсек """
        safety_q_name = SAFETY_BLOCK_QUEUE_NAME
        safety_event = Event(source=BaseControlSystem.event_source_name,
                      destination=safety_q_name,
                      operation="release_cargo",
                      parameters=None
                      )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(safety_event)
class NavigationSystem(BaseNavigationSystem):
    """Класс навигационного блока"""
    def _send_position_to_consumers(self):        
        control_q_name = CONTROL_SYSTEM_QUEUE_NAME
        safety_q_name = SAFETY_BLOCK_QUEUE_NAME

        event = Event(
            source=BaseNavigationSystem.event_source_name,
            destination=control_q_name,
            operation="position_update",
            parameters=self._position
        )
        safety_event = Event(
            source=BaseNavigationSystem.event_source_name,
            destination=safety_q_name,
            operation="position_update",
            parameters=self._position
        )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event)
        security_monitor_q.put(safety_event)
class SafetyBlock(BaseSafetyBlock):
    """ класс ограничений безопасности """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cargo_locked = True  # Флаг состояния грузового отсека

    @staticmethod
    def angular_difference(angle1: float, angle2: float) -> float:
        diff = abs(angle1 - angle2) % 360
        return diff if diff <= 180 else 360 - diff
    def _set_new_direction(self, direction: float):
        """ установка нового направления перемещения """
        # self._log_message(LOG_INFO, f"текущие координаты: {self._position}")
        # self._log_message(LOG_DEBUG, f"маршрутное задание: {self._mission}")
        # self._log_message(LOG_DEBUG, f"состояние маршруте: {self._route}")
        if not self._mission or not self._position or not self._route:
            self._log_message(LOG_ERROR, "Неизвестный путь или местоположение!")
            self._speed = 0
            self._send_speed_to_consumers()
            self._send_lock_cargo_to_consumers()
            return
        else:
            next_point = self._route.next_point()
            if not next_point:
                self._log_message(LOG_INFO, "Нет следующей точки маршрута.")
                self._direction = direction
                self._send_direction_to_consumers()
                self._speed = 0
                self._send_speed_to_consumers()
                self._send_lock_cargo_to_consumers()
                return
            
            calculated_bearing = self._calculate_bearing(self._position, next_point)
            
            # diff = abs(calculated_bearing - direction)
            diff = SafetyBlock.angular_difference(calculated_bearing, direction)
            self._log_message(LOG_DEBUG, f"calculated_bearing: {calculated_bearing}, requested direction: {direction}, diff: {diff}")
            
            if diff > 10:
                self._log_message(LOG_ERROR, f"принудительная установка направления! Запрошенное направление {direction}, расчётное {calculated_bearing}")
                self._send_lock_cargo_to_consumers()

            self._direction = calculated_bearing
            self._send_direction_to_consumers()
    def _calculate_bearing(self, start: GeoPoint, end: GeoPoint) -> float:
        """ Расчет направления движения в градусах (0-360) """
        delta_longitude = end.longitude - start.longitude
        x = math.sin(math.radians(delta_longitude)) * math.cos(math.radians(end.latitude))
        y = (math.cos(math.radians(start.latitude)) * math.sin(math.radians(end.latitude)) -
            math.sin(math.radians(start.latitude)) * math.cos(math.radians(end.latitude)) *
            math.cos(math.radians(delta_longitude)))
        initial_bearing_rad = math.atan2(x, y)
        initial_bearing_deg = math.degrees(initial_bearing_rad)
        return (initial_bearing_deg + 360) % 360
    def _set_new_speed(self, speed: float):
        """ установка новой скорости """
        if not self._mission or not self._position or not self._route:
            self._log_message(LOG_ERROR, "Неизвестный путь или местоположение!")
            self._speed = 0
            self._send_speed_to_consumers()
            self._send_lock_cargo_to_consumers()
            return
        else:
            allowed_speed = self._route.calculate_speed()
            if speed > allowed_speed:
                self._log_message(LOG_ERROR, f"принудительная установка скорости! Запрошенная скорость {speed}, разрешённая {allowed_speed}")
                self._speed = allowed_speed
                self._send_lock_cargo_to_consumers()
            else:
                self._speed = speed
        self._send_speed_to_consumers()
    def _send_speed_to_consumers(self):
        self._log_message(LOG_DEBUG, "отправляем скорость получателям")

        servos_q_name = SERVOS_QUEUE_NAME

        # отправка сообщения с желаемой скоростью
        event_speed = Event(source=self.event_source_name,
                            destination=servos_q_name,
                            operation="set_speed",
                            parameters=self._speed
                            )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event_speed)
    def _send_direction_to_consumers(self):
        self._log_message(LOG_DEBUG, "отправляем направление получателям")

        servos_q_name = SERVOS_QUEUE_NAME

        # отправка сообщения с желаемой скоростью
        event_direction = Event(source=self.event_source_name,
                            destination=servos_q_name,
                            operation="set_direction",
                            parameters=self._direction
                            )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event_direction)
    def _lock_cargo(self, _):
        self._send_lock_cargo_to_consumers()
    def _release_cargo(self, _):
        if not self._mission or not self._position or not self._route:
            self._log_message(LOG_ERROR, "Неизвестный путь или местоположение!")
            self._speed = 0
            self._send_speed_to_consumers()
            self._send_lock_cargo_to_consumers()
            return 
        if not self._route.route_finished:
            self._log_message(LOG_INFO, "Маршрут не завершён, выгрузка невозможна!")
            self._send_lock_cargo_to_consumers()
            return
        self._send_release_cargo_to_consumers()
    def _send_lock_cargo_to_consumers(self):
        if self._cargo_locked:
            return
        self._log_message(LOG_DEBUG, "Отправляем команду на блокировку грузового отсека")
        self._cargo_locked = True # Отмечаем, что отсек заблокирован
        event = Event(
            source=self.event_source_name,
            destination=CARGO_BAY_QUEUE_NAME,
            operation="lock_cargo",
            parameters=None
        )

        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event)
    def _send_release_cargo_to_consumers(self):
        if not self._cargo_locked:
            return
        self._log_message(LOG_DEBUG, "Отправляем команду на разблокировку грузового отсека")
        self._cargo_locked = False  # Отмечаем, что отсек разблокирован
        event = Event(
            source=self.event_source_name,
            destination=CARGO_BAY_QUEUE_NAME,
            operation="release_cargo",
            parameters=None
        )
        security_monitor_q = self._queues_dir.get_queue(SECURITY_MONITOR_QUEUE_NAME)
        security_monitor_q.put(event)

queues_dir = QueuesDirectory()  

communication_gateway = CommunicationGateway(queues_dir=queues_dir)
control_system = ControlSystem(queues_dir=queues_dir)
navigation_system = NavigationSystem(queues_dir=queues_dir)

afcs_present = True
car_id = "m5"
wpl_file = "module2.wpl"

parser = WPLParser(wpl_file)    
points = parser.parse()

# обновите скоростные ограничения для вашего маршрута!
speed_limits = [
    GeoSpecificSpeedLimit(0, 60),
    GeoSpecificSpeedLimit(19, 110),
    GeoSpecificSpeedLimit(26, 60),
]

home = points[0]
mission = Mission(home=home, waypoints=points,speed_limits=speed_limits, armed=True)

# каталог очередей для передачи сообщений между блоками
queues_dir = QueuesDirectory() 

# создание блоков передачи данных в СУПА
if afcs_present:
    mission_sender = MissionSender(
        queues_dir=queues_dir, client_id=car_id, log_level=LOG_ERROR)
    telemetry_sender = TelemetrySender(
        queues_dir=queues_dir, client_id=car_id, log_level=LOG_ERROR)

# создание основных функциональных блоков
mission_planner = MissionPlanner(
    queues_dir, afcs_present=afcs_present, mission=mission)

sitl = SITL(
    queues_dir=queues_dir, position=home,
    car_id=car_id, post_telemetry=afcs_present, log_level=LOG_ERROR)

tls_terminator = TLSTerminator(
    queues_dir=queues_dir, 
    cert_path=TLS_CERT_PATH, 
    key_path=TLS_KEY_PATH, 
    log_level=LOG_INFO
)
communication_gateway = CommunicationGateway(
    queues_dir=queues_dir, log_level=LOG_ERROR)
control_system = ControlSystem(queues_dir=queues_dir, log_level=LOG_INFO)
navigation_system = NavigationSystem(
    queues_dir=queues_dir, log_level=LOG_ERROR)
servos = Servos(queues_dir=queues_dir, log_level=LOG_ERROR)
cargo_bay = CargoBay(queues_dir=queues_dir, log_level=LOG_INFO)
safety_block = SafetyBlock(queues_dir=queues_dir, log_level=LOG_INFO)
security = SecurityMonitor(queues_dir=queues_dir)


# сборка всех запускаемых блоков в одном "кузове"
system_components = SystemComponentsContainer(
components=[
        # вариант компонентов с передачей телеметрии в СУПА
        mission_sender,
        telemetry_sender,
        sitl,
        mission_planner,
        navigation_system,
        servos,
        cargo_bay,
        tls_terminator,
        communication_gateway,
        control_system,
        safety_block,
        security
    ] if afcs_present else [
        # вариант компонентов для конфигурации без СУПА
        sitl,
        mission_planner,
        navigation_system,
        servos,
        cargo_bay,
        tls_terminator,
        communication_gateway,
        control_system,
        safety_block,
        security
    ])

system_components.start()

sleep(160)

system_components.stop()

system_components.clean()