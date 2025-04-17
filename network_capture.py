import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from collections import defaultdict, deque
import time
from typing import Dict, Tuple, Set, List, Optional
from dataclasses import dataclass, field


# TODO: ARP if needed
@dataclass
class Connection:
    start_time: float = 0
    last_time: float = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    count: int = 0
    srv_count: int = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    same_srv_connections: List[Tuple] = field(default_factory=list)
    diff_host_services: Set[int] = field(default_factory=set)
    flags: List[str] = field(default_factory=list)

@dataclass
class HostStats:
    count: int = 0
    srv_count: int = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    same_src_port_rate: float = 0
    srv_diff_host_rate: float = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    last_port: int = 0
    connections: deque = field(default_factory=lambda: deque(maxlen=100))

class NetworkCapture:
    __slots__ = ('interface', 'timeout', 'connections', 'host_stats',
                 'recent_connections', 'two_second_connections', 'detect_internal')

    # ports to check srv/services
    COMMON_PORTS = {
        80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 20: 'ftp_data',
        23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3', 143: 'imap',
        512: 'exec', 513: 'login', 514: 'shell', 520: 'efs'
    }

    PROTOCOL_TYPES = {6: 'tcp', 17: 'udp', 1: 'icmp'}

    def __init__(self, interface: str = scapy.conf.iface, timeout: int = 60, detect_internal: bool = False):
        self.interface = interface
        self.timeout = timeout
        self.connections: Dict[Tuple, Connection] = defaultdict(Connection)
        self.host_stats: Dict[str, HostStats] = defaultdict(HostStats)
        self.recent_connections: deque = deque(maxlen=100)
        self.two_second_connections: List[Tuple[Connection, float]] = []
        self.detect_internal = detect_internal

    def _is_internal_traffic(self, packet: scapy.Packet) -> bool:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            return self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)
        return False

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        return ip.startswith(('10.', '172.16.', '192.168.'))

    def extract_features(self, packet: scapy.Packet) -> Optional[Dict]:
        if IP in packet:
            if not self.detect_internal and self._is_internal_traffic(packet):
                return None
            
            if TCP in packet or UDP in packet or ICMP in packet:
                return self._extract_ip_features(packet)
        return None

    def _get_connection_key(self, ip: IP, transport) -> Tuple:
        return (ip.src, ip.dst, getattr(transport, 'sport', 0), getattr(transport, 'dport', 0), ip.proto)

    def _update_connection(self, conn: Connection, packet: scapy.Packet, current_time: float) -> None:
        if conn.start_time == 0:
            conn.start_time = current_time

        conn.last_time = current_time
        conn.src_bytes += len(packet)
        conn.dst_bytes += len(packet.payload)
        
        self._update_two_second_stats(conn)
        self._update_connection_services(conn, packet)
        self._update_flags(conn, packet)

    def _update_two_second_stats(self, conn: Connection) -> None:
        current_time = time.time()
        self.two_second_connections = [(c, t) for c, t in self.two_second_connections if current_time - t <= 2]
        self.two_second_connections.append((conn, current_time))

        conn.count = sum(1 for c, _ in self.two_second_connections if c == conn)
        conn.srv_count = sum(1 for c, _ in self.two_second_connections if c.same_srv_connections == conn.same_srv_connections)

    def _update_connection_services(self, conn: Connection, packet: scapy.Packet) -> None:
        if TCP in packet or UDP in packet:
            transport = packet[TCP] if TCP in packet else packet[UDP]
            if transport.dport == transport.sport:
                conn.same_srv_connections.append((packet[IP].src, packet[IP].dst, transport.sport, transport.dport))
            else:
                conn.diff_host_services.add(transport.dport)

    def _update_flags(self, conn: Connection, packet: scapy.Packet) -> None:
        if TCP in packet:
            flag = self._get_flag(packet[TCP])
            conn.flags.append(flag)

    def _update_host_stats(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> None:
        host_stats = self.host_stats[dst_ip]
        host_stats.count += 1
        host_stats.srv_count += 1 if host_stats.last_port == dst_port else 0
        host_stats.last_port = dst_port

        recent_connections = list(self.recent_connections)
        recent_connections.append((src_ip, dst_ip, src_port, dst_port, proto, time.time()))

        if recent_connections:
            host_stats.same_srv_rate = sum(1 for conn in recent_connections if conn[3] == dst_port) / len(recent_connections)
            host_stats.diff_srv_rate = sum(1 for conn in recent_connections if conn[3] != dst_port) / len(recent_connections)
            host_stats.same_src_port_rate = sum(1 for conn in recent_connections if conn[2] == src_port) / len(recent_connections)
            host_stats.srv_diff_host_rate = sum(1 for conn in recent_connections if conn[1] != dst_ip) / len(recent_connections)
            host_stats.serror_rate = sum(1 for conn in recent_connections if self._is_serror(
                self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
            host_stats.srv_serror_rate = sum(1 for conn in recent_connections if self._is_serror(
                self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
            host_stats.rerror_rate = sum(1 for conn in recent_connections if self._is_rerror(
                self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
            host_stats.srv_rerror_rate = sum(1 for conn in recent_connections if self._is_rerror(
                self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)

        self.recent_connections = deque(recent_connections, maxlen=100)

    def _extract_ip_features(self, packet: scapy.Packet) -> Dict:
        ip = packet[IP]
        transport = packet.getlayer(TCP) or packet.getlayer(UDP) or packet.getlayer(ICMP)
        conn_key = self._get_connection_key(ip, transport)
        conn = self.connections[conn_key]
        current_time = time.time()

        self._update_connection(conn, packet, current_time)
        self._update_host_stats(ip.src, ip.dst, getattr(transport, 'sport', 0), getattr(transport, 'dport', 0), ip.proto)

        return self._extract_features_dict(packet, ip, transport, conn)

    def _extract_features_dict(self, packet: scapy.Packet, ip: IP, transport, conn: Connection) -> Dict:
        return {
            'timestamp': packet.time,  # packet capture timestamp
            'rawBytes': bytes(packet).hex(),  # raw packet bytes as hex string
            'duration': conn.last_time - conn.start_time,
            'protocol_type': self._get_protocol_type(ip.proto),
            'service': self._get_service(transport.dport),
            'flag': self._get_flag(transport),
            'src_bytes': conn.src_bytes,
            'dst_bytes': conn.dst_bytes,
            'land': int(ip.src == ip.dst and getattr(transport, 'sport', 0) == getattr(transport, 'dport', 0)),
            'wrong_fragment': self._get_wrong_fragment(ip),
            'urgent': self._get_urgent(transport),
            # count use as the number of packets that were processed in 2 seconds window.
            'count': conn.count, 
            'srv_count': conn.srv_count,
            'serror_rate': self._calculate_rate(conn, self._is_serror),
            'srv_serror_rate': self._calculate_srv_rate(conn, self._is_serror),
            'rerror_rate': self._calculate_rate(conn, self._is_rerror),
            'srv_rerror_rate': self._calculate_srv_rate(conn, self._is_rerror),
            'same_srv_rate': self._calculate_rate(conn, self._is_same_srv),
            'diff_srv_rate': self._calculate_rate(conn, self._is_diff_srv),
            'srv_diff_host_rate': self._calculate_srv_rate(conn, self._is_diff_host),
            'dst_host_count': self.host_stats[ip.dst].count,
            'dst_host_srv_count': self.host_stats[ip.dst].srv_count,
            'dst_host_same_srv_rate': self.host_stats[ip.dst].same_srv_rate,
            'dst_host_diff_srv_rate': self.host_stats[ip.dst].diff_srv_rate,
            'dst_host_same_src_port_rate': self.host_stats[ip.dst].same_src_port_rate,
            'dst_host_srv_diff_host_rate': self.host_stats[ip.dst].srv_diff_host_rate,
            'dst_host_serror_rate': self.host_stats[ip.dst].serror_rate,
            'dst_host_srv_serror_rate': self.host_stats[ip.dst].srv_serror_rate,
            'dst_host_rerror_rate': self.host_stats[ip.dst].rerror_rate,
            'dst_host_srv_rerror_rate': self.host_stats[ip.dst].srv_rerror_rate
        }

    def _calculate_rate(self, conn: Connection, condition) -> float:
        if conn.count == 0:
            return 0.0
        return sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.count

    def _calculate_srv_rate(self, conn: Connection, condition) -> float:
        if conn.srv_count == 0:
            return 0.0
        return sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.srv_count

    def _is_serror(self, conn: Connection) -> bool:
        return any('S' in flag and 'F' not in flag and 'A' not in flag for flag in conn.flags)

    def _is_rerror(self, conn: Connection) -> bool:
        return any('R' in flag for flag in conn.flags)

    def _is_same_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) == 1

    def _is_diff_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) > 1

    def _is_diff_host(self, conn: Connection) -> bool:
        return len(conn.diff_host_services) > 1

    @staticmethod
    def _get_protocol_type(protocol: int) -> str:
        return NetworkCapture.PROTOCOL_TYPES.get(protocol, 'other')

    @staticmethod
    def _get_service(port: int) -> str:
        return NetworkCapture.COMMON_PORTS.get(port, 'other')

    @staticmethod
    def _get_flag(transport) -> str:
        if isinstance(transport, ICMP):
            return 'SF'

        if not hasattr(transport, 'flags'):
            return 'OTH'

        flags = ''.join(flag for bit, flag in [
            (0x01, 'F'), (0x02, 'S'), (0x04, 'R'),
            (0x08, 'P'), (0x10, 'A'), (0x20, 'U')
        ] if transport.flags & bit)

        if not flags:
            return 'OTH'
        elif 'S' in flags and 'F' in flags:
            return 'SF'
        elif 'S' in flags:
            return 'S0'
        elif 'F' in flags:
            return 'REJ'
        elif 'R' in flags:
            return 'RSTO'
        elif 'R' in flags and 'A' in flags:
            return 'RSTR'
        else:
            return flags

    @staticmethod
    def _get_wrong_fragment(ip: IP) -> int:
        return int(ip.frag != 0 or ip.flags.MF)

    @staticmethod
    def _get_urgent(transport) -> int:
        return int(getattr(transport, 'urgptr', 0) > 0 if hasattr(transport, 'urgptr') else 0)

    def start_capture(self) -> None:
        print(f"Starting packet capture on interface {self.interface}")
        scapy.sniff(iface=self.interface, prn=self.process_packet, store=False, timeout=360)
        # print(len(self.connections))

    def process_packet(self, packet: scapy.Packet) -> Optional[Dict]:
        # print(packet.json())
        return self.extract_features(packet)

    def start_capture_2s(self) -> None:
        print(f"Starting packet capture on interface {self.interface}")
        
        start_time = time.time()
        packets = []
        
        # Capture packets for 2 seconds
        packets = scapy.sniff(iface=self.interface, timeout=2)
        
        # Process all captured packets and measure time
        processing_start = time.time()
        for packet in packets:
            self.process_packet(packet)
        processing_end = time.time()
        
        total_packets = len(packets)
        processing_time = processing_end - processing_start
        
        print(f"\nNetworkCapture Statistics:")
        print(f"Total packets captured in 2 seconds: {total_packets}")
        print(f"Total processing time: {processing_time:.4f} seconds")
        print(f"Average processing time per packet: {(processing_time/total_packets if total_packets else 0):.6f} seconds")

if __name__ == "__main__":
    extractor = NetworkCapture()
    extractor.start_capture()
