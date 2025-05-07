import json
from network_feature_extractor import NetworkFeatureExtractor
import scapy.all as scapy
import pika


class RabbitMQInterface:
    def __init__(self, user: str = "guest", password: str = "guest", host: str = "localhost", port: int = 5672, queue: str = "network-capture"):
        # self.user = os.getenv('RABBITMQ_USER', 'guest')
        # self.password = os.getenv('RABBITMQ_PASSWORD', 'guest')
        # self.host = os.getenv('RABBITMQ_HOST', 'localhost')
        # self.port = int(os.getenv('RABBITMQ_PORT', 5672))
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.connection = None
        self.channel = None
        self.queue_name = queue
        self.connect()

    def connect(self):
        """Connect to RabbitMQ and check the exchange."""
        parameters = pika.ConnectionParameters(
            host=self.host, port=self.port)
        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name, durable=True)

    def close(self):
        """Close RabbitMQ connection."""
        try:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
        except Exception as e:
            print(f"Error closing connection: {e}")

    def publish(self, message):
        """Publish message to RabbitMQ with retry mechanism."""
        max_retries = 3

        for attempt in range(max_retries):
            try:
                if not self.connection or self.connection.is_closed:
                    self.reconnect()

                self.channel.basic_publish(
                    exchange='',
                    routing_key=self.queue_name,
                    body=message,
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                        content_type='application/json',
                    )
                )
                return True
            except Exception as e:
                print(f"Publish attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    continue
                else:
                    print("Max retries reached, giving up")
                    return False


class NetworkCaptureModule(NetworkFeatureExtractor):
    def __init__(self, rabbitmq: RabbitMQInterface, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rabbitmq = rabbitmq
        # packets that failed to sent
        self._packets_failed = 0

    def start_capture(self) -> None:
        print(f"Starting packet capture on interface {self.interface}")
        try:
            scapy.sniff(iface=self.interface, filter="tcp or udp or icmp",
                        prn=self.process_packet, store=False)
        except Exception as e:
            print(f"Capture error: {e}")

    def process_packet(self, packet: scapy.Packet) -> None:
        """extract features from packet and send to RabbitMQ"""
        features = self.extract_features(packet)
        if features:
            message = json.dumps(features)
            if not self.rabbitmq.publish(message):
                self._packets_failed += 1
                print("Failed to send packet")


def main():
    rabbitMQ = RabbitMQInterface(queue="ids-queue")
    network_capture = NetworkCaptureModule(rabbitMQ)
    network_capture.start_capture()


if __name__ == "__main__":
    main()
