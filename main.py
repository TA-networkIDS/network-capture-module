import asyncio
import json
import threading
import websockets
from network_capture import NetworkCapture
import scapy.all as scapy


class WebSocketNetworkCapture(NetworkCapture):
    def __init__(self, websocket, loop, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.websocket = websocket
        self.loop = loop
        self._running = True

    def start_capture(self) -> None:
        print(f"Starting packet capture on interface {self.interface}")
        try:
            scapy.sniff(iface=self.interface,
                        prn=self.process_packet, store=False)
        except Exception as e:
            print(f"Capture error: {e}")
            self._running = False

    def process_packet(self, packet: scapy.Packet) -> None:
        if not self._running:
            return

        features = self.extract_features(packet)
        if features:
            # Schedule the coroutine on the event loop
            asyncio.run_coroutine_threadsafe(
                self.send_packet(features), self.loop)

    async def send_packet(self, features: dict) -> None:
        try:
            await self.websocket.send(json.dumps(features))
            # print("Packet sent successfully")
        except Exception as e:
            print(f"Failed to send packet: {e}")
            self._running = False


def start_capture_thread(capture: WebSocketNetworkCapture) -> threading.Thread:
    # Run start_capture in a separate thread
    thread = threading.Thread(target=capture.start_capture)
    thread.daemon = True
    thread.start()
    return thread


async def connect_websocket():
    uri = "ws://127.0.0.1:8888/ws"
    retry_delay = 5  # seconds between retries
    attempt = 1

    while True:
        try:
            print(f"Attempting to connect to backend (attempt {attempt})...")
            async with websockets.connect(uri) as websocket:
                print("Connected to backend WebSocket successfully!")

                # Get the current event loop
                loop = asyncio.get_running_loop()

                # Initialize capture with websocket and loop
                capture = WebSocketNetworkCapture(websocket, loop)
                capture_thread = start_capture_thread(capture)

                # Keep the connection alive
                while capture._running:
                    try:
                        await websocket.ping()
                        await asyncio.sleep(1)
                    except:
                        break

                print("Capture stopped, reconnecting...")

        except (websockets.exceptions.WebSocketException, ConnectionRefusedError) as e:
            print(f"Connection attempt {attempt} failed: {str(e)}")
            print(f"Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
            attempt += 1
        except KeyboardInterrupt:
            print("\nProgram terminated by user")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            print(f"Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
            attempt += 1


async def main():
    await connect_websocket()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
