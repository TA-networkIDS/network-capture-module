import time
import statistics
from network_feature_extractor import NetworkFeatureExtractor
import scapy.all as scapy


class TimedFeatureExtractor(NetworkFeatureExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processing_times = []
        self.total_packets = 0
        self.start_time = None
        self.stats_interval = 5  # Print stats every 5 seconds
        self.last_stats_time = 0
        self.running = True

    def process_packet(self, packet: scapy.Packet):
        if not self.running:
            return

        if self.start_time is None:
            self.start_time = time.time()
            self.last_stats_time = self.start_time

        start_process = time.time()
        features = self.extract_features(packet)
        end_process = time.time()

        if features:  # Only count packets that were actually processed
            processing_time = (end_process - start_process) * 1000  # Convert to milliseconds
            self.processing_times.append(processing_time)
            self.total_packets += 1

            # Print stats every X seconds
            current_time = time.time()
            if current_time - self.last_stats_time >= self.stats_interval:
                self.print_stats()
                self.last_stats_time = current_time

        return features

    def print_stats(self):
        if not self.processing_times:
            return

        current_time = time.time()
        elapsed_time = current_time - self.start_time
        
        # Calculate statistics
        avg_time = statistics.mean(self.processing_times)
        max_time = max(self.processing_times)
        min_time = min(self.processing_times)
        packets_per_second = self.total_packets / elapsed_time
        
        print("\n=== Performance Statistics ===")
        print(f"Total packets processed: {self.total_packets}")
        print(f"Total elapsed time: {elapsed_time:.2f} seconds")
        print(f"Average packets/second: {packets_per_second:.2f}")
        print(f"Average processing time: {avg_time:.3f}ms")
        print(f"Maximum processing time: {max_time:.3f}ms")
        print(f"Minimum processing time: {min_time:.3f}ms")
        print("===========================\n")

    def start_capture(self, duration=None):
        """
        Start packet capture with optional duration
        Args:
            duration: Number of seconds to capture. If None, captures until interrupted
        """
        self.running = True
        print(f"Starting network capture for {duration if duration else 'unlimited'} seconds...")
        
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                timeout=duration,
                stop_filter=lambda _: not self.running
            )
        except KeyboardInterrupt:
            self.running = False
            print("\nCapture stopped by user")
        
        self.print_final_stats()

    def stop_capture(self):
        """Stop the packet capture"""
        self.running = False

    def print_final_stats(self):
        if self.processing_times:
            print("\n=== Final Statistics ===")
            print(f"Total packets processed: {self.total_packets}")
            print(f"Average processing time: {statistics.mean(self.processing_times):.3f}ms")
            print(f"Maximum processing time: {max(self.processing_times):.3f}ms")
            print(f"Minimum processing time: {min(self.processing_times):.3f}ms")
            print("=====================")
        else:
            print("\nNo packets were processed")

def main():
    try:
        # Create extractor with 30-second capture duration
        extractor = TimedFeatureExtractor()
        
        # Start capture for 30 seconds
        extractor.start_capture(duration=2)
        
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()