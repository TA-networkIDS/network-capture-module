from network_capture import NetworkCapture
from network_feature_extractor import NetworkFeatureExtractor
import time

def main():
    # Test NetworkCapture
    print("Testing NetworkCapture...")
    nc = NetworkCapture()
    nc.start_capture_2s()
    
    print("\n" + "="*50 + "\n")
    
    # Test NetworkFeatureExtractor
    print("Testing NetworkFeatureExtractor...")
    nfe = NetworkFeatureExtractor()
    nfe.start_capture_2s()

if __name__ == "__main__":
    main()