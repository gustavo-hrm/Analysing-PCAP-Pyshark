import pyshark

def analyze_pcap(file_path):
    try:
        # Use Pyshark to read the pcap file
        capture = pyshark.FileCapture(file_path, display_filter='http')

        http_packet_count = 0
        print("Analyzing HTTP packets...")

        for packet in capture:
            http_packet_count += 1
            if 'http' in packet:
                print(f"HTTP Packet: {packet.http}")
            else:
                print("No HTTP Payload found in this packet.")

        print(f"Total HTTP packets analyzed: {http_packet_count}")

        if http_packet_count == 0:
            print("No HTTP packets were captured. Check the pcap file and your capture method.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    analyze_pcap("http_pcap.pcapng")