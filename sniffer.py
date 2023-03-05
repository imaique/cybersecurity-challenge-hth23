import pyshark

capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', bpf_filter='ip and tcp port 1234')
capture.sniff(timeout=50)

for packet in capture.sniff_continuously(packet_count=5):
    print('Just arrived:', packet)