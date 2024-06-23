import logging
from scapy.all import ARP, Ether, srp
import socket
import subprocess

# Configure logging
logging.basicConfig(filename='network_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def get_devices_info(ip_range="192.168.0.0/24"):
    try:
        # Create an ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send the packet and receive the response
        result, _ = srp(packet, timeout=3, verbose=0)

        # Parse the result
        devices = []
        for sent, received in result:
            try:
                # Get device hostname
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "Unknown"

            devices.append({
                "IP": received.psrc,
                "MAC": received.hwsrc,
                "Hostname": hostname
            })

        if not devices:
            logging.info("No devices found.")
        return devices

    except PermissionError as e:
        logging.error(
            f"Permission error: {e}. Try running the script with sudo.")
        return []
    except Exception as e:
        logging.error(f"Error: {e}")
        return []


def block_device(ip_address):
    try:
        subprocess.check_call(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        subprocess.check_call(
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"])
        logging.info(f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP: {ip_address}. Error: {e}")


def rule_exists(chain, ip_address, direction):
    try:
        result = subprocess.check_output(
            ["sudo", "iptables", "-C", chain, direction, ip_address, "-j", "DROP"])
        return True
    except subprocess.CalledProcessError:
        return False


def unblock_device(ip_address):
    try:
        if rule_exists("INPUT", ip_address, "-s"):
            subprocess.check_call(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])
            logging.info(f"Unblocked IP: {ip_address} from INPUT chain")
        else:
            logging.info(f"No INPUT rule found for IP: {ip_address}")

        if rule_exists("OUTPUT", ip_address, "-d"):
            subprocess.check_call(
                ["sudo", "iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"])
            logging.info(f"Unblocked IP: {ip_address} from OUTPUT chain")
        else:
            logging.info(f"No OUTPUT rule found for IP: {ip_address}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to unblock IP: {ip_address}. Error: {e}")


# Example usage
devices = get_devices_info("192.168.0.0/24")
if devices:
    for device in devices:
        logging.info(
            f"IP: {device['IP']}, MAC: {device['MAC']}, Hostname: {device['Hostname']}")
        # Block or unblock based on conditions
        if device['IP'] == "192.168.0.19":  # Example condition
            block_device(device['IP'])
        else:
            unblock_device(device['IP'])
else:
    logging.info("No devices found or an error occurred.")
