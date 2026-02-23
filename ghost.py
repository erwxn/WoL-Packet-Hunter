from scapy.all import *
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
import binascii

# --- Setup UI ---
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "bold yellow",
    "danger": "bold white on red",
    "header": "bold black on white",
    "success": "bold green",
    "magic": "bold magenta"
})
console = Console(theme=custom_theme)

def log_magic_packet(target_mac, src_ip, proto):
    """Display a beautiful alert when a Magic Packet is detected"""
    console.print(Panel(
        f"[bold white]Target MAC:[/bold white] [green]{target_mac}[/green]\n"
        f"[dim]Source:[/dim] {src_ip} ({proto})",
        title="[magic]✨ MAGIC PACKET DETECTED ✨[/magic]",
        border_style="magenta",
        expand=False
    ))

def extract_mac_from_magic_packet(payload):
    """
    Checks if the payload contains a Magic Packet signature.
    Format: 6 bytes of 0xFF followed by 16 repetitions of the target MAC address.
    """
    if len(payload) < 102: # 6 + 16*6 = 102 bytes minimum
        return None
    
    # Look for the sync stream (6 bytes of 0xFF)
    sync_stream = b'\xff' * 6
    if sync_stream not in payload:
        return None
        
    # Find the start of the pattern
    start_index = payload.find(sync_stream)
    
    # The MAC address should immediately follow the sync stream
    # and be repeated 16 times (16 * 6 = 96 bytes)
    mac_data_start = start_index + 6
    mac_data_end = mac_data_start + 96
    
    if mac_data_end > len(payload):
        return None
        
    mac_data = payload[mac_data_start:mac_data_end]
    
    # Extract the first 6 bytes which should be the MAC
    possible_mac = mac_data[:6]
    
    # Verify repetition
    if possible_mac * 16 == mac_data:
        # Convert bytes to readable MAC string
        return binascii.hexlify(possible_mac, ':').decode('utf-8')
        
    return None

def packet_callback(packet):
    """Main callback for every sniffed packet"""
    try:
        if IP in packet:
            src_ip = packet[IP].src
            payload = b""
            proto = "OTHER"
            
            if UDP in packet:
                proto = "UDP"
                payload = bytes(packet[UDP].payload)
            elif TCP in packet:
                proto = "TCP"  # Less likely for WoL but possible in some encapsulation
                payload = bytes(packet[TCP].payload)
            elif Raw in packet:
                payload = bytes(packet[Raw].load)
            
            # Check payload for magic packet structure
            if payload:
                target_mac = extract_mac_from_magic_packet(payload)
                if target_mac:
                    log_magic_packet(target_mac, src_ip, proto)
                    return # Stop processing this packet after finding it
            
            # Optional: Verbose log for other packets (can be noisy)
            # console.print(f"[dim]{proto} {src_ip} -> {packet[IP].dst}[/]", end="\r")

    except Exception as e:
        # console.print(f"[red]Error parsing packet:[/red] {e}")
        pass

def start_listener():
    console.print(Panel.fit(
        "[bold green]MAGIC PACKET LISTENER STARTED[/bold green]\n"
        "[dim]Listening for Wake-on-LAN packets (EtherType 0x0842 or UDP broadcast)...[/]",
        subtitle="[italic]Press Ctrl+C to stop[/]",
        border_style="green"
    ))
    
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        console.print("\n[bold red]Listener Stopped by user[/]")
    except PermissionError:
        console.print("[bold red]ERROR: Permission denied. Run as Administrator/Root.[/]")

if __name__ == "__main__":
    start_listener()
