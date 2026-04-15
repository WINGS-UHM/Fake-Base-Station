"""
NGAP NGSetupRequest message handler for fake base station.
Provides methods to setup, encode, and decode NGAP messages.
"""

from pycrate_asn1dir import NGAP
from scapy.all import rdpcap
from pathlib import Path
from typing import List, Optional, Iterator, Tuple, Callable
import socket
import time
import threading


class NGSetupRequestConfig:
    """Configuration for NGSetupRequest messages."""
    
    # Values from our known ngap.pcap in test folder
    PLMN = b"\x00\xf1\x10"          # 001/01
    TAC = b"\x00\x00\x07"            # TAC = 7
    SST = b"\x01"                    # sST = 1
    GNB_ID_LEN = 22
    GNB_ID_VAL = 411
    RAN_NAME = "ocucp01"
    
    def __init__(self, plmn=None, tac=None, sst=None, gnb_id_len=None, 
                 gnb_id_val=None, ran_name=None):
        """
        Initialize configuration with optional overrides.
        
        Args:
            plmn: PLMN identity (bytes)
            tac: TAC value (bytes)
            sst: sST value (bytes)
            gnb_id_len: gNB ID length (int)
            gnb_id_val: gNB ID value (int)
            ran_name: RAN node name (str)
        """
        self.plmn = plmn or self.PLMN
        self.tac = tac or self.TAC
        self.sst = sst or self.SST
        self.gnb_id_len = gnb_id_len or self.GNB_ID_LEN
        self.gnb_id_val = gnb_id_val or self.GNB_ID_VAL
        self.ran_name = ran_name or self.RAN_NAME


def build_ngsetup_request(config : NGSetupRequestConfig = None):
    """
    Build the NGSetupRequest message structure.
    
    Args:
        config: NGSetupRequestConfig object (uses defaults if None)
        
    Returns:
        tuple: NGSetupRequest value structure for NGAP_PDU
    """
    if config is None:
        config = NGSetupRequestConfig()
    
    ngsetup_req_val = (
        "initiatingMessage",
        {
            "procedureCode": NGAP.NGAP_Constants.id_NGSetup._val,
            "criticality": NGAP.NGAP_CommonDataTypes.Criticality._cont_rev[0]
                             if hasattr(NGAP.NGAP_CommonDataTypes.Criticality, "_cont_rev")
                             else "reject",
            "value": (
                "NGSetupRequest",
                {
                    "protocolIEs": [
                        {
                            "id": NGAP.NGAP_Constants.id_GlobalRANNodeID._val,
                            "criticality": "reject",
                            "value": (
                                "GlobalRANNodeID",
                                (
                                    "globalGNB-ID",
                                    {
                                        "pLMNIdentity": config.plmn,
                                        "gNB-ID": ("gNB-ID", (config.gnb_id_val, config.gnb_id_len)),
                                    },
                                ),
                            ),
                        },
                        {
                            "id": NGAP.NGAP_Constants.id_RANNodeName._val,
                            "criticality": "ignore",
                            "value": ("RANNodeName", config.ran_name),
                        },
                        {
                            "id": NGAP.NGAP_Constants.id_SupportedTAList._val,
                            "criticality": "reject",
                            "value": (
                                "SupportedTAList",
                                [
                                    {
                                        "tAC": config.tac,
                                        "broadcastPLMNList": [
                                            {
                                                "pLMNIdentity": config.plmn,
                                                "tAISliceSupportList": [
                                                    {
                                                        "s-NSSAI": {
                                                            "sST": config.sst
                                                        }
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            ),
                        },
                        {
                            "id": NGAP.NGAP_Constants.id_DefaultPagingDRX._val,
                            "criticality": "ignore",
                            "value": ("PagingDRX", "v256"),
                        },
                    ]
                },
            ),
        },
    )
    
    return ngsetup_req_val


def encode_ngsetup_request(config : NGSetupRequestConfig = None):
    """
    Build and encode the NGSetupRequest message.
    
    Args:
        config: NGSetupRequestConfig object (uses defaults if None)
        
    Returns:
        bytes: Encoded NGAP PDU
    """
    ngsetup_req_val = build_ngsetup_request(config)
    
    # Use the generated NGAP_PDU object
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.set_val(ngsetup_req_val)
    
    encoded = pdu.to_aper()
    return encoded


def decode_ngsetup_request(encoded_data: bytes | str) -> NGAP.NGAP_PDU_Descriptions:
    """
    Decode an encoded NGSetupRequest message.
    
    Args:
        encoded_data: bytes or hex string of encoded NGAP PDU
        
    Returns:
        NGAP_PDU: Decoded PDU object
    """
    # Convert hex string to bytes if needed
    if isinstance(encoded_data, str):
        encoded_data = bytes.fromhex(encoded_data)
    
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.from_aper(encoded_data)
    
    return pdu


def print_decoded_structure(pdu):
    """
    Print the decoded PDU structure in a human-readable format.
    
    Args:
        pdu: NGAP_PDU object
    """
    print(pdu)


NGAP_SCTP_PORT = 38412
NGAP_SCTP_PPID = 60  # Payload Protocol Identifier for NGAP (3GPP TS 38.412)


def create_sctp_socket(host: str, port: int = NGAP_SCTP_PORT) -> socket.socket:
    """
    Create and connect an SCTP socket suitable for sending NGAP messages.
    NGAP runs over SCTP on port 38412 (3GPP TS 38.412).

    Requires OS-level SCTP support:
      - Linux: install lksctp-tools (apt install lksctp-tools)
      - Windows: not natively supported; use WSL or a third-party SCTP stack

    Args:
        host: Destination IP address of the AMF / 5G core
        port: SCTP port (default 38412)

    Returns:
        socket.socket: Connected SCTP one-to-one (SOCK_STREAM) socket

    Raises:
        OSError: If SCTP is not supported on this OS
    """
    IPPROTO_SCTP = getattr(socket, 'IPPROTO_SCTP', 132)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    except OSError as e:
        raise OSError(
            f"Failed to create SCTP socket: {e}\n"
            "SCTP is not supported on this system. "
            "On Linux install lksctp-tools; on Windows use WSL."
        ) from e

    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        sock.close()
        raise ConnectionRefusedError(
            f"Connection refused to {host}:{port}. "
            "Make sure an AMF / 5G core is running and listening on that address and port."
        )
    return sock


class PCAPTrafficReplayer:
    """
    Load and replay NGAP traffic from a .pcap file.
    Extracts NGAP messages from captured packets and provides
    methods to iterate through and decode them.
    """
    
    def __init__(self, pcap_file: str | Path):
        """
        Initialize the traffic replayer with a pcap file.
        
        Args:
            pcap_file: Path to the .pcap file
            
        Raises:
            FileNotFoundError: If the pcap file doesn't exist
            Exception: If the pcap file cannot be read
        """
        self.pcap_file = Path(pcap_file)
        
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        self.packets = []
        self.ngap_messages = []
        self._load_pcap()
    
    def _load_pcap(self):
        """Load and parse the pcap file."""
        try:
            self.packets = rdpcap(str(self.pcap_file))
            self._extract_ngap_messages()
        except Exception as e:
            raise Exception(f"Error reading PCAP file: {e}")
    
    def _extract_ngap_messages(self):
        """Extract NGAP payload data from packets."""
        from scapy.layers.inet import IP, UDP
        from scapy.layers.sctp import SCTP
        
        NGAP_MARKER = b'ngap'
        NGAP_MARKER_SEARCH_LIMIT = 16  # Search within first N bytes for the marker
        
        self.ngap_messages = []
        base_time = None
        
        for idx, packet in enumerate(self.packets):
            payload = None
            
            # Extract timestamp
            timestamp = packet.time if hasattr(packet, 'time') else None
            if base_time is None and timestamp is not None:
                base_time = timestamp
            
            relative_time = (timestamp - base_time) if timestamp and base_time else 0
            
            raw_data = None
            
            # Try to extract raw data from known layers first
            if packet.haslayer(SCTP) and packet[SCTP].haslayer('Raw'):
                raw_data = bytes(packet[SCTP]['Raw'].load)
            elif packet.haslayer(UDP) and packet[UDP].haslayer('Raw'):
                raw_data = bytes(packet[UDP]['Raw'].load)
            elif packet.haslayer('Raw'):
                raw_data = bytes(packet['Raw'].load)
            
            # Detect NGAP by looking for 'ngap' marker near start of raw data
            if raw_data:
                marker_pos = raw_data.find(NGAP_MARKER, 0, NGAP_MARKER_SEARCH_LIMIT + len(NGAP_MARKER))
                if marker_pos != -1:
                    # NGAP PDU starts immediately after the 'ngap' marker
                    payload = raw_data[marker_pos + len(NGAP_MARKER):]
            
            if payload:
                src_ip = packet[IP].src if packet.haslayer(IP) else None
                dst_ip = packet[IP].dst if packet.haslayer(IP) else None
                src_port = None
                dst_port = None
                
                if packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(SCTP):
                    src_port = packet[SCTP].sport
                    dst_port = packet[SCTP].dport
                
                self.ngap_messages.append({
                    'packet_index': idx,
                    'payload': payload,
                    'packet': packet,
                    'timestamp': timestamp,
                    'relative_time': relative_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port
                })
    
    def _get_all_packet_payloads(self) -> List:
        """
        Get all packet payloads from the pcap file, including non-NGAP packets.
        
        Returns:
            List of packet dictionaries with payload, timestamp, and timing info
        """
        all_packets = []
        base_time = None
        
        for idx, packet in enumerate(self.packets):
            # Extract timestamp
            timestamp = packet.time if hasattr(packet, 'time') else None
            if base_time is None and timestamp is not None:
                base_time = timestamp
            
            relative_time = (timestamp - base_time) if timestamp and base_time else 0
            
            # Try to extract any payload
            payload = None
            from scapy.layers.inet import IP, UDP
            from scapy.layers.sctp import SCTP
            
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw'].load)
            
            if payload:
                all_packets.append({
                    'packet_index': idx,
                    'payload': payload,
                    'packet': packet,
                    'timestamp': timestamp,
                    'relative_time': relative_time
                })
        
        return all_packets
    
    def get_messages(self) -> List[bytes]:
        """
        Get all extracted NGAP message payloads.
        
        Returns:
            List of byte payloads
        """
        return [msg['payload'] for msg in self.ngap_messages]
    
    def get_message_count(self) -> int:
        """
        Get the number of NGAP messages extracted.
        
        Returns:
            int: Number of messages
        """
        return len(self.ngap_messages)
    
    def get_packet_count(self) -> int:
        """
        Get the total number of packets in the pcap file.
        
        Returns:
            int: Number of packets
        """
        return len(self.packets)
    
    def iterate_messages(self) -> Iterator[Tuple[int, bytes]]:
        """
        Iterate through NGAP messages with their indices.
        
        Yields:
            Tuple of (message_index, payload_bytes)
        """
        for idx, msg in enumerate(self.ngap_messages):
            yield idx, msg['payload']
    
    def decode_message(self, message_payload: bytes):
        """
        Decode an NGAP message payload.
        
        Args:
            message_payload: Raw NGAP message bytes
            
        Returns:
            NGAP_PDU: Decoded PDU object
        """
        return decode_ngsetup_request(message_payload)
    
    def get_decoded_messages(self) -> List:
        """
        Get all messages decoded as NGAP PDUs.
        
        Returns:
            List of decoded NGAP_PDU objects
        """
        decoded = []
        for msg in self.ngap_messages:
            try:
                decoded.append(self.decode_message(msg['payload']))
            except Exception as e:
                print(f"Warning: Failed to decode message at index {msg['packet_index']}: {e}")
        return decoded
    
    def get_message_hex(self, index: int) -> str:
        """
        Get a message as a hex string.
        
        Args:
            index: Message index
            
        Returns:
            Hex string representation
        """
        if index < 0 or index >= len(self.ngap_messages):
            raise IndexError(f"Message index {index} out of range")
        
        return self.ngap_messages[index]['payload'].hex()
    
    def summary(self) -> str:
        """
        Get a summary of the loaded traffic.
        
        Returns:
            Summary string
        """
        return (
            f"PCAP Traffic Summary:\n"
            f"  File: {self.pcap_file}\n"
            f"  Total packets: {self.get_packet_count()}\n"
            f"  NGAP messages: {self.get_message_count()}\n"
            f"  Message sizes: {[len(m['payload']) for m in self.ngap_messages]}"
        )
    
    def replay_to_udp(self, host: str, port: int, speed_factor: float = 1.0, 
                      on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
                      stop_event: Optional[threading.Event] = None,
                      packet_type: str = "ngap_only") -> None:
        """
        Replay captured packets to a UDP socket with timing.
        
        Args:
            host: Destination IP address
            port: Destination UDP port
            speed_factor: Replay speed multiplier (1.0 = real-time, 2.0 = 2x, 0.5 = half-speed)
            on_packet_sent: Optional callback function called with (index, payload) after each send
            stop_event: Optional threading.Event to stop replay early
            packet_type: "ngap_only" to replay only extracted NGAP messages, or "all" to replay all packets
            
        Raises:
            RuntimeError: If no messages to replay
            ValueError: If packet_type is invalid
        """
        if packet_type not in ("ngap_only", "all"):
            raise ValueError(f"packet_type must be 'ngap_only' or 'all', got '{packet_type}'")
        
        messages = self.ngap_messages if packet_type == "ngap_only" else self._get_all_packet_payloads()
        
        if not messages:
            raise RuntimeError(f"No {packet_type} messages to replay")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            print(f"Starting UDP replay to {host}:{port} at {speed_factor}x speed ({packet_type})...")
            
            for msg_idx, msg in enumerate(messages):
                if stop_event and stop_event.is_set():
                    print("Replay stopped by stop_event")
                    break
                
                # Wait for timing (except first packet)
                if msg_idx > 0:
                    wait_time = (msg['relative_time'] - messages[msg_idx - 1]['relative_time']) / speed_factor
                    if wait_time > 0:
                        time.sleep(float(wait_time))
                
                # Send packet
                sock.sendto(msg['payload'], (host, port))
                
                if on_packet_sent:
                    on_packet_sent(msg_idx, msg['payload'])
                
                print(f"  [{msg_idx}] Sent {len(msg['payload'])} bytes")
            
            print("UDP replay complete")
        
        finally:
            sock.close()
    
    def replay_to_socket(self, sock: socket.socket, speed_factor: float = 1.0,
                        on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
                        stop_event: Optional[threading.Event] = None,
                        packet_type: str = "ngap_only") -> None:
        """
        Replay captured packets to an open socket with timing.
        Supports both UDP and other socket types.
        
        Args:
            sock: Open socket object
            speed_factor: Replay speed multiplier (1.0 = real-time, 2.0 = 2x, 0.5 = half-speed)
            on_packet_sent: Optional callback function called with (index, payload) after each send
            stop_event: Optional threading.Event to stop replay early
            packet_type: "ngap_only" to replay only extracted NGAP messages, or "all" to replay all packets
            
        Raises:
            RuntimeError: If no messages to replay
            ValueError: If packet_type is invalid
        """
        if packet_type not in ("ngap_only", "all"):
            raise ValueError(f"packet_type must be 'ngap_only' or 'all', got '{packet_type}'")
        
        messages = self.ngap_messages if packet_type == "ngap_only" else self._get_all_packet_payloads()
        
        if not messages:
            raise RuntimeError(f"No {packet_type} messages to replay")
        
        print(f"Starting replay to socket at {speed_factor}x speed ({packet_type})...")
        
        for msg_idx, msg in enumerate(messages):
            if stop_event and stop_event.is_set():
                print("Replay stopped by stop_event")
                break
            
            # Wait for timing (except first packet)
            if msg_idx > 0:
                wait_time = (msg['relative_time'] - messages[msg_idx - 1]['relative_time']) / speed_factor
                if wait_time > 0:
                    time.sleep(float(wait_time))
            
            # Send packet
            try:
                sock.send(msg['payload'])
            except (BrokenPipeError, ConnectionResetError):
                print(f"  [{msg_idx}] Connection closed")
                break
            
            if on_packet_sent:
                on_packet_sent(msg_idx, msg['payload'])
            
            print(f"  [{msg_idx}] Sent {len(msg['payload'])} bytes")
        
        print("Replay complete")
    
    def replay_threaded(self, sock: socket.socket, speed_factor: float = 1.0,
                       on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
                       packet_type: str = "ngap_only") -> threading.Thread:
        """
        Start replay in a background thread.
        
        Args:
            sock: Open socket object
            speed_factor: Replay speed multiplier
            on_packet_sent: Optional callback function
            packet_type: "ngap_only" to replay only extracted NGAP messages, or "all" to replay all packets
            
        Returns:
            threading.Thread: The replay thread (started but not joined)
        """
        stop_event = threading.Event()
        
        def replay_worker():
            self.replay_to_socket(sock, speed_factor, on_packet_sent, stop_event, packet_type)
        
        thread = threading.Thread(target=replay_worker, daemon=False)
        thread.stop_event = stop_event
        thread.start()
        
        return thread
    
    def replay_to_sctp(self, host: str, port: int = NGAP_SCTP_PORT, speed_factor: float = 1.0,
                       on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
                       stop_event: Optional[threading.Event] = None,
                       packet_type: str = "ngap_only") -> None:
        """
        Replay captured NGAP packets over a new SCTP connection.
        NGAP runs over SCTP on port 38412 per 3GPP TS 38.412.

        Requires OS-level SCTP support (Linux with lksctp-tools; not natively
        available on Windows — use WSL).

        Args:
            host: Destination IP address of the AMF / 5G core
            port: SCTP port (default 38412)
            speed_factor: Replay speed multiplier (1.0 = real-time)
            on_packet_sent: Optional callback called with (index, payload) after each send
            stop_event: Optional threading.Event to stop replay early
            packet_type: "ngap_only" or "all"

        Raises:
            RuntimeError: If no messages to replay
            ValueError: If packet_type is invalid
            OSError: If SCTP is not supported on this OS
        """
        if packet_type not in ("ngap_only", "all"):
            raise ValueError(f"packet_type must be 'ngap_only' or 'all', got '{packet_type}'")

        messages = self.ngap_messages if packet_type == "ngap_only" else self._get_all_packet_payloads()

        if not messages:
            raise RuntimeError(f"No {packet_type} messages to replay")

        sock = create_sctp_socket(host, port)

        try:
            print(f"Starting SCTP replay to {host}:{port} at {speed_factor}x speed ({packet_type})...")

            for msg_idx, msg in enumerate(messages):
                if stop_event and stop_event.is_set():
                    print("Replay stopped by stop_event")
                    break

                if msg_idx > 0:
                    wait_time = (msg['relative_time'] - messages[msg_idx - 1]['relative_time']) / speed_factor
                    if wait_time > 0:
                        time.sleep(float(wait_time))

                try:
                    sock.send(msg['payload'])
                except (BrokenPipeError, ConnectionResetError) as e:
                    print(f"  [{msg_idx}] Connection closed: {e}")
                    break

                if on_packet_sent:
                    on_packet_sent(msg_idx, msg['payload'])

                print(f"  [{msg_idx}] Sent {len(msg['payload'])} bytes over SCTP")

            print("SCTP replay complete")

        finally:
            sock.close()

    def replay_sctp_threaded(self, host: str, port: int = NGAP_SCTP_PORT,
                             speed_factor: float = 1.0,
                             on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
                             packet_type: str = "ngap_only") -> threading.Thread:
        """
        Start SCTP replay in a background thread.

        Args:
            host: Destination IP address
            port: SCTP port (default 38412)
            speed_factor: Replay speed multiplier
            on_packet_sent: Optional callback
            packet_type: "ngap_only" or "all"

        Returns:
            threading.Thread: Started replay thread with a .stop_event attribute
        """
        stop_event = threading.Event()

        def replay_worker():
            try:
                self.replay_to_sctp(host, port, speed_factor, on_packet_sent, stop_event, packet_type)
            except Exception as e:
                print(f"SCTP replay failed: {e}")

        thread = threading.Thread(target=replay_worker, daemon=False)
        thread.stop_event = stop_event
        thread.start()
        return thread

    def get_timing_info(self) -> str:
        """
        Get timing information for all messages.
        
        Returns:
            Formatted string with timing details
        """
        if not self.ngap_messages:
            return "No messages to display"
        
        result = "Message Timing Information:\n"
        result += "Index | Time (s) | Delta (ms) | Size (bytes)\n"
        result += "-" * 50 + "\n"
        
        for idx, msg in enumerate(self.ngap_messages):
            if idx > 0:
                delta = (msg['relative_time'] - self.ngap_messages[idx - 1]['relative_time']) * 1000
                delta_str = f"{delta:.2f}"
            else:
                delta_str = "0.00"
            
            result += f"{idx:5} | {msg['relative_time']:8.3f} | {delta_str:>9} | {len(msg['payload']):>11}\n"
        
        return result
