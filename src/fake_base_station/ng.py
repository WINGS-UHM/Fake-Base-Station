"""
NGAP NGSetupRequest message handler for fake base station.
Provides methods to setup, encode, and decode NGAP messages.
"""

from pycrate_asn1dir import NGAP
from scapy.all import rdpcap, wrpcap
from pathlib import Path
from typing import List, Optional, Iterator, Tuple, Callable
import socket
import time
import threading
try:
    import zmq
    _ZMQ_AVAILABLE = True
except ImportError:
    _ZMQ_AVAILABLE = False


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


def create_sctp_socket(host: str, port: int = NGAP_SCTP_PORT, timeout: float = 10.0) -> socket.socket:
    """
    Create and connect an SCTP socket suitable for sending NGAP messages.
    NGAP runs over SCTP on port 38412 (3GPP TS 38.412).

    Requires OS-level SCTP support:
      - Linux: install lksctp-tools (apt install lksctp-tools)
      - Windows: not natively supported; use WSL or a third-party SCTP stack

    Args:
        host: Destination IP address of the AMF / 5G core
        port: SCTP port (default 38412)
        timeout: Connect timeout in seconds (default 10)

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
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.settimeout(None)  # back to blocking for recv loop
    except ConnectionRefusedError:
        sock.close()
        raise ConnectionRefusedError(
            f"Connection refused to {host}:{port}. "
            "Make sure an AMF / 5G core is running and listening on that address and port."
        )
    except socket.timeout:
        sock.close()
        raise TimeoutError(
            f"Connection to {host}:{port} timed out after {timeout}s. "
            "Check the AMF IP/port and that the host is reachable."
        )
    return sock


# ---------------------------------------------------------------------------
# NGAP message encoding helpers
# ---------------------------------------------------------------------------

# Minimal NAS 5GMM Registration Request for a test SUCI (null scheme, PLMN 001-01)
# IMSI: 001010000010001 (matches default NGSetupRequestConfig PLMN)
_DEFAULT_NAS_REGISTRATION_REQUEST = bytes.fromhex(
    "7e004179000d"      # EPD=5GMM, SecHdr=plain, MsgType=RegReq, ngKSI+RegType, MobId-LV len=13
    "0100f1100000"      # SUPI format=IMSI, PLMN 001-01, routing indicator 0000
    "00000000100001"    # protection scheme=null, HN key id=0, MSIN=0000100001
)


def encode_initial_ue_message(
    ran_ue_ngap_id: int,
    nas_pdu: bytes = None,
    config: "NGSetupRequestConfig" = None,
) -> bytes:
    """
    Encode an NGAP InitialUEMessage containing a NAS PDU.

    Args:
        ran_ue_ngap_id: RAN-UE-NGAP-ID assigned by the (fake) gNB.
        nas_pdu: NAS PDU bytes. Defaults to a minimal 5G Registration Request.
        config: NGSetupRequestConfig for PLMN/TAC (uses defaults if None).

    Returns:
        bytes: APER-encoded NGAP InitialUEMessage PDU.
    """
    cfg = config or NGSetupRequestConfig()
    nas_pdu = nas_pdu if nas_pdu is not None else _DEFAULT_NAS_REGISTRATION_REQUEST

    val = ('initiatingMessage', {
        'procedureCode': 15,   # id-initialUEMessage
        'criticality': 'ignore',
        'value': ('InitialUEMessage', {
            'protocolIEs': [
                {'id': 85, 'criticality': 'reject',
                 'value': ('RAN-UE-NGAP-ID', ran_ue_ngap_id)},
                {'id': 38, 'criticality': 'reject',
                 'value': ('NAS-PDU', nas_pdu)},
                {'id': 121, 'criticality': 'reject',
                 'value': ('UserLocationInformation', (
                     'userLocationInformationNR', {
                         'nR-CGI': {
                             'pLMNIdentity': cfg.plmn,
                             'nRCellIdentity': (0, 36),
                         },
                         'tAI': {
                             'pLMNIdentity': cfg.plmn,
                             'tAC': cfg.tac,
                         },
                     }
                 ))},
                {'id': 90, 'criticality': 'ignore',
                 'value': ('RRCEstablishmentCause', 'mo-Signalling')},
            ]
        })
    })
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.set_val(val)
    return pdu.to_aper()


def encode_ue_context_release_complete(
    amf_ue_ngap_id: int,
    ran_ue_ngap_id: int,
) -> bytes:
    """
    Encode a UEContextReleaseComplete message.

    Args:
        amf_ue_ngap_id: AMF-UE-NGAP-ID received from the AMF.
        ran_ue_ngap_id: RAN-UE-NGAP-ID assigned locally.

    Returns:
        bytes: APER-encoded NGAP UEContextReleaseComplete PDU.
    """
    val = ('successfulOutcome', {
        'procedureCode': 41,   # id-UEContextRelease
        'criticality': 'reject',
        'value': ('UEContextReleaseComplete', {
            'protocolIEs': [
                {'id': 10,  'criticality': 'ignore',
                 'value': ('AMF-UE-NGAP-ID', amf_ue_ngap_id)},
                {'id': 85,  'criticality': 'ignore',
                 'value': ('RAN-UE-NGAP-ID', ran_ue_ngap_id)},
            ]
        })
    })
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.set_val(val)
    return pdu.to_aper()


def decode_ngap_message(data: bytes) -> dict:
    """
    Decode a raw NGAP APER-encoded PDU and return a summary dict.

    Returns:
        dict with keys: 'message_name', 'procedure_code', 'type',
                        'amf_ue_ngap_id' (int or None), 'ran_ue_ngap_id' (int or None)
    """
    result = {
        'message_name': 'Unknown',
        'procedure_code': None,
        'type': None,
        'amf_ue_ngap_id': None,
        'ran_ue_ngap_id': None,
    }
    try:
        pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        pdu.from_aper(data)
        val = pdu.get_val()
        if not val:
            return result
        pdu_type, content = val
        result['type'] = pdu_type
        result['procedure_code'] = content.get('procedureCode')
        inner = content.get('value')
        if inner and isinstance(inner, tuple) and len(inner) == 2:
            result['message_name'] = inner[0]
            body = inner[1]
            ies = body.get('protocolIEs', []) if isinstance(body, dict) else []
            for ie in ies:
                ie_id = ie.get('id')
                ie_val = ie.get('value')
                if isinstance(ie_val, tuple) and len(ie_val) == 2:
                    if ie_id == 10:   # AMF-UE-NGAP-ID
                        result['amf_ue_ngap_id'] = ie_val[1]
                    elif ie_id == 85:  # RAN-UE-NGAP-ID
                        result['ran_ue_ngap_id'] = ie_val[1]
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Open5GS NGAP connection (acts as a fake gNB toward the AMF)
# ---------------------------------------------------------------------------

class Open5GSConnection:
    """
    Maintains a fake-gNB NGAP connection to an Open5GS AMF over SCTP.

    Lifecycle:
      1. ``connect()`` – SCTP connect, NGSetup handshake, starts receive thread.
      2. ``register_ue()`` – Send InitialUEMessage to trigger NAS Registration.
      3. ``send_ue_context_release_complete()`` – Respond to a release command.
      4. ``disconnect()`` – Close socket, stop receive thread.

    Callbacks:
      * ``on_message(msg_dict)`` – Called for every decoded incoming NGAP message.
      * ``on_status(status_str)`` – Called on connection state changes / errors.
    """

    def __init__(
        self,
        amf_host: str,
        amf_port: int = NGAP_SCTP_PORT,
        config: "NGSetupRequestConfig" = None,
        on_message=None,
        on_status=None,
    ):
        self.amf_host = amf_host
        self.amf_port = amf_port
        self.config = config or NGSetupRequestConfig()
        self.on_message = on_message   # callable(dict)
        self.on_status = on_status     # callable(str)

        self._sock: Optional[socket.socket] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

        # UE context state
        self.amf_ue_ngap_id: Optional[int] = None
        self.ran_ue_ngap_id: int = 1   # locally assigned

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._sock is not None and self._running

    def connect(self) -> bool:
        """
        Connect to AMF, perform NGSetup handshake, start receive loop.

        Returns True on success, False on failure (check on_status for reason).
        """
        if self.is_connected:
            return True
        try:
            self._emit_status("Connecting to AMF …")
            sock = create_sctp_socket(self.amf_host, self.amf_port)
            self._sock = sock
            self._running = True

            # Start receive thread before sending (AMF may respond immediately)
            self._rx_thread = threading.Thread(
                target=self._receive_loop, daemon=True, name="Open5GS-RX"
            )
            self._rx_thread.start()

            # Send NGSetupRequest
            ng_setup = encode_ngsetup_request(self.config)
            sock.sendall(ng_setup)
            self._emit_status("NGSetupRequest sent – waiting for response …")
            return True
        except Exception as exc:
            self._running = False
            self._sock = None
            self._emit_status(f"Connection failed: {exc}")
            return False

    def register_ue(self, nas_pdu: bytes = None) -> bool:
        """
        Send an InitialUEMessage to trigger 5G NAS Registration.

        Args:
            nas_pdu: Optional NAS PDU override; defaults to a test Registration Request.
        """
        if not self.is_connected:
            self._emit_status("Not connected – call connect() first.")
            return False
        try:
            msg = encode_initial_ue_message(self.ran_ue_ngap_id, nas_pdu, self.config)
            self._sock.sendall(msg)
            self._emit_status(f"InitialUEMessage sent (RAN-UE-NGAP-ID={self.ran_ue_ngap_id})")
            return True
        except Exception as exc:
            self._emit_status(f"register_ue error: {exc}")
            return False

    def send_ue_context_release_complete(
        self,
        amf_ue_ngap_id: int = None,
        ran_ue_ngap_id: int = None,
    ) -> bool:
        """
        Send UEContextReleaseComplete to the AMF.

        Args:
            amf_ue_ngap_id: Override AMF ID (uses stored value if None).
            ran_ue_ngap_id: Override RAN ID (uses stored value if None).
        """
        if not self.is_connected:
            self._emit_status("Not connected – cannot send UEContextReleaseComplete.")
            return False
        amf_id = amf_ue_ngap_id if amf_ue_ngap_id is not None else self.amf_ue_ngap_id
        ran_id = ran_ue_ngap_id if ran_ue_ngap_id is not None else self.ran_ue_ngap_id
        if amf_id is None:
            self._emit_status("AMF-UE-NGAP-ID unknown – register a UE first.")
            return False
        try:
            msg = encode_ue_context_release_complete(amf_id, ran_id)
            self._sock.sendall(msg)
            self._emit_status(
                f"UEContextReleaseComplete sent (AMF-ID={amf_id}, RAN-ID={ran_id})"
            )
            return True
        except Exception as exc:
            self._emit_status(f"send_ue_context_release_complete error: {exc}")
            return False

    def disconnect(self):
        """Close the SCTP socket and stop the receive thread."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._emit_status("Disconnected from AMF.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _receive_loop(self):
        """Background thread: receive SCTP data, decode, dispatch."""
        buf = b""
        while self._running and self._sock:
            try:
                chunk = self._sock.recv(65535)
                if not chunk:
                    self._emit_status("AMF closed connection.")
                    self._running = False
                    self._sock = None
                    break
                buf += chunk
                # Try to decode each 4096-byte chunk as a full NGAP PDU
                # (SCTP is message-oriented, so recv usually returns one PDU)
                msg = decode_ngap_message(buf)
                buf = b""

                # Persist AMF-UE-NGAP-ID as soon as we see it
                if msg.get('amf_ue_ngap_id') is not None:
                    with self._lock:
                        self.amf_ue_ngap_id = msg['amf_ue_ngap_id']

                name = msg.get('message_name', 'Unknown')
                self._emit_status(f"Received: {name}")

                if name == 'NGSetupResponse':
                    self._emit_status("NGSetup complete – connected to Open5GS AMF.")

                if self.on_message:
                    try:
                        self.on_message(msg)
                    except Exception:
                        pass
            except OSError:
                if self._running:
                    self._emit_status("Receive error – connection lost.")
                self._running = False
                self._sock = None
                break

    def _emit_status(self, msg: str):
        print(f"[Open5GS] {msg}")
        if self.on_status:
            try:
                self.on_status(msg)
            except Exception:
                pass


class PCAPTrafficReplayer:
    """
    Load and replay NGAP traffic from a .pcap file.
    Extracts NGAP messages from captured packets and provides
    methods to iterate through and decode them.
    """
    
    def __init__(self, pcap_file: str | Path, source_ip: Optional[str] = None):
        """
        Initialize the traffic replayer with a pcap file.
        
        Args:
            pcap_file: Path to the .pcap file
            source_ip: Optional source IP filter. If set, only packets with this
                source IP are considered for extraction/replay.
            
        Raises:
            FileNotFoundError: If the pcap file doesn't exist
            Exception: If the pcap file cannot be read
        """
        self.pcap_file = Path(pcap_file)
        self.source_ip = source_ip
        
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        self.packets = []
        self.ngap_messages = []
        self._load_pcap()

    def _packet_matches_source_filter(self, packet) -> bool:
        """Return True if packet matches the configured source IP filter."""
        if not self.source_ip:
            return True

        from scapy.layers.inet import IP

        if not packet.haslayer(IP):
            return False

        return packet[IP].src == self.source_ip
    
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
        
        self.ngap_messages = []
        base_time = None
        
        for idx, packet in enumerate(self.packets):
            if not self._packet_matches_source_filter(packet):
                continue

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
            
            # Keep full transport payload bytes as the NGAP PDU payload.
            # Previous marker-based slicing could truncate/offset the PDU.
            if raw_data:
                payload = raw_data
            
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
            if not self._packet_matches_source_filter(packet):
                continue

            # Extract timestamp
            timestamp = packet.time if hasattr(packet, 'time') else None
            if base_time is None and timestamp is not None:
                base_time = timestamp
            
            relative_time = (timestamp - base_time) if timestamp and base_time else 0
            
            # Try to extract any payload
            payload = None
            from scapy.layers.inet import IP, UDP
            from scapy.layers.sctp import SCTP
            
            if packet.haslayer(SCTP) and packet[SCTP].haslayer('Raw'):
                payload = bytes(packet[SCTP]['Raw'].load)
            elif packet.haslayer(UDP) and packet[UDP].haslayer('Raw'):
                payload = bytes(packet[UDP]['Raw'].load)
            elif packet.haslayer('Raw'):
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
            f"  Source IP filter: {self.source_ip if self.source_ip else 'None'}\n"
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

    def replay_to_zmq(
        self,
        endpoint: str = "tcp://127.0.0.1:5555",
        socket_type: str = "PUSH",
        speed_factor: float = 1.0,
        on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
        stop_event: Optional[threading.Event] = None,
        packet_type: str = "ngap_only",
    ) -> None:
        """
        Replay captured packets over a ZMQ socket (no USRP / radio hardware needed).

        Uses ZeroMQ instead of SCTP/UDP so the receiver only needs a matching
        ZMQ socket — no kernel SCTP support required and no SDR hardware required.

        Supported socket_type values:
          - "PUSH" : paired with a PULL listener (pipeline pattern, default)
          - "PUB"  : paired with a SUB listener (publish-subscribe pattern)

        Args:
            endpoint:    ZMQ endpoint string, e.g. "tcp://127.0.0.1:5555"
            socket_type: ZMQ socket type to use — "PUSH" or "PUB"
            speed_factor: Replay speed multiplier (1.0 = real-time)
            on_packet_sent: Optional callback called with (index, payload) after each send
            stop_event:  Optional threading.Event to stop replay early
            packet_type: "ngap_only" or "all"

        Raises:
            ImportError: If pyzmq is not installed (pip install pyzmq)
            ValueError:  If socket_type or packet_type is invalid
            RuntimeError: If no messages to replay
        """
        if not _ZMQ_AVAILABLE:
            raise ImportError(
                "pyzmq is not installed. Install it with: pip install pyzmq"
            )

        if socket_type not in ("PUSH", "PUB"):
            raise ValueError(f"socket_type must be 'PUSH' or 'PUB', got '{socket_type}'")

        if packet_type not in ("ngap_only", "all"):
            raise ValueError(f"packet_type must be 'ngap_only' or 'all', got '{packet_type}'")

        messages = self.ngap_messages if packet_type == "ngap_only" else self._get_all_packet_payloads()

        if not messages:
            raise RuntimeError(f"No {packet_type} messages to replay")

        zmq_type = zmq.PUSH if socket_type == "PUSH" else zmq.PUB
        context = zmq.Context()
        sock = context.socket(zmq_type)
        sock.bind(endpoint)

        # PUB sockets need a brief settle time so subscribers can connect
        if socket_type == "PUB":
            time.sleep(0.1)

        try:
            print(f"Starting ZMQ {socket_type} replay on {endpoint} at {speed_factor}x speed ({packet_type})...")

            for msg_idx, msg in enumerate(messages):
                if stop_event and stop_event.is_set():
                    print("Replay stopped by stop_event")
                    break

                if msg_idx > 0:
                    wait_time = (msg['relative_time'] - messages[msg_idx - 1]['relative_time']) / speed_factor
                    if wait_time > 0:
                        time.sleep(float(wait_time))

                sock.send(msg['payload'])

                if on_packet_sent:
                    on_packet_sent(msg_idx, msg['payload'])

                print(f"  [{msg_idx}] Sent {len(msg['payload'])} bytes via ZMQ {socket_type}")

            print("ZMQ replay complete")

        finally:
            sock.close()
            context.term()

    def replay_zmq_threaded(
        self,
        endpoint: str = "tcp://127.0.0.1:5555",
        socket_type: str = "PUSH",
        speed_factor: float = 1.0,
        on_packet_sent: Optional[Callable[[int, bytes], None]] = None,
        packet_type: str = "ngap_only",
    ) -> threading.Thread:
        """
        Start ZMQ replay in a background thread.

        The returned thread has a ``.stop_event`` attribute (threading.Event)
        that can be set to terminate the replay early.

        Args:
            endpoint:    ZMQ endpoint string, e.g. "tcp://127.0.0.1:5555"
            socket_type: "PUSH" (default) or "PUB"
            speed_factor: Replay speed multiplier
            on_packet_sent: Optional callback called with (index, payload)
            packet_type: "ngap_only" or "all"

        Returns:
            threading.Thread: Started replay thread with a .stop_event attribute
        """
        stop_event = threading.Event()

        def replay_worker():
            try:
                self.replay_to_zmq(
                    endpoint, socket_type, speed_factor,
                    on_packet_sent, stop_event, packet_type
                )
            except Exception as e:
                print(f"ZMQ replay failed: {e}")

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


def save_modified_ngap_pcap(
    input_pcap: str | Path,
    output_pcap: str | Path,
    new_dst_ip: str,
    source_ip: Optional[str] = None,
    ngap_port: int = NGAP_SCTP_PORT,
) -> tuple[int, int]:
    """
    Save a copy of a PCAP with destination IP rewritten for NGAP packets.

    Args:
        input_pcap: Source pcap path.
        output_pcap: Output pcap path to write.
        new_dst_ip: Destination IP to apply to matching packets.
        source_ip: Optional source IP filter.
        ngap_port: Port used to identify NGAP transport packets.

    Returns:
        tuple[int, int]: (modified_packet_count, total_packet_count)
    """
    from scapy.layers.inet import IP, UDP
    from scapy.layers.sctp import SCTP

    input_path = Path(input_pcap)
    output_path = Path(output_pcap)

    if not input_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {input_path}")

    packets = rdpcap(str(input_path))
    modified_count = 0

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        if source_ip and packet[IP].src != source_ip:
            continue

        is_ngap_packet = False
        if packet.haslayer(SCTP):
            sctp_layer = packet[SCTP]
            is_ngap_packet = (sctp_layer.sport == ngap_port) or (sctp_layer.dport == ngap_port)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            is_ngap_packet = (udp_layer.sport == ngap_port) or (udp_layer.dport == ngap_port)

        if not is_ngap_packet:
            continue

        packet[IP].dst = new_dst_ip
        if hasattr(packet[IP], "chksum"):
            del packet[IP].chksum

        if packet.haslayer(SCTP) and hasattr(packet[SCTP], "chksum"):
            del packet[SCTP].chksum
        if packet.haslayer(UDP) and hasattr(packet[UDP], "chksum"):
            del packet[UDP].chksum

        modified_count += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return modified_count, len(packets)
