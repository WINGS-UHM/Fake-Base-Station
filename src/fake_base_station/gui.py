import ipaddress
import json
import threading
import tkinter as tk
import socket
import time
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk

from scapy.all import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP

try:
    from pycrate_asn1dir import NGAP
except ImportError:
    NGAP = None

try:
    import zmq
    _ZMQ_AVAILABLE = True
except ImportError:
    _ZMQ_AVAILABLE = False


NGAP_SCTP_PORT = 38412


def _extract_ngap_payload(packet):
    """Extract NGAP payload from SCTP or UDP layers.
    
    For SCTP: Look for SCTPChunkData with 'data' field.
    For UDP: Look for Raw payload.
    """
    if packet.haslayer(SCTP):
        sctp_layer = packet[SCTP]
        sctp_payload = sctp_layer.payload
        # Check if SCTP payload is a data chunk
        if type(sctp_payload).__name__ == 'SCTPChunkData':
            raw = sctp_payload.fields.get('data')
            if raw:
                return raw
        # Fallback to Raw layer if present
        if sctp_layer.haslayer("Raw"):
            return bytes(sctp_layer["Raw"].load)
    if packet.haslayer(UDP) and packet[UDP].haslayer("Raw"):
        return bytes(packet[UDP]["Raw"].load)
    return None


def _to_python_pdu(decoded_pdu):
    try:
        return decoded_pdu.get_val()
    except Exception:
        return None


def _extract_protocol_ies(message_container):
    if not isinstance(message_container, dict):
        return []

    value = message_container.get("value")
    if not (isinstance(value, tuple) and len(value) == 2):
        return []

    _, message_body = value
    if not isinstance(message_body, dict):
        return []

    ies = message_body.get("protocolIEs", [])
    return ies if isinstance(ies, list) else []


def _parse_ie_value(ie):
    value = ie.get("value")
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1]
    return None, value


def _extract_message_name(payload: bytes) -> str | None:
    """Extract NGAP message name from payload."""
    if NGAP is None or not payload:
        return None

    try:
        pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        pdu.from_aper(payload)
        py_pdu = _to_python_pdu(pdu)
        if not (isinstance(py_pdu, tuple) and len(py_pdu) == 2):
            return None

        _, message_container = py_pdu
        if not isinstance(message_container, dict):
            return None

        value = message_container.get("value")
        if isinstance(value, tuple) and len(value) == 2:
            message_name = value[0]
            if isinstance(message_name, str):
                return message_name
        return None
    except Exception:
        return None


def _detect_release_signal(payload: bytes) -> bool | None:
    if NGAP is None or not payload:
        return None

    try:
        pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        pdu.from_aper(payload)
        py_pdu = _to_python_pdu(pdu)
        if not (isinstance(py_pdu, tuple) and len(py_pdu) == 2):
            return None

        _, message_container = py_pdu
        if not isinstance(message_container, dict):
            return None

        value = message_container.get("value")
        message_name = value[0] if isinstance(value, tuple) and len(value) == 2 else None
        if isinstance(message_name, str) and "Release" in message_name:
            return True

        for ie in _extract_protocol_ies(message_container):
            ie_name, _ = _parse_ie_value(ie)
            if isinstance(ie_name, str) and "Release" in ie_name:
                return True

        return False
    except Exception:
        return None


class PcapPacketLoader:
    """Load PCAP and extract packet metadata for UI display."""
    
    def __init__(self, pcap_file: str | Path):
        self.pcap_file = Path(pcap_file)
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        self.packets = rdpcap(str(self.pcap_file))
        self.packet_metadata = self._extract_metadata()
    
    def _extract_metadata(self) -> list[dict]:
        """Extract metadata for each packet in the PCAP."""
        metadata = []
        for idx, packet in enumerate(self.packets):
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = None
            is_ngap = False
            payload_size = 0
            contains_release_signal = None
            message_name = None
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            
            if packet.haslayer(SCTP):
                protocol = "SCTP"
                src_port = packet[SCTP].sport
                dst_port = packet[SCTP].dport
                # Only mark as NGAP if on NGAP port AND has actual data payload (SCTPChunkData)
                sctp_layer = packet[SCTP]
                sctp_payload = sctp_layer.payload
                has_data = type(sctp_payload).__name__ == 'SCTPChunkData' and 'data' in sctp_payload.fields
                is_ngap = (dst_port == NGAP_SCTP_PORT or src_port == NGAP_SCTP_PORT) and has_data
                if has_data and 'data' in sctp_payload.fields:
                    payload_size = len(sctp_payload.fields['data'])
                elif sctp_layer.haslayer("Raw"):
                    payload_size = len(sctp_layer["Raw"].load)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                is_ngap = dst_port == NGAP_SCTP_PORT or src_port == NGAP_SCTP_PORT
                if packet[UDP].haslayer("Raw"):
                    payload_size = len(packet[UDP]["Raw"].load)
            
            if is_ngap:
                payload = _extract_ngap_payload(packet)
                contains_release_signal = _detect_release_signal(payload)
                message_name = _extract_message_name(payload)

            timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
            
            metadata.append({
                "index": idx,
                "packet": packet,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "is_ngap": is_ngap,
                "contains_release_signal": contains_release_signal,
                "message_name": message_name,
                "payload_size": payload_size,
                "timestamp": timestamp,
            })
        
        return metadata
    
    def get_packet_count(self) -> int:
        return len(self.packets)
    
    def get_ngap_count(self) -> int:
        return sum(1 for m in self.packet_metadata if m["is_ngap"])


class ModifiedPcapReplayer:
    """Replay selected packets with optional IP modification."""
    
    def __init__(self, packets_to_replay: list):
        """
        Args:
            packets_to_replay: List of dicts with 'packet' and optionally 'dst_ip'
        """
        self.packets = packets_to_replay
    
    def replay_to_udp(self, host: str, port: int, on_packet_sent=None):
        if not self.packets:
            raise RuntimeError("No packets to replay")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for pkt_dict in self.packets:
                packet = pkt_dict["packet"]
                dst_ip = pkt_dict.get("dst_ip")
                
                if dst_ip and packet.haslayer(IP):
                    packet[IP].dst = dst_ip
                    packet[IP].chksum = None
                
                payload = bytes(packet)
                sock.sendto(payload, (host, port))
                
                if on_packet_sent:
                    on_packet_sent(pkt_dict.get("index", 0), len(payload))
        finally:
            sock.close()

    def replay_to_sctp(self, host: str, port: int, on_packet_sent=None):
        if not self.packets:
            raise RuntimeError("No packets to replay")

        ipproto_sctp = getattr(socket, "IPPROTO_SCTP", 132)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, ipproto_sctp)
        try:
            sock.connect((host, port))
            for pkt_dict in self.packets:
                packet = pkt_dict["packet"]
                dst_ip = pkt_dict.get("dst_ip")
                
                if dst_ip and packet.haslayer(IP):
                    packet[IP].dst = dst_ip
                    packet[IP].chksum = None
                
                payload = bytes(packet)
                sock.send(payload)
                
                if on_packet_sent:
                    on_packet_sent(pkt_dict.get("index", 0), len(payload))
        finally:
            sock.close()

    def replay_to_zmq(self, endpoint: str, on_packet_sent=None):
        """Send raw NGAP payloads over a ZMQ PUSH socket.

        Each message is sent as a two-frame multipart message:
          Frame 0: JSON metadata {"message_name": ..., "contains_release_signal": ...}
          Frame 1: raw NGAP payload bytes

        This lets the UE Listener display the *overridden* message name set in
        the gNB GUI (e.g. UEContextReleaseCommand) rather than re-decoding the
        original bytes, which would give the original message.

        Args:
            endpoint: ZMQ endpoint, e.g. "tcp://127.0.0.1:5555"
            on_packet_sent: Optional callback(index, size)
        """
        if not _ZMQ_AVAILABLE:
            raise ImportError("pyzmq is not installed. Run: pip install pyzmq")
        if not self.packets:
            raise RuntimeError("No packets to replay")

        context = zmq.Context()
        sock = context.socket(zmq.PUSH)
        sock.connect(endpoint)
        # Brief settle so the PULL side is ready
        time.sleep(0.05)

        try:
            for pkt_dict in self.packets:
                packet = pkt_dict["packet"]
                ngap_bytes = _extract_ngap_payload(packet)
                if ngap_bytes is None:
                    ngap_bytes = bytes(packet)

                # Carry overridden metadata set by the user in the GUI
                meta_frame = json.dumps({
                    "message_name": pkt_dict.get("message_name"),
                    "contains_release_signal": pkt_dict.get("contains_release_signal"),
                }).encode()

                sock.send_multipart([meta_frame, ngap_bytes])
                if on_packet_sent:
                    on_packet_sent(pkt_dict.get("index", 0), len(ngap_bytes))
        finally:
            sock.close()
            context.term()


class NGAPPcapGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NGAP PCAP Packet Selector & Replayer")
        self.geometry("1400x700")

        self.loader: PcapPacketLoader | None = None
        self.working_packet_metadata: list[dict] = []
        self.filtered_packet_metadata: list[dict] = []
        self.replay_thread: threading.Thread | None = None

        self._build_ui()

    def _build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=2)
        root.rowconfigure(0, weight=1)

        # Left panel: controls
        left = ttk.Frame(root)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(1, weight=1)

        # Right panel: packet list + log
        right = ttk.Frame(root)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # --- LEFT PANEL ---
        row = 0
        ttk.Label(left, text="Input PCAP", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))

        row += 1
        ttk.Label(left, text="File").grid(row=row, column=0, sticky="w", pady=4)
        self.input_pcap_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.input_pcap_var).grid(row=row, column=1, sticky="ew", padx=6)
        ttk.Button(left, text="Browse", command=self._on_browse_input).grid(row=row, column=2, sticky="ew")

        row += 1
        ttk.Label(left, text="Status").grid(row=row, column=0, sticky="w", pady=4)
        self.status_var = tk.StringVar(value="No file loaded")
        ttk.Label(left, textvariable=self.status_var, foreground="blue").grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)

        row += 1
        ttk.Label(left, text="Modify Selected Packets", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))

        row += 1
        ttk.Label(left, text="New Dst IP").grid(row=row, column=0, sticky="w", pady=4)
        self.dest_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(left, textvariable=self.dest_ip_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)

        row += 1
        ttk.Label(left, text="Replay Configuration", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))

        row += 1
        ttk.Label(left, text="Host").grid(row=row, column=0, sticky="w", pady=4)
        self.replay_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(left, textvariable=self.replay_host_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Port").grid(row=row, column=0, sticky="w", pady=4)
        self.replay_port_var = tk.StringVar(value=str(NGAP_SCTP_PORT))
        ttk.Entry(left, textvariable=self.replay_port_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Protocol").grid(row=row, column=0, sticky="w", pady=4)
        self.replay_protocol_var = tk.StringVar(value="UDP")
        proto_cb = ttk.Combobox(left, textvariable=self.replay_protocol_var, values=["UDP", "SCTP", "ZMQ"], state="readonly")
        proto_cb.grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        proto_cb.bind("<<ComboboxSelected>>", self._on_protocol_change)

        row += 1
        self._zmq_endpoint_label = ttk.Label(left, text="ZMQ Endpoint")
        self._zmq_endpoint_label.grid(row=row, column=0, sticky="w", pady=4)
        self.zmq_endpoint_var = tk.StringVar(value="tcp://127.0.0.1:5555")
        self._zmq_endpoint_entry = ttk.Entry(left, textvariable=self.zmq_endpoint_var)
        self._zmq_endpoint_entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        # Hide ZMQ endpoint row by default
        self._zmq_endpoint_label.grid_remove()
        self._zmq_endpoint_entry.grid_remove()

        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)

        row += 1
        ttk.Label(left, text="Filter Packets", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))

        row += 1
        ttk.Label(left, text="Src IP").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_src_ip_var = tk.StringVar(value="")
        ttk.Entry(left, textvariable=self.filter_src_ip_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Dst IP").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_dst_ip_var = tk.StringVar(value="")
        ttk.Entry(left, textvariable=self.filter_dst_ip_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Protocol").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_protocol_var = tk.StringVar(value="Any")
        ttk.Combobox(left, textvariable=self.filter_protocol_var, values=["Any", "SCTP", "UDP"], state="readonly").grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Src Port").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_src_port_var = tk.StringVar(value="")
        ttk.Entry(left, textvariable=self.filter_src_port_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="Dst Port").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_dst_port_var = tk.StringVar(value="")
        ttk.Entry(left, textvariable=self.filter_dst_port_var).grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        ttk.Label(left, text="NGAP Only").grid(row=row, column=0, sticky="w", pady=2)
        self.filter_ngap_var = tk.StringVar(value="Any")
        ttk.Combobox(left, textvariable=self.filter_ngap_var, values=["Any", "Yes", "No"], state="readonly").grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)

        row += 1
        filter_btn_frame = ttk.Frame(left)
        filter_btn_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Button(filter_btn_frame, text="Apply Filter", command=self._apply_filter).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(filter_btn_frame, text="Reset Filter", command=self._reset_filter).pack(side=tk.LEFT, padx=4)

        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)

        row += 1
        btn_frame = ttk.Frame(left)
        btn_frame.grid(row=row, column=0, columnspan=3, sticky="ew")
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        ttk.Button(btn_frame, text="Select All", command=self._select_all).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(btn_frame, text="Clear", command=self._clear_all).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Delete Selected", command=self._delete_selected).pack(side=tk.LEFT, padx=3)

        row += 1
        release_signal_frame = ttk.LabelFrame(left, text="Release Signal", padding=4)
        release_signal_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
        release_signal_frame.columnconfigure(0, weight=1)
        release_signal_frame.columnconfigure(1, weight=1)
        release_signal_frame.columnconfigure(2, weight=1)
        ttk.Button(release_signal_frame, text="Mark Release", command=lambda: self._set_release_signal_for_selected(True)).grid(row=0, column=0, sticky="ew", padx=2)
        ttk.Button(release_signal_frame, text="Clear Release", command=lambda: self._set_release_signal_for_selected(False)).grid(row=0, column=1, sticky="ew", padx=2)
        ttk.Button(release_signal_frame, text="Toggle", command=lambda: self._set_release_signal_for_selected(None)).grid(row=0, column=2, sticky="ew", padx=2)

        row += 1
        ttk.Button(left, text="Replay Selected", command=self._on_replay).grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)

        # --- RIGHT PANEL: PACKET LIST ---
        list_frame = ttk.LabelFrame(right, text="Packets", padding=6)
        list_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        columns = ("Index", "Protocol", "Src", "Dst", "SrcPort", "DstPort", "Payload", "NGAP", "Message", "Release")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, height=15, selectmode="extended")
        self.packet_tree.column("#0", width=0, stretch=tk.NO)
        self.packet_tree.column("Index", anchor=tk.CENTER, width=50)
        self.packet_tree.column("Protocol", anchor=tk.CENTER, width=60)
        self.packet_tree.column("Src", anchor=tk.W, width=110)
        self.packet_tree.column("Dst", anchor=tk.W, width=110)
        self.packet_tree.column("SrcPort", anchor=tk.CENTER, width=65)
        self.packet_tree.column("DstPort", anchor=tk.CENTER, width=65)
        self.packet_tree.column("Payload", anchor=tk.CENTER, width=65)
        self.packet_tree.column("NGAP", anchor=tk.CENTER, width=45)
        self.packet_tree.column("Message", anchor=tk.W, width=200)
        self.packet_tree.column("Release", anchor=tk.CENTER, width=65)

        for col in columns:
            self.packet_tree.heading(col, text=col)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=scrollbar.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- RIGHT PANEL: LOG ---
        log_frame = ttk.LabelFrame(right, text="Log", padding=6)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, height=10)
        self.log_text.grid(row=0, column=0, sticky="nsew")

    def _on_protocol_change(self, _event=None):
        """Show/hide ZMQ endpoint field based on selected protocol."""
        if self.replay_protocol_var.get() == "ZMQ":
            self._zmq_endpoint_label.grid()
            self._zmq_endpoint_entry.grid()
        else:
            self._zmq_endpoint_label.grid_remove()
            self._zmq_endpoint_entry.grid_remove()

    def _log(self, message: str):
        def append():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.after(0, append)

    def _on_browse_input(self):
        selected = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if not selected:
            return

        try:
            self.loader = PcapPacketLoader(selected)
            self.working_packet_metadata = list(self.loader.packet_metadata)
            self.filtered_packet_metadata = list(self.working_packet_metadata)
            self.input_pcap_var.set(str(selected))
            self._populate_packet_list(self.filtered_packet_metadata)
            self._refresh_status()
            self._log(f"Loaded PCAP: {selected}")
            self._log(f"Total packets: {self.loader.get_packet_count()}, NGAP packets: {self.loader.get_ngap_count()}")
        except Exception as exc:
            self._log(f"Failed to load PCAP: {exc}")
            messagebox.showerror("Load Failed", str(exc))

    def _populate_packet_list(self, packet_rows: list[dict]):
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        for meta in packet_rows:
            ngap = "Y" if meta["is_ngap"] else "N"
            release_signal = meta.get("contains_release_signal")
            if release_signal is True:
                release_value = "Y"
            elif release_signal is False:
                release_value = "N"
            else:
                release_value = "?" if meta["is_ngap"] else "-"
            
            # Enhance message display for UEContextReleaseCommand
            message_name = meta.get("message_name") or "-"
            if message_name == "UEContextReleaseCommand":
                release_status = "RELEASE" if release_signal is True else "no-release" if release_signal is False else "unknown"
                message_name = f"UEContextReleaseCommand ({release_status})"
            
            values = (
                meta["index"],
                meta["protocol"] or "?",
                meta["src_ip"] or "?",
                meta["dst_ip"] or "?",
                meta["src_port"] or "?",
                meta["dst_port"] or "?",
                meta["payload_size"],
                ngap,
                message_name,
                release_value,
            )
            self.packet_tree.insert("", tk.END, iid=str(meta["index"]), values=values, tags=("ngap",) if meta["is_ngap"] else ())

        self.packet_tree.tag_configure("ngap", foreground="green")

    def _refresh_status(self):
        working_total = len(self.working_packet_metadata)
        working_ngap = sum(1 for m in self.working_packet_metadata if m["is_ngap"])
        filtered_total = len(self.filtered_packet_metadata)
        self.status_var.set(
            f"Working: {working_total} packets ({working_ngap} NGAP) | Showing: {filtered_total}"
        )

    def _select_all(self):
        items = self.packet_tree.get_children()
        self.packet_tree.selection_set(items)
        self._log(f"Selected {len(items)} packets")

    def _clear_all(self):
        self.packet_tree.selection_remove(self.packet_tree.selection())
        self._log("Cleared selection")

    def _matches_filter(self, meta: dict) -> bool:
        src_ip = self.filter_src_ip_var.get().strip()
        dst_ip = self.filter_dst_ip_var.get().strip()
        protocol = self.filter_protocol_var.get().strip()
        src_port = self.filter_src_port_var.get().strip()
        dst_port = self.filter_dst_port_var.get().strip()
        ngap_only = self.filter_ngap_var.get().strip()

        if src_ip and (meta.get("src_ip") or "") != src_ip:
            return False
        if dst_ip and (meta.get("dst_ip") or "") != dst_ip:
            return False
        if protocol and protocol != "Any" and (meta.get("protocol") or "") != protocol:
            return False

        if src_port:
            try:
                if meta.get("src_port") != int(src_port):
                    return False
            except ValueError:
                raise ValueError(f"Invalid Src Port filter: {src_port}")

        if dst_port:
            try:
                if meta.get("dst_port") != int(dst_port):
                    return False
            except ValueError:
                raise ValueError(f"Invalid Dst Port filter: {dst_port}")

        if ngap_only == "Yes" and not meta.get("is_ngap"):
            return False
        if ngap_only == "No" and meta.get("is_ngap"):
            return False

        return True

    def _apply_filter(self):
        try:
            if not self.loader:
                raise ValueError("No PCAP loaded")

            self.filtered_packet_metadata = [m for m in self.working_packet_metadata if self._matches_filter(m)]
            self._populate_packet_list(self.filtered_packet_metadata)
            self._refresh_status()
            self._log(f"Filter applied: showing {len(self.filtered_packet_metadata)} packets")
        except Exception as exc:
            self._log(f"Filter failed: {exc}")
            messagebox.showerror("Filter Failed", str(exc))

    def _reset_filter(self):
        self.filter_src_ip_var.set("")
        self.filter_dst_ip_var.set("")
        self.filter_protocol_var.set("Any")
        self.filter_src_port_var.set("")
        self.filter_dst_port_var.set("")
        self.filter_ngap_var.set("Any")
        self.filtered_packet_metadata = list(self.working_packet_metadata)
        self._populate_packet_list(self.filtered_packet_metadata)
        self._refresh_status()
        self._log("Filters reset")

    def _delete_selected(self):
        try:
            if not self.loader:
                raise ValueError("No PCAP loaded")

            selected_items = self.packet_tree.selection()
            if not selected_items:
                raise ValueError("No packets selected")

            selected_indices = {int(self.packet_tree.item(item, "values")[0]) for item in selected_items}
            before_count = len(self.working_packet_metadata)
            self.working_packet_metadata = [m for m in self.working_packet_metadata if m["index"] not in selected_indices]
            self.filtered_packet_metadata = [m for m in self.filtered_packet_metadata if m["index"] not in selected_indices]

            self._populate_packet_list(self.filtered_packet_metadata)
            self._refresh_status()
            self._log(f"Deleted {before_count - len(self.working_packet_metadata)} packets from list")
        except Exception as exc:
            self._log(f"Delete failed: {exc}")
            messagebox.showerror("Delete Failed", str(exc))

    def _set_release_signal_for_selected(self, value: bool | None):
        """Set contains_release_signal flag for selected packets.
        
        Args:
            value: True to mark as release, False to clear, None to toggle
        """
        try:
            if not self.loader:
                raise ValueError("No PCAP loaded")

            selected_items = self.packet_tree.selection()
            if not selected_items:
                raise ValueError("No packets selected")

            selected_indices = {int(self.packet_tree.item(item, "values")[0]) for item in selected_items}
            
            # Track which UEContextReleaseCommand packets were updated
            updated_release_commands = []
            
            # Update both working and filtered lists
            for meta in self.working_packet_metadata:
                if meta["index"] in selected_indices:
                    old_value = meta.get("contains_release_signal")
                    if value is None:
                        # Toggle
                        new_value = not old_value if old_value is not None else True
                        meta["contains_release_signal"] = new_value
                    else:
                        new_value = value
                        meta["contains_release_signal"] = value
                    
                    # If marking a packet as release but it's not already UEContextReleaseCommand, change it
                    if new_value is True and meta.get("message_name") != "UEContextReleaseCommand":
                        meta["message_name"] = "UEContextReleaseCommand"
                    
                    # Track UEContextReleaseCommand updates
                    if meta.get("message_name") == "UEContextReleaseCommand":
                        updated_release_commands.append({
                            "index": meta["index"],
                            "old_value": old_value,
                            "new_value": new_value
                        })
            
            self._populate_packet_list(self.filtered_packet_metadata)
            self._refresh_status()
            
            action = "marked as release" if value is True else "cleared release flag" if value is False else "toggled release flag"
            log_msg = f"Release signal {action} for {len(selected_indices)} packets"
            
            # Add detailed message for UEContextReleaseCommand updates
            if updated_release_commands:
                cmd_updates = "; ".join([
                    f"Packet {rc['index']}: UEContextReleaseCommand ({rc['old_value']} -> {rc['new_value']})"
                    for rc in updated_release_commands
                ])
                log_msg += f" | {cmd_updates}"
            
            self._log(log_msg)
        except Exception as exc:
            self._log(f"Set release signal failed: {exc}")
            messagebox.showerror("Set Release Signal Failed", str(exc))

    def _validate_ipv4(self, value: str, field_name: str):
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value}") from exc

    def _on_replay(self):
        try:
            if not self.loader:
                raise ValueError("No PCAP loaded")

            selected_items = self.packet_tree.selection()
            if not selected_items:
                raise ValueError("No packets selected")

            new_dst_ip = self.dest_ip_var.get().strip()
            self._validate_ipv4(new_dst_ip, "destination IP")

            host = self.replay_host_var.get().strip()
            self._validate_ipv4(host, "replay host")
            port = int(self.replay_port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError("Port must be 1-65535")

            protocol = self.replay_protocol_var.get().strip().upper()

            packets_to_replay = []
            metadata_by_index = {m["index"]: m for m in self.working_packet_metadata}
            for item in selected_items:
                idx = int(self.packet_tree.item(item, "values")[0])
                if idx not in metadata_by_index:
                    continue
                meta = metadata_by_index[idx]
                pkt_dict = {
                    "index": idx,
                    "packet": meta["packet"].copy(),
                    "dst_ip": new_dst_ip,
                    # Carry user-modified metadata so ZMQ relay can send the overridden values
                    "message_name": meta.get("message_name"),
                    "contains_release_signal": meta.get("contains_release_signal"),
                }
                packets_to_replay.append(pkt_dict)

            if not packets_to_replay:
                raise ValueError("Selected packets are no longer available in the working list")

            if self.replay_thread and self.replay_thread.is_alive():
                raise RuntimeError("Replay already running")

            replayer = ModifiedPcapReplayer(packets_to_replay)
            self._log(f"Replaying {len(packets_to_replay)} packets to {host}:{port} via {protocol}")

            def on_packet_sent(idx, size):
                self._log(f"  [{idx}] Sent {size} bytes")

            if protocol == "SCTP":
                def sctp_worker():
                    try:
                        replayer.replay_to_sctp(host=host, port=port, on_packet_sent=on_packet_sent)
                        self._log("Replay complete")
                    except Exception as e:
                        self._log(f"Replay failed: {e}")

                self.replay_thread = threading.Thread(target=sctp_worker, daemon=False)
                self.replay_thread.start()
            elif protocol == "ZMQ":
                endpoint = self.zmq_endpoint_var.get().strip()
                if not endpoint:
                    raise ValueError("ZMQ endpoint cannot be empty")
                self._log(f"Replaying {len(packets_to_replay)} packets via ZMQ PUSH to {endpoint}")

                def zmq_worker():
                    try:
                        replayer.replay_to_zmq(endpoint=endpoint, on_packet_sent=on_packet_sent)
                        self._log("ZMQ replay complete")
                    except Exception as e:
                        self._log(f"ZMQ replay failed: {e}")

                self.replay_thread = threading.Thread(target=zmq_worker, daemon=False)
                self.replay_thread.start()
            else:
                def udp_worker():
                    try:
                        replayer.replay_to_udp(host=host, port=port, on_packet_sent=on_packet_sent)
                        self._log("Replay complete")
                    except Exception as e:
                        self._log(f"Replay failed: {e}")

                self.replay_thread = threading.Thread(target=udp_worker, daemon=False)
                self.replay_thread.start()

        except Exception as exc:
            self._log(f"Replay failed: {exc}")
            messagebox.showerror("Replay Failed", str(exc))


def main():
    app = NGAPPcapGui()
    app.mainloop()


if __name__ == "__main__":
    main()

