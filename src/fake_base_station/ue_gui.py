import ipaddress
import json
import threading
import tkinter as tk
import socket
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff
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


def _detect_release_signal(payload: bytes) -> bool | None:
    """Detect if NGAP payload contains a release signal."""
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

        return False
    except Exception:
        return None


def _extract_message_name(payload: bytes) -> str | None:
    """Extract NGAP message name from raw payload bytes."""
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
            name = value[0]
            if isinstance(name, str):
                return name
        return None
    except Exception:
        return None


class PacketListener:
    """Captures incoming packets via network sniffing and extracts metadata."""
    
    def __init__(self):
        self.packets_received = []
        self.stop_sniffing = False
        self.sniffer_thread = None
        self.lock = threading.Lock()
        # Filter state
        self.filter_src_ip = None
        self.filter_dst_ip = None
        self.filter_protocol = None
        self.filter_src_port = None
        self.filter_dst_port = None
        self.filter_ngap_only = False
    
    def set_filters(self, src_ip=None, dst_ip=None, protocol=None, src_port=None, dst_port=None, ngap_only=False):
        """Update capture filters (applied during packet inspection)."""
        with self.lock:
            self.filter_src_ip = src_ip
            self.filter_dst_ip = dst_ip
            self.filter_protocol = protocol
            self.filter_src_port = src_port
            self.filter_dst_port = dst_port
            self.filter_ngap_only = ngap_only
    
    def _matches_filter(self, meta: dict) -> bool:
        """Check if packet metadata matches all active filters."""
        if self.filter_src_ip and (meta.get("src_ip") or "") != self.filter_src_ip:
            return False
        if self.filter_dst_ip and (meta.get("dst_ip") or "") != self.filter_dst_ip:
            return False
        if self.filter_protocol and self.filter_protocol != "Any" and (meta.get("protocol") or "") != self.filter_protocol:
            return False
        
        if self.filter_src_port and meta.get("src_port") != self.filter_src_port:
            return False
        if self.filter_dst_port and meta.get("dst_port") != self.filter_dst_port:
            return False
        
        if self.filter_ngap_only and not meta.get("is_ngap"):
            return False
        
        return True
    
    def _packet_callback(self, packet):
        """Called for each captured packet."""
        if self.stop_sniffing:
            return False
        
        try:
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = None
            is_ngap = False
            payload_size = 0
            contains_release_signal = None
            
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
            
            message_name = None
            if is_ngap:
                payload = _extract_ngap_payload(packet)
                contains_release_signal = _detect_release_signal(payload)
                message_name = _extract_message_name(payload)

            timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
            
            metadata = {
                "timestamp": timestamp,
                "datetime": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
                "packet": packet,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "is_ngap": is_ngap,
                "contains_release_signal": contains_release_signal,
                "payload_size": payload_size,
                "message_name": message_name,
            }
            
            # Check filters before storing
            if self._matches_filter(metadata):
                with self.lock:
                    self.packets_received.append(metadata)
        
        except Exception:
            pass
        
        return True
    
    def start_listening(self, iface=None, packet_count=0):
        """Start listening for packets in a background thread."""
        self.stop_sniffing = False
        
        def sniff_worker():
            try:
                sniff(
                    iface=iface,
                    prn=self._packet_callback,
                    store=False,
                    filter="sctp or udp",
                    stop_filter=lambda x: self.stop_sniffing,
                    count=packet_count if packet_count > 0 else 0,
                )
            except Exception as e:
                print(f"Sniffing error: {e}")
        
        self.sniffer_thread = threading.Thread(target=sniff_worker, daemon=False)
        self.sniffer_thread.start()
    
    def stop_listening(self):
        """Stop the packet listener."""
        self.stop_sniffing = True
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
    
    def get_packets(self):
        """Get a copy of all captured packets."""
        with self.lock:
            return list(self.packets_received)
    
    def clear_packets(self):
        """Clear all captured packets."""
        with self.lock:
            self.packets_received.clear()


class ZmqPacketListener:
    """Receives raw NGAP payloads over a ZMQ PULL socket and decodes them."""

    def __init__(self):
        self.packets_received = []
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._socket = None
        self._context = None

    def start_listening(self, endpoint: str = "tcp://127.0.0.1:5555"):
        """Bind a ZMQ PULL socket on `endpoint` and start receiving."""
        if not _ZMQ_AVAILABLE:
            raise ImportError("pyzmq is not installed. Run: pip install pyzmq")
        self._stop_event.clear()
        self._endpoint = endpoint

        def _worker():
            self._context = zmq.Context()
            self._socket = self._context.socket(zmq.PULL)
            self._socket.bind(endpoint)
            self._socket.setsockopt(zmq.RCVTIMEO, 500)  # 500 ms poll timeout
            try:
                while not self._stop_event.is_set():
                    try:
                        raw = self._socket.recv_multipart()
                    except zmq.Again:
                        continue  # timeout, check stop_event
                    self._handle_message(raw)
            finally:
                self._socket.close()
                self._context.term()

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def _handle_message(self, frames):
        """Process a received ZMQ multipart message.

        Expects two frames:
          frames[0]: JSON metadata {"message_name": ..., "contains_release_signal": ...}
          frames[1]: raw NGAP bytes

        Falls back to single-frame (raw bytes only) for backwards compatibility.
        """
        if len(frames) == 2:
            try:
                override = json.loads(frames[0].decode())
            except Exception:
                override = {}
            raw = frames[1]
        else:
            override = {}
            raw = frames[0]

        # Use overridden name from sender if present, else decode from bytes
        message_name = override.get("message_name") or _extract_message_name(raw)
        release_signal = override.get("contains_release_signal")
        if release_signal is None:
            release_signal = _detect_release_signal(raw)

        ts = datetime.now()
        meta = {
            "timestamp": ts.timestamp(),
            "datetime": ts.strftime("%H:%M:%S"),
            "packet": None,
            "src_ip": "zmq-sender",
            "dst_ip": "zmq-self",
            "src_port": None,
            "dst_port": None,
            "protocol": "ZMQ",
            "is_ngap": message_name is not None,
            "contains_release_signal": release_signal,
            "payload_size": len(raw),
            "message_name": message_name or "(unknown)",
        }
        with self.lock:
            self.packets_received.append(meta)

    def stop_listening(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def get_packets(self):
        with self.lock:
            return list(self.packets_received)

    def clear_packets(self):
        with self.lock:
            self.packets_received.clear()


class UEGapGui:
    """User Equipment NGAP Packet Listener GUI."""
    
    def __init__(self):
        self.listener = PacketListener()
        self.zmq_listener = ZmqPacketListener()
        self._active_listener = self.listener  # whichever is currently in use
        self.updating = False
        
        self.root = tk.Tk()
        self.root.title("NGAP UE Listener")
        self.root.geometry("1400x700")
        
        self._setup_ui()
        self._schedule_update()
    
    def _setup_ui(self):
        """Setup the GUI layout."""
        root = self.root
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=3)
        root.rowconfigure(0, weight=1)
        
        # Left panel
        left = ttk.Frame(root)
        left.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        left.columnconfigure(1, weight=1)
        
        # Right panel
        right = ttk.Frame(root)
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        
        # --- LEFT PANEL ---
        row = 0
        ttk.Label(left, text="Listener Configuration", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))
        
        row += 1
        ttk.Label(left, text="Listen Mode", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 4))

        row += 1
        self.listen_mode_var = tk.StringVar(value="Sniff")
        mode_frame = ttk.Frame(left)
        mode_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        ttk.Radiobutton(mode_frame, text="Network Sniff", variable=self.listen_mode_var, value="Sniff", command=self._on_mode_change).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(mode_frame, text="ZMQ PULL", variable=self.listen_mode_var, value="ZMQ", command=self._on_mode_change).pack(side=tk.LEFT)

        row += 1
        ttk.Label(left, text="Interface").grid(row=row, column=0, sticky="w", pady=4)
        self.iface_var = tk.StringVar(value="")
        self._iface_entry = ttk.Entry(left, textvariable=self.iface_var)
        self._iface_entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        ttk.Label(left, text="(empty=all)", font=("Arial", 8)).grid(row=row+1, column=1, sticky="w", padx=6)

        row += 2
        self._zmq_ep_label = ttk.Label(left, text="ZMQ Endpoint")
        self._zmq_ep_label.grid(row=row, column=0, sticky="w", pady=4)
        self.zmq_endpoint_var = tk.StringVar(value="tcp://127.0.0.1:5555")
        self._zmq_ep_entry = ttk.Entry(left, textvariable=self.zmq_endpoint_var)
        self._zmq_ep_entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        self._zmq_ep_label.grid_remove()
        self._zmq_ep_entry.grid_remove()
        
        row += 2
        ttk.Label(left, text="Status").grid(row=row, column=0, sticky="w", pady=4)
        self.status_var = tk.StringVar(value="Stopped")
        tk.Label(left, textvariable=self.status_var, foreground="red").grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        
        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)
        
        row += 1
        ctrl_frame = ttk.Frame(left)
        ctrl_frame.grid(row=row, column=0, columnspan=3, sticky="ew")
        ctrl_frame.columnconfigure(0, weight=1)
        ctrl_frame.columnconfigure(1, weight=1)
        ttk.Button(ctrl_frame, text="Start Listening", command=self._start_listening).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(ctrl_frame, text="Stop Listening", command=self._stop_listening).pack(side=tk.LEFT, padx=3)
        
        row += 1
        ttk.Label(left, text="Packets Captured", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 6))
        
        row += 1
        self.packet_count_var = tk.StringVar(value="0")
        tk.Label(left, textvariable=self.packet_count_var, font=("Arial", 14, "bold"), foreground="blue").grid(row=row, column=0, columnspan=3, sticky="w", pady=4)
        
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
        self.filter_ngap_var = tk.StringVar(value="Yes")
        ttk.Combobox(left, textvariable=self.filter_ngap_var, values=["Any", "Yes", "No"], state="readonly").grid(row=row, column=1, columnspan=2, sticky="ew", padx=6)
        
        row += 1
        filter_btn_frame = ttk.Frame(left)
        filter_btn_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Button(filter_btn_frame, text="Apply Filter", command=self._apply_filter).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(filter_btn_frame, text="Reset Filter", command=self._reset_filter).pack(side=tk.LEFT, padx=4)
        
        row += 1
        ttk.Separator(left).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)
        
        row += 1
        ttk.Button(left, text="Clear All Packets", command=self._clear_packets).grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
        
        # --- RIGHT PANEL: PACKET LIST ---
        list_frame = ttk.LabelFrame(right, text="Captured Packets", padding=6)
        list_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        columns = ("Time", "Src", "Dst", "Protocol", "SrcPort", "DstPort", "Payload", "NGAP", "Message", "Release")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, height=25, selectmode="extended")
        self.packet_tree.column("#0", width=0, stretch=tk.NO)
        self.packet_tree.column("Time", anchor=tk.CENTER, width=80)
        self.packet_tree.column("Src", anchor=tk.W, width=110)
        self.packet_tree.column("Dst", anchor=tk.W, width=110)
        self.packet_tree.column("Protocol", anchor=tk.CENTER, width=60)
        self.packet_tree.column("SrcPort", anchor=tk.CENTER, width=65)
        self.packet_tree.column("DstPort", anchor=tk.CENTER, width=65)
        self.packet_tree.column("Payload", anchor=tk.CENTER, width=65)
        self.packet_tree.column("NGAP", anchor=tk.CENTER, width=50)
        self.packet_tree.column("Message", anchor=tk.W, width=220)
        self.packet_tree.column("Release", anchor=tk.CENTER, width=60)
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=scrollbar.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # --- LOG PANEL ---
        log_frame = ttk.LabelFrame(right, text="Log", padding=6)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = ScrolledText(log_frame, height=10, width=120, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky="nsew")
    
    def _on_mode_change(self):
        """Show/hide interface vs ZMQ endpoint fields based on selected mode."""
        if self.listen_mode_var.get() == "ZMQ":
            self._iface_entry.grid_remove()
            self._zmq_ep_label.grid()
            self._zmq_ep_entry.grid()
        else:
            self._zmq_ep_label.grid_remove()
            self._zmq_ep_entry.grid_remove()
            self._iface_entry.grid()

    def _log(self, message: str):
        """Append message to log."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def _start_listening(self):
        """Start packet listener."""
        try:
            mode = self.listen_mode_var.get()
            if mode == "ZMQ":
                endpoint = self.zmq_endpoint_var.get().strip()
                if not endpoint:
                    raise ValueError("ZMQ endpoint cannot be empty")
                self.zmq_listener.clear_packets()
                self.zmq_listener.start_listening(endpoint=endpoint)
                self._active_listener = self.zmq_listener
                self.status_var.set("Listening (ZMQ)")
                self._log(f"ZMQ PULL listener bound on {endpoint}")
            else:
                iface = self.iface_var.get().strip() or None
                self.listener.clear_packets()
                self.listener.start_listening(iface=iface)
                self._active_listener = self.listener
                self.status_var.set("Listening")
                self._log(f"Sniff listener started on interface: {iface or 'all'}")
        except Exception as exc:
            self._log(f"Failed to start listener: {exc}")
            messagebox.showerror("Start Failed", str(exc))
    
    def _stop_listening(self):
        """Stop packet listener."""
        try:
            self.listener.stop_listening()
            self.zmq_listener.stop_listening()
            self.status_var.set("Stopped")
            self._log("Listener stopped")
        except Exception as exc:
            self._log(f"Failed to stop listener: {exc}")
            messagebox.showerror("Stop Failed", str(exc))
    
    def _matches_filter(self, meta: dict) -> bool:
        """Check if packet matches all active filters (for UI refresh only, not capture)."""
        # Note: Actual filtering happens in PacketListener.set_filters() during capture
        # This method is kept for consistency but the listener stores only filtered packets
        return True
    
    def _apply_filter(self):
        """Apply filters to the listener and refresh display."""
        try:
            src_ip = self.filter_src_ip_var.get().strip() or None
            dst_ip = self.filter_dst_ip_var.get().strip() or None
            protocol = self.filter_protocol_var.get().strip() or "Any"
            src_port = None
            dst_port = None
            
            if self.filter_src_port_var.get().strip():
                try:
                    src_port = int(self.filter_src_port_var.get().strip())
                except ValueError:
                    raise ValueError(f"Invalid Src Port: {self.filter_src_port_var.get().strip()}")
            
            if self.filter_dst_port_var.get().strip():
                try:
                    dst_port = int(self.filter_dst_port_var.get().strip())
                except ValueError:
                    raise ValueError(f"Invalid Dst Port: {self.filter_dst_port_var.get().strip()}")
            
            ngap_only = self.filter_ngap_var.get().strip() == "Yes"
            
            # Update listener filters (applied during capture)
            self.listener.set_filters(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol if protocol != "Any" else None,
                src_port=src_port,
                dst_port=dst_port,
                ngap_only=ngap_only
            )
            
            # Refresh display with newly filtered packets
            self._populate_packet_list()
            all_packets = self._active_listener.get_packets()
            self._log(f"Filter applied: capturing {len(all_packets)} packets")
        except Exception as exc:
            self._log(f"Filter failed: {exc}")
            messagebox.showerror("Filter Failed", str(exc))
    
    def _reset_filter(self):
        """Reset all filters."""
        self.filter_src_ip_var.set("")
        self.filter_dst_ip_var.set("")
        self.filter_protocol_var.set("Any")
        self.filter_src_port_var.set("")
        self.filter_dst_port_var.set("")
        self.filter_ngap_var.set("Yes")
        
        # Clear all filters on listener
        self.listener.set_filters()
        self._populate_packet_list()
        self._log("Filters reset")
    
    def _populate_packet_list(self, packets=None):
        """Populate the packet treeview."""
        if packets is None:
            packets = self._active_listener.get_packets()
        
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        for meta in packets:
            release_val = meta.get("contains_release_signal")
            release_str = "Yes" if release_val is True else "No" if release_val is False else "?"
            ngap_str = "Yes" if meta.get("is_ngap") else "No"
            message_name = meta.get("message_name") or "-"
            
            values = (
                meta.get("datetime", ""),
                meta.get("src_ip") or "N/A",
                meta.get("dst_ip") or "N/A",
                meta.get("protocol") or "N/A",
                str(meta.get("src_port") or "N/A"),
                str(meta.get("dst_port") or "N/A"),
                str(meta.get("payload_size", 0)),
                ngap_str,
                message_name,
                release_str,
            )
            tag = ("ngap",) if meta.get("is_ngap") else ()
            self.packet_tree.insert("", tk.END, values=values, tags=tag)
        
        self.packet_tree.tag_configure("ngap", foreground="green")
    
    def _clear_packets(self):
        """Clear all captured packets."""
        if messagebox.askyesno("Confirm", "Clear all captured packets?"):
            self._active_listener.clear_packets()
            self._populate_packet_list([])
            self.packet_count_var.set("0")
            self._log("All packets cleared")
    
    def _schedule_update(self):
        """Schedule periodic UI update."""
        def update_worker():
            while True:
                try:
                    captured_packets = self._active_listener.get_packets()
                    self.packet_count_var.set(str(len(captured_packets)))
                    self._populate_packet_list(captured_packets)
                    self.root.after(500)
                except Exception:
                    pass

        update_thread = threading.Thread(target=update_worker, daemon=True)
        update_thread.start()
    
    def mainloop(self):
        """Start the GUI event loop."""
        try:
            self.root.mainloop()
        finally:
            self.listener.stop_listening()
            self.zmq_listener.stop_listening()


def main():
    app = UEGapGui()
    app.mainloop()


if __name__ == "__main__":
    main()
