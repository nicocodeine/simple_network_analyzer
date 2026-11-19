import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
from datetime import datetime
import threading
from collections import deque, defaultdict
import ipaddress

try:
    from scapy.all import (
        AsyncSniffer,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        DNS,
        Raw
    )

    SCAPY_AVAILABLE = True

except ImportError:
    SCAPY_AVAILABLE = False
    AsyncSniffer = None

class Packet:
    def __init__(
        self,
        packet_id,
        timestamp,
        source_ip,
        dest_ip,
        protocol,
        src_port,
        dst_port,
        data,
        is_test=False
    ):
        self.packet_id = packet_id
        self.timestamp = timestamp
        self.source_ip = source_ip or "-"
        self.dest_ip = dest_ip or "-"
        self.protocol = protocol or "UNKNOWN"
        self.src_port = src_port if src_port is not None else "-"
        self.dst_port = dst_port if dst_port is not None else "-"
        self.data = data or b""

        self.analysis = ""
        self.source_location = ""
        self.destination_location = ""
        self.vulnerability_flags = []

        self.packet_size = len(self.data)
        self.is_test_packet = is_test

class NetworkAnalyzer:

    def __init__(self):
        self.packets = deque(maxlen=1000)

        self.packet_count = 0

        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.location_stats = defaultdict(int)
        self.vulnerability_stats = defaultdict(int)

    def clear(self):
        self.packets.clear()
        self.packet_count = 0

        self.protocol_stats.clear()
        self.port_stats.clear()
        self.location_stats.clear()
        self.vulnerability_stats.clear()

    def get_ip_location(self, ip):
        if not ip:
            return "Unknown"

        try:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_loopback:
                return "Loopback"

            if ip_obj.is_multicast:
                return "Multicast"

            if ip_obj.is_link_local:
                return "Link-local"

            if ip_obj.is_private:
                return "LAN / Private"

            if ip_obj.is_reserved:
                return "Reserved"

            if ip_obj.is_unspecified:
                return "Unspecified"

            return "Public Network"

        except ValueError:
            return "Unknown"

    def check_vulnerabilities(self, packet):

        vulnerabilities = []

        protocol = packet.protocol
        src_port = packet.src_port
        dst_port = packet.dst_port
        data = packet.data or b""

        if protocol == "TCP":

            if dst_port == 23 or src_port == 23:
                vulnerabilities.append(
                    "TELNET detected - credentials/data may be sent in plaintext"
                )

            if dst_port == 21 or src_port == 21:
                vulnerabilities.append(
                    "FTP detected - credentials/data may be unencrypted"
                )

            if dst_port == 80 or src_port == 80:
                if b"GET " in data or b"POST " in data or b"HTTP/" in data:
                    vulnerabilities.append(
                        "HTTP detected - web traffic is not encrypted"
                    )

            if dst_port == 25 or src_port == 25:
                vulnerabilities.append(
                    "SMTP detected - verify STARTTLS/TLS configuration"
                )

            if dst_port == 110 or src_port == 110:
                vulnerabilities.append(
                    "POP3 detected - verify encrypted authentication"
                )

            if dst_port == 143 or src_port == 143:
                vulnerabilities.append(
                    "IMAP detected - verify encrypted authentication"
                )

            if dst_port == 22 or src_port == 22:
                vulnerabilities.append(
                    "SSH detected - verify authentication and server configuration"
                )

            if dst_port in (3306, 5432, 1433, 1521) or src_port in (3306, 5432, 1433, 1521):
                vulnerabilities.append(
                    "Database service detected - verify network exposure and access control"
                )

            if dst_port in (3389, 5900, 5901) or src_port in (3389, 5900, 5901):
                vulnerabilities.append(
                    "Remote desktop service detected - verify authentication and exposure"
                )

        elif protocol == "UDP":

            if dst_port == 53 or src_port == 53:
                vulnerabilities.append(
                    "DNS traffic - inspect for unusual queries or possible tunneling"
                )

            if dst_port in (67, 68) or src_port in (67, 68):
                vulnerabilities.append(
                    "DHCP traffic - verify trusted DHCP server"
                )

            if dst_port == 123 or src_port == 123:
                vulnerabilities.append(
                    "NTP traffic - verify trusted time source"
                )

            if dst_port == 161 or src_port == 161:
                vulnerabilities.append(
                    "SNMP traffic detected - verify community/authentication settings"
                )

            if dst_port == 1900 or src_port == 1900:
                vulnerabilities.append(
                    "SSDP/UPnP traffic detected - verify device exposure"
                )

            if dst_port in (137, 138) or src_port in (137, 138):
                vulnerabilities.append(
                    "NetBIOS traffic detected - verify local network exposure"
                )

        elif protocol == "ICMP":
            vulnerabilities.append(
                "ICMP traffic detected - verify that echo/reachability traffic is expected"
            )

        if len(data) > 1024:
            vulnerabilities.append(
                f"Large payload detected ({len(data)} bytes) - low severity"
            )

        try:
            data_str = data.decode(
                "utf-8",
                errors="ignore"
            ).lower()
        except Exception:
            data_str = ""

        sensitive_words = [
            "password=",
            "passwd=",
            "username=",
            "user=",
            "authorization:",
            "basic ",
            "login=",
            "token=",
            "api_key=",
            "apikey=",
            "secret="
        ]

        if any(word in data_str for word in sensitive_words):
            vulnerabilities.append(
                "Possible credential or authentication data exposure"
            )

        if protocol == "TCP" and data:
            if b"OPTIONS " in data or b"TRACE " in data:
                vulnerabilities.append(
                    "Unusual HTTP method detected - review request"
                )

        return vulnerabilities

    def analyze_protocol(
        self,
        protocol,
        src_port,
        dst_port,
        data
    ):

        ports = []

        if isinstance(src_port, int):
            ports.append(src_port)

        if isinstance(dst_port, int):
            ports.append(dst_port)

        if protocol == "TCP":

            if 80 in ports:
                return "HTTP"

            if 443 in ports:
                return "HTTPS"

            if 22 in ports:
                return "SSH"

            if 21 in ports:
                return "FTP"

            if 23 in ports:
                return "TELNET"

            if 25 in ports:
                return "SMTP"

            return "TCP"

        if protocol == "UDP":

            if 53 in ports:
                return "DNS"

            if 67 in ports or 68 in ports:
                return "DHCP"

            if 123 in ports:
                return "NTP"

            return "UDP"

        if protocol == "ICMP":
            return "ICMP"

        return protocol

    def capture_packet(
        self,
        source_ip,
        dest_ip,
        protocol,
        src_port,
        dst_port,
        data,
        is_test=False
    ):

        self.packet_count += 1

        packet = Packet(
            packet_id=self.packet_count,
            timestamp=time.time(),
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            data=data,
            is_test=is_test
        )

        packet.source_location = self.get_ip_location(
            packet.source_ip
        )

        packet.destination_location = self.get_ip_location(
            packet.dest_ip
        )

        packet.analysis = self.analyze_protocol(
            packet.protocol,
            packet.src_port,
            packet.dst_port,
            packet.data
        )

        packet.vulnerability_flags = self.check_vulnerabilities(
            packet
        )

        self.packets.append(packet)

        self.protocol_stats[packet.protocol] += 1

        port_pair = (
            f"{packet.src_port}->{packet.dst_port}"
        )

        self.port_stats[port_pair] += 1

        location_pair = (
            f"{packet.source_location}"
            f" -> "
            f"{packet.destination_location}"
        )

        self.location_stats[location_pair] += 1

        for vulnerability in packet.vulnerability_flags:
            self.vulnerability_stats[vulnerability] += 1

        return packet

class SimpleNetworkAnalyzerGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Simple Network Analyzer"
        )

        self.root.geometry(
            "1450x900"
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close
        )

        self.analyzer = NetworkAnalyzer()

        self.current_filter = "ALL"
        self.filter_buttons = {}

        self.capture_running = False

        self.sniffer = None

        self.capture_thread = None

        self.simulation_thread = None

        self.setup_ui()

    def setup_ui(self):

        main_frame = ttk.Frame(
            self.root
        )

        main_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=10
        )

        control_frame = ttk.Frame(
            main_frame
        )

        control_frame.pack(
            fill=tk.X,
            pady=(0, 10)
        )

        self.start_button = ttk.Button(
            control_frame,
            text="▶ Start Capture",
            command=self.start_capture
        )

        self.start_button.pack(
            side=tk.LEFT,
            padx=5
        )

        self.stop_button = ttk.Button(
            control_frame,
            text="■ Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED
        )

        self.stop_button.pack(
            side=tk.LEFT,
            padx=5
        )

        self.clear_button = ttk.Button(
            control_frame,
            text="Clear",
            command=self.clear_packets
        )

        self.clear_button.pack(
            side=tk.LEFT,
            padx=5
        )

        self.status_label = ttk.Label(
            control_frame,
            text="Status: Stopped"
        )

        self.status_label.pack(
            side=tk.RIGHT,
            padx=5
        )

        filter_frame = ttk.Frame(
            main_frame
        )

        filter_frame.pack(
            fill=tk.X,
            pady=(0, 6)
        )

        ttk.Label(
            filter_frame,
            text="Filters:"
        ).pack(
            side=tk.LEFT,
            padx=(5, 8)
        )

        filters = [
            ("ALL", "All packets"),
            ("TCP", "TCP"),
            ("UDP", "UDP"),
            ("DNS", "DNS"),
            ("HTTP", "HTTP"),
            ("HTTPS", "HTTPS"),
            ("SSH", "SSH"),
            ("ALERTS", "Alerts only"),
            ("LOW", "Low"),
            ("MEDIUM", "Medium"),
            ("HIGH", "High"),
            ("CRITICAL", "Critical")
        ]

        severity_colors = {
            "LOW": "#fff3cd",
            "MEDIUM": "#ffd8a8",
            "HIGH": "#ffaaaa",
            "CRITICAL": "#ff6666",
        }

        for filter_name, button_text in filters:
            button_kwargs = {
                "text": button_text,
                "relief": tk.RAISED,
                "bd": 2,
                "padx": 8,
                "pady": 2,
                "command": lambda name=filter_name: self.set_filter(name),
                "cursor": "hand2",
            }

            if filter_name in severity_colors:
                button_kwargs["bg"] = severity_colors[filter_name]
                button_kwargs["activebackground"] = severity_colors[filter_name]
                button_kwargs["fg"] = "#ffffff" if filter_name == "CRITICAL" else "#111111"

            button = tk.Button(filter_frame, **button_kwargs)
            button.pack(
                side=tk.LEFT,
                padx=2
            )
            self.filter_buttons[filter_name] = button

        legend_frame = ttk.Frame(
            main_frame
        )

        legend_frame.pack(
            fill=tk.X,
            pady=(0, 8)
        )

        ttk.Label(
            legend_frame,
            text="Alerts:"
        ).pack(
            side=tk.LEFT,
            padx=(5, 8)
        )

        self.add_alert_legend(
            legend_frame,
            "LOW",
            "#fff3cd"
        )
        self.add_alert_legend(
            legend_frame,
            "MEDIUM",
            "#ffd8a8"
        )
        self.add_alert_legend(
            legend_frame,
            "HIGH",
            "#ffaaaa"
        )
        self.add_alert_legend(
            legend_frame,
            "CRITICAL",
            "#ff6666"
        )

        list_frame = ttk.Frame(
            main_frame
        )

        list_frame.pack(
            fill=tk.BOTH,
            expand=True
        )

        columns = (
            "Num",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Ports",
            "Size",
            "Location",
            "Analysis"
        )

        self.packet_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings"
        )

        widths = {
            "Num": 60,
            "Time": 100,
            "Source": 180,
            "Destination": 180,
            "Protocol": 90,
            "Ports": 120,
            "Size": 80,
            "Location": 220,
            "Analysis": 120
        }

        for column in columns:

            self.packet_tree.heading(
                column,
                text=column
            )

            self.packet_tree.column(
                column,
                width=widths.get(
                    column,
                    100
                ),
                anchor=tk.W
            )

        vertical_scrollbar = ttk.Scrollbar(
            list_frame,
            orient=tk.VERTICAL,
            command=self.packet_tree.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            list_frame,
            orient=tk.HORIZONTAL,
            command=self.packet_tree.xview
        )

        self.packet_tree.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        self.configure_alert_tags()

        self.packet_tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        vertical_scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        horizontal_scrollbar.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )

        analysis_frame = ttk.LabelFrame(
            main_frame,
            text="Packet Analysis"
        )

        analysis_frame.pack(
            fill=tk.X,
            pady=(10, 0)
        )

        self.analysis_text = scrolledtext.ScrolledText(
            analysis_frame,
            height=10,
            wrap=tk.WORD,
            state=tk.DISABLED
        )

        self.analysis_text.pack(
            fill=tk.BOTH,
            expand=True,
            padx=5,
            pady=5
        )

        vuln_frame = ttk.LabelFrame(
            main_frame,
            text="Security Warnings"
        )

        vuln_frame.pack(
            fill=tk.X,
            pady=(10, 0)
        )

        self.vuln_text = scrolledtext.ScrolledText(
            vuln_frame,
            height=6,
            wrap=tk.WORD,
            state=tk.DISABLED
        )

        self.vuln_text.pack(
            fill=tk.BOTH,
            expand=True,
            padx=5,
            pady=5
        )

        self.packet_tree.bind(
            "<<TreeviewSelect>>",
            self.on_packet_select
        )

        self.set_filter("ALL")

    def start_capture(self):

        if self.capture_running:
            return

        self.capture_running = True

        self.start_button.config(
            state=tk.DISABLED
        )

        self.stop_button.config(
            state=tk.NORMAL
        )

        if SCAPY_AVAILABLE:

            self.status_label.config(
                text="Status: Capturing real traffic"
            )

            self.capture_thread = threading.Thread(
                target=self.start_real_capture,
                daemon=True
            )

            self.capture_thread.start()

        else:

            self.status_label.config(
                text="Status: Simulation mode"
            )

            self.simulation_thread = threading.Thread(
                target=self.simulate_capture,
                daemon=True
            )

            self.simulation_thread.start()

    def start_real_capture(self):

        try:

            self.sniffer = AsyncSniffer(
                prn=self.process_packet,
                store=False
            )

            self.sniffer.start()

        except Exception as error:

            self.root.after(
                0,
                self.real_capture_failed,
                str(error)
            )

    def real_capture_failed(self, error):

        self.capture_running = False

        self.start_button.config(
            state=tk.NORMAL
        )

        self.stop_button.config(
            state=tk.DISABLED
        )

        self.status_label.config(
            text="Status: Capture failed"
        )

        messagebox.showerror(
            "Capture error",
            "Could not start real packet capture.\n\n"
            f"{error}\n\n"
            "The application will switch to simulation mode."
        )

        if not self.capture_running:

            self.capture_running = True

            self.status_label.config(
                text="Status: Simulation mode"
            )

            self.simulation_thread = threading.Thread(
                target=self.simulate_capture,
                daemon=True
            )

            self.simulation_thread.start()

    def stop_capture(self):
        if not self.capture_running:
            return

        self.capture_running = False

        sniffer = self.sniffer
        self.sniffer = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as error:
                print("Error stopping sniffer:", error)


    def process_packet(self, packet):

        if not self.capture_running:
            return

        try:

            src_ip = "-"
            dst_ip = "-"
            protocol = "OTHER"

            src_port = "-"
            dst_port = "-"

            data = b""

            if IP in packet:

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            elif IPv6 in packet:

                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            if TCP in packet:

                protocol = "TCP"

                src_port = int(
                    packet[TCP].sport
                )

                dst_port = int(
                    packet[TCP].dport
                )

                if Raw in packet:

                    data = bytes(
                        packet[Raw].load
                    )

            elif UDP in packet:

                protocol = "UDP"

                src_port = int(
                    packet[UDP].sport
                )

                dst_port = int(
                    packet[UDP].dport
                )

                if Raw in packet:

                    data = bytes(
                        packet[Raw].load
                    )

            elif ICMP in packet:

                protocol = "ICMP"

                if Raw in packet:

                    data = bytes(
                        packet[Raw].load
                    )

            packet_obj = self.analyzer.capture_packet(
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                data,
                is_test=False
            )

            self.root.after(
                0,
                self.update_packet_list,
                packet_obj
            )

        except Exception as error:

            print(
                "Packet processing error:",
                error
            )

    def simulate_capture(self):

        test_packets = [

            (
                "192.168.1.100",
                "8.8.8.8",
                "UDP",
                53000,
                53,
                b"DNS query for google.com",
                False
            ),

            (
                "192.168.1.100",
                "192.168.1.1",
                "TCP",
                54321,
                80,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                False
            ),

            (
                "192.168.1.100",
                "192.168.1.1",
                "TCP",
                54322,
                443,
                b"TLS Client Hello",
                False
            ),

            (
                "192.168.1.100",
                "192.168.1.1",
                "TCP",
                54323,
                22,
                b"SSH connection",
                False
            ),

            (
                "192.168.1.100",
                "192.168.1.1",
                "UDP",
                54324,
                53,
                b"DNS response for example.com",
                False
            ),

            (
                "10.0.0.5",
                "172.16.0.10",
                "TCP",
                443,
                54321,
                b"HTTPS request to internal server",
                False
            ),

            (
                "192.168.1.200",
                "10.0.0.1",
                "UDP",
                67,
                68,
                b"DHCP request from client",
                False
            ),

            (
                "192.168.1.50",
                "203.0.113.50",
                "TCP",
                80,
                443,
                b"Web application access",
                False
            ),

            (
                "192.168.1.75",
                "192.168.1.1",
                "UDP",
                53001,
                53,
                b"DNS query for internal.company.com",
                False
            ),

            (
                "10.0.0.100",
                "10.0.0.50",
                "TCP",
                22,
                54321,
                b"SSH authentication attempt",
                False
            ),

            (
                "192.168.1.150",
                "10.0.0.200",
                "TCP",
                54321,
                80,
                b"A" * 2048,
                True
            ),

            (
                "192.168.1.250",
                "192.168.1.254",
                "UDP",
                53002,
                53,
                b"Test packet for demo purposes",
                True
            ),

            (
                "192.168.1.60",
                "192.168.1.10",
                "TCP",
                51000,
                23,
                b"login=admin password=demo123",
                True
            ),

            (
                "192.168.1.61",
                "192.168.1.20",
                "TCP",
                51001,
                3306,
                b"Database connection",
                True
            ),

            (
                "192.168.1.62",
                "192.168.1.21",
                "UDP",
                51002,
                161,
                b"SNMP request",
                True
            ),

            (
                "192.168.1.63",
                "192.168.1.22",
                "UDP",
                51003,
                1900,
                b"SSDP discovery",
                True
            ),

            (
                "192.168.1.64",
                "192.168.1.23",
                "TCP",
                51004,
                3389,
                b"Remote desktop connection",
                True
            ),

            (
                "192.168.1.65",
                "192.168.1.24",
                "ICMP",
                "-",
                "-",
                b"ping",
                True
            )
        ]

        index = 0

        while self.capture_running:

            source, destination, protocol, src_port, dst_port, data, is_test = (
                test_packets[index % len(test_packets)]
            )

            packet = self.analyzer.capture_packet(
                source,
                destination,
                protocol,
                src_port,
                dst_port,
                data,
                is_test
            )

            self.root.after(
                0,
                self.update_packet_list,
                packet
            )

            index += 1

            time.sleep(1)

    def add_alert_legend(self, parent, text, background):
        label = tk.Label(
            parent,
            text=f" {text} ",
            bg=background,
            fg="#111111" if text != "CRITICAL" else "#ffffff",
            relief=tk.GROOVE,
            bd=1,
            padx=5,
            pady=2
        )
        label.pack(side=tk.LEFT, padx=3)

    def set_filter(self, filter_name):
        self.current_filter = filter_name

        severity_colors = {
            "LOW": "#fff3cd",
            "MEDIUM": "#ffd8a8",
            "HIGH": "#ffaaaa",
            "CRITICAL": "#ff6666",
        }

        for name, button in self.filter_buttons.items():
            if name == filter_name:
                button.config(relief=tk.SUNKEN, bd=3)

                if name in severity_colors:
                    button.config(
                        bg=severity_colors[name],
                        activebackground=severity_colors[name]
                    )
                else:
                    button.config(bg="#d9d9d9")
            else:
                button.config(relief=tk.RAISED, bd=2)

                if name in severity_colors:
                    button.config(
                        bg=severity_colors[name],
                        activebackground=severity_colors[name]
                    )
                else:
                    button.config(bg="#f0f0f0")

        self.refresh_packet_list()

    def packet_matches_filter(self, packet):
        if self.current_filter == "ALL":
            return True

        if self.current_filter == "ALERTS":
            return bool(packet.vulnerability_flags)

        if self.current_filter in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            return self.get_alert_tag(packet) == self.current_filter.lower()

        if self.current_filter == "TCP":
            return packet.protocol == "TCP"

        if self.current_filter == "UDP":
            return packet.protocol == "UDP"

        analyzed = packet.analysis

        if self.current_filter in ("DNS", "HTTP", "HTTPS", "SSH"):
            return analyzed == self.current_filter

        return False

    def get_alert_tag(self, packet):
        if not packet.vulnerability_flags:
            if packet.is_test_packet:
                return "test"
            return "normal"

        text = " ".join(packet.vulnerability_flags).lower()

        if (
            "credential or authentication data exposure" in text
            or "password=" in text
            or "passwd=" in text
            or "authorization:" in text
            or "api_key=" in text
            or "apikey=" in text
            or "secret=" in text
        ):
            return "critical"

        if (
            "telnet" in text
            or "ftp detected" in text
            or "remote desktop service" in text
            or "database service" in text
        ):
            return "high"

        if (
            "http detected" in text
            or "smtp detected" in text
            or "pop3 detected" in text
            or "imap detected" in text
            or "dns traffic" in text
            or "dhcp traffic" in text
            or "ntp traffic" in text
            or "snmp traffic" in text
            or "ssdp/upnp" in text
            or "netbios traffic" in text
            or "ssh detected" in text
            or "unusual http method" in text
        ):
            return "medium"

        if (
            "large payload" in text
            or "icmp traffic" in text
        ):
            return "low"

        return "low"

    def configure_alert_tags(self):
        self.packet_tree.tag_configure(
            "normal",
            background="#ffffff",
            foreground="#111111"
        )

        self.packet_tree.tag_configure(
            "test",
            background="#fff4cc",
            foreground="#111111"
        )

        self.packet_tree.tag_configure(
            "low",
            background="#fff3cd",
            foreground="#5c4a00"
        )

        self.packet_tree.tag_configure(
            "medium",
            background="#ffd8a8",
            foreground="#6a3500"
        )

        self.packet_tree.tag_configure(
            "high",
            background="#ffaaaa",
            foreground="#5c0000"
        )

        self.packet_tree.tag_configure(
            "critical",
            background="#ff6666",
            foreground="#ffffff"
        )

    def refresh_packet_list(self):
        self.packet_tree.delete(
            *self.packet_tree.get_children()
        )

        for packet in self.analyzer.packets:
            if not self.packet_matches_filter(packet):
                continue

            timestamp = datetime.fromtimestamp(
                packet.timestamp
            ).strftime(
                "%H:%M:%S.%f"
            )[:-3]

            item_id = self.packet_tree.insert(
                "",
                tk.END,
                values=(
                    packet.packet_id,
                    timestamp,
                    f"{packet.source_ip}:{packet.src_port}",
                    f"{packet.dest_ip}:{packet.dst_port}",
                    packet.protocol,
                    f"{packet.src_port} -> {packet.dst_port}",
                    f"{packet.packet_size} B",
                    f"{packet.source_location} -> {packet.destination_location}",
                    packet.analysis
                )
            )

            self.packet_tree.item(
                item_id,
                tags=(self.get_alert_tag(packet),)
            )

        self.packet_tree.see(
            self.packet_tree.get_children()[-1]
        ) if self.packet_tree.get_children() else None

    def update_packet_list(self, packet):
        if not self.capture_running:
            return

        try:
            if not self.root.winfo_exists():
                return
        except tk.TclError:
            return

        self.refresh_packet_list()

    def on_packet_select(self, event=None):

        selection = self.packet_tree.selection()

        if not selection:
            return

        item = self.packet_tree.item(
            selection[0]
        )

        values = item.get(
            "values",
            []
        )

        if not values:
            return

        try:

            packet_id = int(
                values[0]
            )

        except (ValueError, TypeError):

            return

        packet_obj = None

        for packet in self.analyzer.packets:

            if packet.packet_id == packet_id:

                packet_obj = packet
                break

        if packet_obj is None:
            return

        self.analysis_text.config(
            state=tk.NORMAL
        )

        self.analysis_text.delete(
            "1.0",
            tk.END
        )

        self.analysis_text.insert(
            tk.END,
            f"Protocol: {packet_obj.analysis}\n\n"
        )

        self.analysis_text.insert(
            tk.END,
            "Packet details\n"
        )

        self.analysis_text.insert(
            tk.END,
            "-------------------------\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Number: {packet_obj.packet_id}\n"
        )

        self.analysis_text.insert(
            tk.END,
            "Time: "
            + datetime.fromtimestamp(
                packet_obj.timestamp
            ).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3]
            + "\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Source: {packet_obj.source_ip}:{packet_obj.src_port}\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Destination: {packet_obj.dest_ip}:{packet_obj.dst_port}\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Protocol: {packet_obj.protocol}\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Analysis: {packet_obj.analysis}\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Size: {packet_obj.packet_size} bytes\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Source location: {packet_obj.source_location}\n"
        )

        self.analysis_text.insert(
            tk.END,
            f"Destination location: {packet_obj.destination_location}\n"
        )

        if packet_obj.is_test_packet:

            self.analysis_text.insert(
                tk.END,
                "\n⚠ TEST PACKET\n"
            )

            self.analysis_text.insert(
                tk.END,
                "This packet was generated by simulation mode.\n"
            )

        self.analysis_text.config(
            state=tk.DISABLED
        )

        self.vuln_text.config(
            state=tk.NORMAL
        )

        self.vuln_text.delete(
            "1.0",
            tk.END
        )

        if packet_obj.vulnerability_flags:

            self.vuln_text.insert(
                tk.END,
                "⚠ SECURITY WARNINGS\n\n"
            )

            for vulnerability in packet_obj.vulnerability_flags:

                self.vuln_text.insert(
                    tk.END,
                    f"• {vulnerability}\n"
                )

        else:

            self.vuln_text.insert(
                tk.END,
                "✓ No immediate security warnings detected."
            )

        self.vuln_text.config(
            state=tk.DISABLED
        )

    def clear_packets(self):

        self.analyzer.clear()

        self.packet_tree.delete(
            *self.packet_tree.get_children()
        )

        self.analysis_text.config(
            state=tk.NORMAL
        )

        self.analysis_text.delete(
            "1.0",
            tk.END
        )

        self.analysis_text.config(
            state=tk.DISABLED
        )

        self.vuln_text.config(
            state=tk.NORMAL
        )

        self.vuln_text.delete(
            "1.0",
            tk.END
        )

        self.vuln_text.config(
            state=tk.DISABLED
        )

    def on_close(self):

        self.capture_running = False

        try:

            if self.sniffer is not None:

                self.sniffer.stop()

                self.sniffer = None

        except Exception:
            pass

        self.root.destroy()

def main():

    root = tk.Tk()

    app = SimpleNetworkAnalyzerGUI(
        root
    )

    style = ttk.Style()

    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "Treeview",
        rowheight=25
    )

    root.mainloop()

if __name__ == "__main__":
    main()
