import sys
import os
import socket
import threading
import time
import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import defaultdict
import psutil
import netifaces
import subprocess
import platform
import re
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import queue
import random
import dpkt
from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
from io import StringIO

# Constants
VERSION = "1.0.0"
THEME_COLOR = "#2E8B57"  # Sea Green
DARK_THEME = "#1A3D1A"
LIGHT_THEME = "#E8F5E9"
TEXT_COLOR = "#FFFFFF"
BUTTON_COLOR = "#3CB371"
TERMINAL_BG = "#000000"
TERMINAL_TEXT = "#00FF00"
MAX_LOG_LINES = 1000
UPDATE_INTERVAL = 1000  # ms
PACKET_SNIFF_TIMEOUT = 5  # seconds
THREAT_UPDATE_INTERVAL = 2  # seconds

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Accurate Cyber Defense Monitoring Tool Gui v{VERSION}")
        self.root.geometry("1200x800")
        self.root.configure(bg=THEME_COLOR)
        
        # Initialize variables
        self.monitoring = False
        self.target_ip = ""
        self.packet_count = 0
        self.threat_stats = defaultdict(int)
        self.log_queue = queue.Queue()
        self.terminal_history = []
        self.history_index = 0
        self.current_command = ""
        self.interface = None
        self.sniffer_thread = None
        self.stop_sniffer = threading.Event()
        self.threat_detection_thread = None
        self.stop_threat_detection = threading.Event()
        
        # Setup GUI
        self.setup_gui()
        
        # Start log updater
        self.update_logs()
        
        # Start threat stats updater
        self.update_threat_stats()
        
        # Initialize network interfaces
        self.refresh_interfaces()
        
        # Load saved settings
        self.load_settings()

    def setup_gui(self):
        # Create main frames
        self.main_frame = tk.Frame(self.root, bg=THEME_COLOR)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Controls and Terminal
        self.left_panel = tk.Frame(self.main_frame, bg=DARK_THEME, width=400)
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        
        # Right panel - Logs and Charts
        self.right_panel = tk.Frame(self.main_frame, bg=THEME_COLOR)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Setup left panel components
        self.setup_controls()
        self.setup_terminal()
        
        # Setup right panel components
        self.setup_log_viewer()
        self.setup_charts()
        self.setup_threat_stats()
    
    def setup_controls(self):
        control_frame = tk.LabelFrame(self.left_panel, text="Controls", bg=DARK_THEME, fg=TEXT_COLOR)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP Address Entry
        ip_frame = tk.Frame(control_frame, bg=DARK_THEME)
        ip_frame.pack(fill=tk.X, pady=5)
        tk.Label(ip_frame, text="Target IP:", bg=DARK_THEME, fg=TEXT_COLOR).pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_frame, bg="#333333", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ip_entry.bind("<Return>", lambda e: self.start_monitoring())
        
        # Interface Selection
        if_frame = tk.Frame(control_frame, bg=DARK_THEME)
        if_frame.pack(fill=tk.X, pady=5)
        tk.Label(if_frame, text="Interface:", bg=DARK_THEME, fg=TEXT_COLOR).pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_dropdown = ttk.Combobox(if_frame, textvariable=self.if_var, state="readonly")
        self.if_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Buttons
        btn_frame = tk.Frame(control_frame, bg=DARK_THEME)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="Start Monitoring", bg=BUTTON_COLOR, fg=TEXT_COLOR,
                                  command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        self.stop_btn = tk.Button(btn_frame, text="Stop", bg="#CD5C5C", fg=TEXT_COLOR,
                                 command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        self.refresh_btn = tk.Button(btn_frame, text="Refresh", bg=BUTTON_COLOR, fg=TEXT_COLOR,
                                    command=self.refresh_interfaces)
        self.refresh_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Threat Level Indicator
        threat_frame = tk.Frame(control_frame, bg=DARK_THEME)
        threat_frame.pack(fill=tk.X, pady=5)
        tk.Label(threat_frame, text="Threat Level:", bg=DARK_THEME, fg=TEXT_COLOR).pack(side=tk.LEFT)
        self.threat_level = tk.Label(threat_frame, text="Low", bg="green", fg=TEXT_COLOR)
        self.threat_level.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Packet Counter
        packet_frame = tk.Frame(control_frame, bg=DARK_THEME)
        packet_frame.pack(fill=tk.X, pady=5)
        tk.Label(packet_frame, text="Packets Analyzed:", bg=DARK_THEME, fg=TEXT_COLOR).pack(side=tk.LEFT)
        self.packet_counter = tk.Label(packet_frame, text="0", bg=DARK_THEME, fg=TEXT_COLOR)
        self.packet_counter.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def setup_terminal(self):
        terminal_frame = tk.LabelFrame(self.left_panel, text="Terminal", bg=DARK_THEME, fg=TEXT_COLOR)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame, bg=TERMINAL_BG, fg=TERMINAL_TEXT, 
            insertbackground=TERMINAL_TEXT, wrap=tk.WORD
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        self.terminal_output.bind("<Key>", self.handle_terminal_key)
        
        # Add welcome message
        self.print_terminal("Cyber Security Monitoring Tool - Terminal")
        self.print_terminal("Type 'help' for available commands\n")
        
        # Terminal input
        self.terminal_input = tk.Entry(terminal_frame, bg=TERMINAL_BG, fg=TERMINAL_TEXT,
                                      insertbackground=TERMINAL_TEXT)
        self.terminal_input.pack(fill=tk.X, pady=(0, 5))
        self.terminal_input.bind("<Return>", self.execute_command)
        self.terminal_input.focus_set()
    
    def setup_log_viewer(self):
        log_frame = tk.LabelFrame(self.right_panel, text="Security Logs", bg=THEME_COLOR, fg=TEXT_COLOR)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_viewer = scrolledtext.ScrolledText(
            log_frame, bg="#333333", fg="#00FF00", 
            insertbackground="#00FF00", wrap=tk.WORD
        )
        self.log_viewer.pack(fill=tk.BOTH, expand=True)
        self.log_viewer.config(state=tk.DISABLED)
    
    def setup_charts(self):
        chart_frame = tk.Frame(self.right_panel, bg=THEME_COLOR)
        chart_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        # Create figure for charts
        self.figure, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.figure.patch.set_facecolor(DARK_THEME)
        
        # Set colors for charts
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor(DARK_THEME)
            ax.tick_params(colors=TEXT_COLOR)
            ax.xaxis.label.set_color(TEXT_COLOR)
            ax.yaxis.label.set_color(TEXT_COLOR)
            ax.title.set_color(TEXT_COLOR)
            for spine in ax.spines.values():
                spine.set_edgecolor(TEXT_COLOR)
        
        # Create canvas for charts
        self.chart_canvas = FigureCanvasTkAgg(self.figure, master=chart_frame)
        self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial empty charts
        self.update_charts()
    
    def setup_threat_stats(self):
        stats_frame = tk.LabelFrame(self.right_panel, text="Threat Statistics", bg=THEME_COLOR, fg=TEXT_COLOR)
        stats_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame, bg="#333333", fg="#00FF00", 
            insertbackground="#00FF00", wrap=tk.WORD, height=8
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        self.stats_text.config(state=tk.DISABLED)
    
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces"""
        interfaces = self.get_network_interfaces()
        self.if_dropdown['values'] = interfaces
        if interfaces:
            self.if_var.set(interfaces[0])
    
    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(["netsh", "interface", "show", "interface"]).decode()
                for line in output.splitlines():
                    if "Connected" in line:
                        parts = line.split()
                        if len(parts) > 3:
                            interfaces.append(" ".join(parts[3:]))
            else:
                interfaces = list(netifaces.interfaces())
        except Exception as e:
            self.log_error(f"Error getting interfaces: {str(e)}")
        return interfaces
    
    def start_monitoring(self):
        """Start monitoring the target IP for threats"""
        self.target_ip = self.ip_entry.get().strip()
        if not self.target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        if not self.if_var.get():
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        if self.monitoring:
            messagebox.showwarning("Warning", "Monitoring is already running")
            return
        
        try:
            # Validate IP address
            socket.inet_aton(self.target_ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.ip_entry.config(state=tk.DISABLED)
        self.if_dropdown.config(state=tk.DISABLED)
        
        self.log_message(f"Started monitoring {self.target_ip} on interface {self.if_var.get()}")
        self.print_terminal(f"Started monitoring {self.target_ip}")
        
        # Start packet sniffing in a separate thread
        self.stop_sniffer.clear()
        self.sniffer_thread = threading.Thread(
            target=self.packet_sniffer,
            args=(self.target_ip, self.if_var.get()),
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start threat detection in a separate thread
        self.stop_threat_detection.clear()
        self.threat_detection_thread = threading.Thread(
            target=self.threat_detection,
            args=(self.target_ip,),
            daemon=True
        )
        self.threat_detection_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring the target IP"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        self.stop_sniffer.set()
        self.stop_threat_detection.set()
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
        
        if self.threat_detection_thread and self.threat_detection_thread.is_alive():
            self.threat_detection_thread.join(timeout=1)
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.ip_entry.config(state=tk.NORMAL)
        self.if_dropdown.config(state=tk.NORMAL)
        
        self.log_message(f"Stopped monitoring {self.target_ip}")
        self.print_terminal(f"Stopped monitoring {self.target_ip}")
    
    def packet_sniffer(self, target_ip, interface):
        """Sniff network packets for analysis"""
        self.log_message(f"Packet sniffer started for {target_ip}")
        
        try:
            # Using scapy to sniff packets
            sniff_filter = f"host {target_ip}"
            
            while not self.stop_sniffer.is_set():
                # Sniff packets for a short period
                packets = sniff(
                    filter=sniff_filter,
                    iface=interface,
                    timeout=PACKET_SNIFF_TIMEOUT,
                    prn=lambda p: self.process_packet(p),
                    stop_filter=lambda p: self.stop_sniffer.is_set()
                )
                
                # Update packet count
                self.packet_count += len(packets)
                self.root.after(0, self.update_packet_counter)
                
                # Small delay to prevent high CPU usage
                time.sleep(0.1)
        
        except Exception as e:
            self.log_error(f"Packet sniffer error: {str(e)}")
        
        self.log_message("Packet sniffer stopped")
    
    def process_packet(self, packet):
        """Process individual network packets"""
        try:
            if IP in packet:
                ip_packet = packet[IP]
                src_ip = ip_packet.src
                dst_ip = ip_packet.dst
                
                # Check if packet is related to our target
                if src_ip == self.target_ip or dst_ip == self.target_ip:
                    # Count packet types
                    if TCP in packet:
                        self.threat_stats["tcp_packets"] += 1
                    elif UDP in packet:
                        self.threat_stats["udp_packets"] += 1
                    elif ICMP in packet:
                        self.threat_stats["icmp_packets"] += 1
                    
                    # Detect potential threats
                    self.detect_threats(packet)
        
        except Exception as e:
            self.log_error(f"Error processing packet: {str(e)}")
    
    def detect_threats(self, packet):
        """Detect potential security threats in packets"""
        try:
            if IP in packet:
                ip_packet = packet[IP]
                src_ip = ip_packet.src
                dst_ip = ip_packet.dst
                
                # Port scanning detection
                if TCP in packet:
                    tcp_packet = packet[TCP]
                    if tcp_packet.flags == 0x02:  # SYN flag only
                        self.threat_stats["syn_packets"] += 1
                        
                        # If we see many SYN packets to different ports from same IP
                        if self.threat_stats["syn_packets"] > 50:
                            self.threat_stats["port_scan_attempts"] += 1
                            self.log_message(f"Possible port scan detected from {src_ip}")
                
                # DDoS detection (many packets from different sources)
                if self.threat_stats["total_packets"] > 1000 and \
                   len(self.threat_stats["unique_sources"]) > 50:
                    self.threat_stats["ddos_attempts"] += 1
                    self.log_message(f"Possible DDoS attack detected from multiple sources")
                
                # Flood detection
                current_time = time.time()
                if src_ip in self.threat_stats["source_timestamps"]:
                    last_time = self.threat_stats["source_timestamps"][src_ip]
                    if current_time - last_time < 0.01:  # 100 packets/sec
                        self.threat_stats["flood_attempts"] += 1
                        self.log_message(f"Possible flood attack from {src_ip}")
                
                self.threat_stats["source_timestamps"][src_ip] = current_time
                self.threat_stats["unique_sources"].add(src_ip)
                self.threat_stats["total_packets"] += 1
        
        except Exception as e:
            self.log_error(f"Error detecting threats: {str(e)}")
    
    def threat_detection(self, target_ip):
        """Background threat detection analysis"""
        self.log_message(f"Threat detection started for {target_ip}")
        
        try:
            while not self.stop_threat_detection.is_set():
                # Simulate some threat detection
                if random.random() < 0.05:  # 5% chance of random threat
                    threat_type = random.choice(["Port Scan", "DDoS", "Flood", "Malware"])
                    self.threat_stats[f"{threat_type.lower().replace(' ', '_')}_attempts"] += 1
                    self.log_message(f"Detected possible {threat_type} threat")
                
                # Update threat level
                total_threats = sum(
                    self.threat_stats.get(key, 0) 
                    for key in ["port_scan_attempts", "ddos_attempts", "flood_attempts"]
                )
                
                if total_threats > 20:
                    threat_level = "Critical"
                    color = "red"
                elif total_threats > 10:
                    threat_level = "High"
                    color = "orange"
                elif total_threats > 5:
                    threat_level = "Medium"
                    color = "yellow"
                else:
                    threat_level = "Low"
                    color = "green"
                
                self.root.after(0, lambda: self.threat_level.config(text=threat_level, bg=color))
                
                time.sleep(THREAT_UPDATE_INTERVAL)
        
        except Exception as e:
            self.log_error(f"Threat detection error: {str(e)}")
        
        self.log_message("Threat detection stopped")
    
    def update_packet_counter(self):
        """Update the packet counter display"""
        self.packet_counter.config(text=str(self.packet_count))
    
    def update_charts(self):
        """Update the threat statistics charts"""
        try:
            # Clear previous charts
            self.ax1.clear()
            self.ax2.clear()
            
            # Prepare data for charts
            threat_types = ["Port Scan", "DDoS", "Flood", "Malware"]
            threat_counts = [
                self.threat_stats.get("port_scan_attempts", 0),
                self.threat_stats.get("ddos_attempts", 0),
                self.threat_stats.get("flood_attempts", 0),
                self.threat_stats.get("malware_attempts", 0)
            ]
            
            packet_types = ["TCP", "UDP", "ICMP", "Other"]
            packet_counts = [
                self.threat_stats.get("tcp_packets", 0),
                self.threat_stats.get("udp_packets", 0),
                self.threat_stats.get("icmp_packets", 0),
                max(0, self.packet_count - sum([
                    self.threat_stats.get("tcp_packets", 0),
                    self.threat_stats.get("udp_packets", 0),
                    self.threat_stats.get("icmp_packets", 0)
                ]))
            ]
            
            # Bar chart for threat types
            self.ax1.bar(threat_types, threat_counts, color=['#FF9999', '#66B2FF', '#99FF99', '#FFCC99'])
            self.ax1.set_title("Threat Types", color=TEXT_COLOR)
            self.ax1.set_ylabel("Count", color=TEXT_COLOR)
            
            # Pie chart for packet types
            self.ax2.pie(
                packet_counts, 
                labels=packet_types, 
                autopct='%1.1f%%',
                colors=['#66B2FF', '#FF9999', '#99FF99', '#FFCC99'],
                textprops={'color': TEXT_COLOR}
            )
            self.ax2.set_title("Packet Types", color=TEXT_COLOR)
            
            # Redraw the canvas
            self.figure.tight_layout()
            self.chart_canvas.draw()
        
        except Exception as e:
            self.log_error(f"Error updating charts: {str(e)}")
    
    def update_threat_stats(self):
        """Update the threat statistics text display"""
        try:
            stats_text = f"Threat Statistics for {self.target_ip or 'None'}\n"
            stats_text += "-" * 40 + "\n"
            
            stats_text += f"Packets Analyzed: {self.packet_count}\n"
            stats_text += f"TCP Packets: {self.threat_stats.get('tcp_packets', 0)}\n"
            stats_text += f"UDP Packets: {self.threat_stats.get('udp_packets', 0)}\n"
            stats_text += f"ICMP Packets: {self.threat_stats.get('icmp_packets', 0)}\n"
            stats_text += f"Port Scan Attempts: {self.threat_stats.get('port_scan_attempts', 0)}\n"
            stats_text += f"DDoS Attempts: {self.threat_stats.get('ddos_attempts', 0)}\n"
            stats_text += f"Flood Attempts: {self.threat_stats.get('flood_attempts', 0)}\n"
            stats_text += f"Malware Attempts: {self.threat_stats.get('malware_attempts', 0)}\n"
            stats_text += f"Unique Sources: {len(self.threat_stats.get('unique_sources', set()))}\n"
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self.stats_text.config(state=tk.DISABLED)
            
            # Update charts as well
            self.update_charts()
            
            # Schedule next update
            self.root.after(UPDATE_INTERVAL, self.update_threat_stats)
        
        except Exception as e:
            self.log_error(f"Error updating threat stats: {str(e)}")
            self.root.after(UPDATE_INTERVAL, self.update_threat_stats)
    
    def update_logs(self):
        """Update the log viewer with new messages"""
        try:
            while not self.log_queue.empty():
                log_entry = self.log_queue.get_nowait()
                
                self.log_viewer.config(state=tk.NORMAL)
                if self.log_viewer.index(tk.END).split('.')[0] > str(MAX_LOG_LINES):
                    self.log_viewer.delete(1.0, 2.0)
                self.log_viewer.insert(tk.END, log_entry + "\n")
                self.log_viewer.config(state=tk.DISABLED)
                self.log_viewer.see(tk.END)
        
        except queue.Empty:
            pass
        
        # Schedule next update
        self.root.after(500, self.update_logs)
    
    def log_message(self, message):
        """Add a message to the log queue"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_queue.put(log_entry)
    
    def log_error(self, error):
        """Add an error message to the log queue"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] ERROR: {error}"
        self.log_queue.put(log_entry)
    
    def print_terminal(self, message):
        """Print a message to the terminal"""
        self.terminal_output.config(state=tk.NORMAL)
        if self.terminal_output.index(tk.END).split('.')[0] > str(MAX_LOG_LINES):
            self.terminal_output.delete(1.0, 2.0)
        self.terminal_output.insert(tk.END, message + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    def handle_terminal_key(self, event):
        """Handle special keys in terminal"""
        if event.keysym == "Up":
            # Arrow up - navigate command history
            if self.terminal_history and self.history_index > 0:
                self.history_index -= 1
                self.terminal_input.delete(0, tk.END)
                self.terminal_input.insert(0, self.terminal_history[self.history_index])
        elif event.keysym == "Down":
            # Arrow down - navigate command history
            if self.terminal_history and self.history_index < len(self.terminal_history) - 1:
                self.history_index += 1
                self.terminal_input.delete(0, tk.END)
                self.terminal_input.insert(0, self.terminal_history[self.history_index])
            elif self.terminal_history and self.history_index == len(self.terminal_history) - 1:
                self.history_index += 1
                self.terminal_input.delete(0, tk.END)
        elif event.keysym == "Escape":
            # Escape - clear current input
            self.terminal_input.delete(0, tk.END)
        else:
            # Allow normal typing
            return "break"
    
    def execute_command(self, event):
        """Execute a terminal command"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Add command to history
        self.terminal_history.append(command)
        self.history_index = len(self.terminal_history)
        
        # Print command in terminal
        self.print_terminal(f"> {command}")
        
        # Process command
        try:
            if command.lower() == "help":
                self.show_help()
            elif command.lower().startswith("help "):
                self.show_command_help(command[5:])
            elif command.lower() == "exit":
                self.root.quit()
            elif command.lower() == "clear":
                self.terminal_output.config(state=tk.NORMAL)
                self.terminal_output.delete(1.0, tk.END)
                self.terminal_output.config(state=tk.DISABLED)
            elif command.lower().startswith("start monitoring"):
                parts = command.split()
                if len(parts) >= 3:
                    ip = parts[2]
                    self.ip_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, ip)
                    self.start_monitoring()
                else:
                    self.print_terminal("Usage: start monitoring <IP>")
            elif command.lower() == "stop":
                self.stop_monitoring()
            elif command.lower() == "ifconfig /all":
                self.run_ifconfig()
            elif command.lower().startswith("netsh"):
                self.run_netsh_command(command)
            else:
                self.run_system_command(command)
        
        except Exception as e:
            self.print_terminal(f"Error executing command: {str(e)}")
    
    def show_help(self):
        """Show available commands in terminal"""
        help_text = """Available Commands:
help - Show this help message
help <command> - Show help for specific command
start monitoring <IP> - Start monitoring target IP
stop - Stop monitoring
clear - Clear terminal
exit - Exit the program
ifconfig /all - Show network interfaces
netsh <command> - Run netsh command
"""
        self.print_terminal(help_text)
    
    def show_command_help(self, command):
        """Show help for a specific command"""
        command = command.lower()
        if command == "start monitoring":
            self.print_terminal("Usage: start monitoring <IP>\nStarts monitoring the specified IP address for threats")
        elif command == "stop":
            self.print_terminal("Usage: stop\nStops the current monitoring session")
        elif command == "clear":
            self.print_terminal("Usage: clear\nClears the terminal output")
        elif command == "exit":
            self.print_terminal("Usage: exit\nExits the program")
        elif command == "ifconfig /all":
            self.print_terminal("Usage: ifconfig /all\nDisplays network interface information")
        elif command == "netsh":
            self.print_terminal("Usage: netsh <command>\nExecutes a netsh command")
        else:
            self.print_terminal(f"No help available for command: {command}")
    
    def run_ifconfig(self):
        """Run ifconfig command and show results"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.print_terminal(result.stdout)
            else:
                self.print_terminal(result.stderr)
        except Exception as e:
            self.print_terminal(f"Error running ifconfig: {str(e)}")
    
    def run_netsh_command(self, command):
        """Run a netsh command and show results"""
        try:
            parts = command.split()
            if len(parts) < 2:
                self.print_terminal("Usage: netsh <command> [args...]")
                return
            
            result = subprocess.run(parts, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.print_terminal(result.stdout)
            else:
                self.print_terminal(result.stderr)
        except Exception as e:
            self.print_terminal(f"Error running netsh command: {str(e)}")
    
    def run_system_command(self, command):
        """Run a system command and show results"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.print_terminal(result.stdout)
            else:
                self.print_terminal(result.stderr)
        except Exception as e:
            self.print_terminal(f"Error running command: {str(e)}")
    
    def load_settings(self):
        """Load saved settings from file"""
        try:
            if os.path.exists("cyber_tool_settings.json"):
                with open("cyber_tool_settings.json", "r") as f:
                    settings = json.load(f)
                    self.ip_entry.insert(0, settings.get("last_ip", ""))
                    self.if_var.set(settings.get("last_interface", ""))
        except Exception as e:
            self.log_error(f"Error loading settings: {str(e)}")
    
    def save_settings(self):
        """Save current settings to file"""
        try:
            settings = {
                "last_ip": self.ip_entry.get(),
                "last_interface": self.if_var.get()
            }
            with open("cyber_tool_settings.json", "w") as f:
                json.dump(settings, f)
        except Exception as e:
            self.log_error(f"Error saving settings: {str(e)}")
    
    def on_closing(self):
        """Handle window closing event"""
        self.stop_monitoring()
        self.save_settings()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()