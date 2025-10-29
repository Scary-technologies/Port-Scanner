import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import queue
import time
import ipaddress

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class PortScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner v4.1 Optimized")
        self.geometry("1000x700")
        
        self.task_running = False
        self.checking_ips = False
        self.scanned_tasks = 0
        self.total_tasks = 0
        self.scanned_ips = 0
        self.total_ips = 0
        self.alive_ips = []
        self.active_scans = {}
        self.open_ports = {}
        self.gui_queue = queue.Queue()
        self.q = queue.Queue()
        
        self._create_widgets()
        self._setup_style()
        self._setup_layout()
        
        self.after(100, self.update_gui)

    def _create_widgets(self):
        self.input_frame = ctk.CTkFrame(self, corner_radius=10)
        
        self.lbl_target = ctk.CTkLabel(self.input_frame, text="Target IP/Range:")
        self.entry_target = ctk.CTkEntry(self.input_frame, width=300, placeholder_text="192.168.1.1-100")
        self.entry_target.insert(0, "192.168.1.1-100")
        
        self.lbl_ports = ctk.CTkLabel(self.input_frame, text="Port Range:")
        self.entry_ports = ctk.CTkEntry(self.input_frame, width=300, placeholder_text="1-1000")
        self.entry_ports.insert(0, "1-1000")
        
        self.lbl_threads = ctk.CTkLabel(self.input_frame, text="Threads:")
        self.thread_selector = ctk.CTkComboBox(
            self.input_frame, 
            values=["50", "100", "200", "500"],
            width=120,
            button_color="#2A8C55",
            dropdown_fg_color="#333333"
        )
        self.thread_selector.set("100")
        
        self.notebook = ttk.Notebook(self)
        self.log_tab = ctk.CTkFrame(self.notebook)
        self.status_tab = ctk.CTkFrame(self.notebook)
        self.open_ports_tab = ctk.CTkFrame(self.notebook)
        
        self.notebook.add(self.log_tab, text="Logs")
        self.notebook.add(self.status_tab, text="Active Scans")
        self.notebook.add(self.open_ports_tab, text="Open Ports")
        
        self.text_area = ctk.CTkTextbox(self.log_tab, wrap="none", font=("Consolas", 12))
        self.text_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(
            self.status_tab,
            columns=("ip", "port", "status"),
            show="headings",
            style="Custom.Treeview"
        )
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("port", text="Port")
        self.tree.heading("status", text="Status")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.open_ports_tree = ttk.Treeview(
            self.open_ports_tab,
            columns=("ip", "ports"),
            show="headings",
            style="Custom.Treeview"
        )
        self.open_ports_tree.heading("ip", text="IP Address")
        self.open_ports_tree.heading("ports", text="Open Ports")
        self.open_ports_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.status_frame = ctk.CTkFrame(self, height=30, corner_radius=0)
        self.progress_label = ctk.CTkLabel(self.status_frame, text="Ready", text_color="#2A8C55")
        self.progress = ctk.CTkProgressBar(self.status_frame, orientation="horizontal", mode="determinate")
        
        self.control_frame = ctk.CTkFrame(self, corner_radius=10)
        self.btn_scan = ctk.CTkButton(
            self.control_frame,
            text="Start Scan",
            command=self.start_scan_thread,
            fg_color="#2A8C55",
            hover_color="#1F6C44",
            corner_radius=8
        )
        self.btn_stop = ctk.CTkButton(
            self.control_frame,
            text="Stop Scan",
            command=self.stop_scan,
            fg_color="#D32F2F",
            hover_color="#B71C1C",
            state="disabled",
            corner_radius=8
        )
        self.btn_export = ctk.CTkButton(
            self.control_frame,
            text="Export Results",
            command=self.export_results,
            fg_color="#1976D2",
            hover_color="#1565C0",
            corner_radius=8
        )

    def _setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure("Custom.Treeview",
                            background="#2a2d2e",
                            foreground="white",
                            fieldbackground="#2a2d2e",
                            bordercolor="#343638",
                            borderwidth=0,
                            font=('Segoe UI', 10),
                            rowheight=25)
        
        self.style.configure("Custom.Treeview.Heading",
                            background="#2A8C55",
                            foreground="white",
                            font=('Segoe UI', 10, 'bold'),
                            relief="flat")
        
        self.style.map("Custom.Treeview",
                      background=[('selected', '#22559b')],
                      foreground=[('selected', 'white')])

    def _setup_layout(self):
        self.input_frame.pack(pady=15, padx=15, fill="x")
        self.lbl_target.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_target.grid(row=0, column=1, padx=5, pady=5)
        self.lbl_ports.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_ports.grid(row=1, column=1, padx=5, pady=5)
        self.lbl_threads.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.thread_selector.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        self.notebook.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.status_frame.pack(fill="x", padx=15, pady=5)
        self.progress_label.pack(side="left", padx=10)
        self.progress.pack(side="right", padx=10, fill="x", expand=True)
        
        self.control_frame.pack(pady=15, padx=15, fill="x")
        self.btn_scan.pack(side="left", padx=10)
        self.btn_stop.pack(side="left", padx=10)
        self.btn_export.pack(side="right", padx=10)

    def parse_ip_range(self, target):
        target = target.strip()
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                return [str(host) for host in network.hosts()]
            except:
                return None
        if '-' in target:
            parts = target.split('-')
            try:
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_part = parts[1].strip()
                if '.' not in end_part:
                    base_ip = parts[0].rsplit('.', 1)[0]
                    end_ip = f"{base_ip}.{end_part}"
                    end_ip = ipaddress.IPv4Address(end_ip)
                else:
                    end_ip = ipaddress.IPv4Address(end_part)
                ips = []
                current_ip = start_ip
                while current_ip <= end_ip:
                    ips.append(str(current_ip))
                    current_ip += 1
                return ips
            except:
                return None
        try:
            ipaddress.IPv4Address(target)
            return [target]
        except:
            try:
                return [socket.gethostbyname(target)]
            except:
                return None

    def validate_input(self):
        ips = self.parse_ip_range(self.entry_target.get())
        if not ips:
            messagebox.showerror("Error", "Invalid IP Range")
            return False
        try:
            start, end = map(int, self.entry_ports.get().split('-'))
            if not 1 <= start <= end <= 65535:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid Port Range")
            return False
        return True

    def is_host_alive(self, ip):
        ports_to_check = [80, 443, 22, 21, 53]
        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False

    def ip_check_worker(self, ip_queue):
        while self.task_running and not ip_queue.empty():
            try:
                ip = ip_queue.get_nowait()
                if self.is_host_alive(ip):
                    self.alive_ips.append(ip)
                self.scanned_ips += 1
                self.gui_queue.put(("progress",))
                ip_queue.task_done()
            except:
                pass

    def scan_port(self, ip, port):
        if not self.task_running:
            return
        self.gui_queue.put(("start", ip, port))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "unknown"
                self.text_area.insert("end", f"[+] {ip}:{port} ({service}) OPEN\n")
                self.gui_queue.put(("end", ip, port, True))
            else:
                self.gui_queue.put(("end", ip, port, False))
            sock.close()
        except Exception as e:
            self.text_area.insert("end", f"[!] {ip}:{port} ERROR: {str(e)}\n")
            self.gui_queue.put(("end", ip, port, False))
        
        self.scanned_tasks += 1
        self.gui_queue.put(("progress",))

    def worker(self):
        while self.task_running and not self.q.empty():
            ip, port = self.q.get()
            self.scan_port(ip, port)
            self.q.task_done()

    def start_scan_thread(self):
        if not self.validate_input():
            return
        
        self.task_running = True
        self.checking_ips = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.text_area.delete('1.0', "end")
        self.progress["value"] = 0
        self.scanned_tasks = 0
        self.scanned_ips = 0
        self.alive_ips = []

        threading.Thread(target=self.prepare_scan, daemon=True).start()

    def prepare_scan(self):
        ips = self.parse_ip_range(self.entry_target.get())
        self.total_ips = len(ips)
        self.progress_label.configure(text=f"Checking {self.total_ips} IPs...")

        ip_queue = queue.Queue()
        for ip in ips:
            ip_queue.put(ip)

        threads = []
        for _ in range(int(self.thread_selector.get())):
            t = threading.Thread(target=self.ip_check_worker, args=(ip_queue,))
            t.start()
            threads.append(t)

        ip_queue.join()
        self.checking_ips = False

        if self.task_running:
            self.start_port_scan()

    def start_port_scan(self):
        start_port, end_port = map(int, self.entry_ports.get().split('-'))
        ports = range(start_port, end_port + 1)
        self.total_tasks = len(self.alive_ips) * len(ports)
        self.progress_label.configure(text=f"Scanning {self.total_tasks} ports...")

        for ip in self.alive_ips:
            for port in ports:
                self.q.put((ip, port))

        for _ in range(int(self.thread_selector.get())):
            threading.Thread(target=self.worker, daemon=True).start()

    def update_gui(self):
        while not self.gui_queue.empty():
            task = self.gui_queue.get_nowait()
            
            if task[0] == "progress":
                progress_value = 0
                if self.checking_ips:
                    progress_value = (self.scanned_ips / self.total_ips) * 100
                    status_text = f"Checked {self.scanned_ips}/{self.total_ips} IPs"
                else:
                    progress_value = (self.scanned_tasks / self.total_tasks) * 100
                    status_text = f"Scanned {self.scanned_tasks}/{self.total_tasks} ports"
                
                self.progress["value"] = progress_value
                self.progress_label.configure(text=status_text)
            
            elif task[0] == "start":
                ip, port = task[1], task[2]
                self.tree.insert("", "end", values=(ip, port, "Scanning"))
            
            elif task[0] == "end":
                ip, port, success = task[1], task[2], task[3]
                for item in self.tree.get_children():
                    if self.tree.item(item)["values"][0] == ip and self.tree.item(item)["values"][1] == port:
                        self.tree.delete(item)
                if success:
                    if ip not in self.open_ports:
                        self.open_ports[ip] = []
                    if port not in self.open_ports[ip]:
                        self.open_ports[ip].append(port)
                        for item in self.open_ports_tree.get_children():
                            if self.open_ports_tree.item(item)["values"][0] == ip:
                                self.open_ports_tree.delete(item)
                        self.open_ports_tree.insert("", "end", values=(ip, ", ".join(map(str, sorted(self.open_ports[ip])))))

        self.after(100, self.update_gui)

    def stop_scan(self):
        self.task_running = False
        self.checking_ips = False
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.progress_label.configure(text="Scan Stopped")
        self.q.queue.clear()

    def export_results(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file:
            try:
                with open(file, "w") as f:
                    f.write(self.text_area.get("1.0", "end"))
                messagebox.showinfo("Success", "Results exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

if __name__ == "__main__":
    app = PortScanner()
    app.mainloop()