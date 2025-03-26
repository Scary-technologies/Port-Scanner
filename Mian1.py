import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import ipaddress
import json
import time

class ProfessionalPortScanner:
    def __init__(self):
        self.ip_range = []
        self.port_range = []
        self.results = {}
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        self.lock = threading.Lock()

    def validate_inputs(self, ip_range, port_range):
        try:
            self.ip_range = list(ipaddress.ip_network(ip_range, strict=False).hosts())
            self.port_range = list(map(int, port_range.split('-')))
            return True
        except ValueError:
            return False

    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((str(ip), port))
                return result == 0
        except:
            return False

    def worker(self):
        while self.is_scanning:
            try:
                ip, port = self.scan_queue.get(timeout=0.5)
                if self.scan_port(ip, port):
                    with self.lock:
                        if ip not in self.results:
                            self.results[ip] = []
                        self.results[ip].append(port)
                self.scan_queue.task_done()
            except queue.Empty:
                continue

class ProfessionalGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Network Scanner v2.0")
        self.geometry("1200x800")
        self.scanner = ProfessionalPortScanner()
        self.setup_ui()
        self.setup_chart()
        self.setup_styles()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        self.configure(bg="#2d2d2d")
        style.configure("TFrame", background="#2d2d2d")
        style.configure("TLabel", background="#2d2d2d", foreground="#ffffff")
        style.configure("TButton", background="#4a90d9", foreground="#ffffff")
        style.configure("Treeview", background="#3d3d3d", fieldbackground="#3d3d3d", foreground="#ffffff")

    def setup_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Input Section
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="IP Range (CIDR):").grid(row=0, column=0, sticky='w')
        self.ip_entry = ttk.Entry(input_frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5)

        ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, sticky='w')
        self.port_entry = ttk.Entry(input_frame, width=30)
        self.port_entry.grid(row=1, column=1, padx=5)

        ttk.Label(input_frame, text="Threads:").grid(row=2, column=0, sticky='w')
        self.thread_combo = ttk.Combobox(input_frame, values=["50", "100", "200", "500"])
        self.thread_combo.current(1)
        self.thread_combo.grid(row=2, column=1, padx=5)

        # Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=10)

        self.start_btn = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Export Data", command=self.export_data).pack(side=tk.LEFT, padx=5)

        # Results Display
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.log_area = scrolledtext.ScrolledText(results_frame, width=90, height=15)
        self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(results_frame, columns=("IP", "Open Ports"), show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Open Ports", text="Open Ports")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def setup_chart(self):
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.ax.set_title("Open Ports Distribution")
        self.ax.set_xlabel("IP Addresses")
        self.ax.set_ylabel("Open Ports Count")

    def update_chart(self):
        self.ax.clear()
        ips = [str(ip) for ip in self.scanner.results.keys()]  # تبدیل IPv4Address به رشته
        counts = [len(ports) for ports in self.scanner.results.values()]
        if ips:
            self.ax.bar(ips, counts, color="#4a90d9")
            self.ax.tick_params(axis='x', rotation=45)
            self.canvas.draw()

    def start_scan(self):
        if not self.scanner.validate_inputs(self.ip_entry.get(), self.port_entry.get()):
            messagebox.showerror("Error", "Invalid input format! Please enter IP range in CIDR format and port range as 'start-end' (e.g., 20-80).")
            return
        self.scanner.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.scanner.results.clear()
        self.log_area.delete(1.0, tk.END)
        self.tree.delete(*self.tree.get_children())

        # Add IPs and ports to the scan queue
        for ip in self.scanner.ip_range:
            for port in range(self.scanner.port_range[0], self.scanner.port_range[1] + 1):
                self.scanner.scan_queue.put((ip, port))

        # Start worker threads
        num_threads = int(self.thread_combo.get())
        for _ in range(num_threads):
            threading.Thread(target=self.scanner.worker, daemon=True).start()

        # Start UI update thread
        threading.Thread(target=self.update_ui, daemon=True).start()

    def update_ui(self):
        while self.scanner.is_scanning or not self.scanner.scan_queue.empty():
            with self.scanner.lock:
                self.tree.delete(*self.tree.get_children())
                for ip, ports in self.scanner.results.items():
                    self.tree.insert("", "end", values=(str(ip), ", ".join(map(str, ports))))
                    self.log_area.insert(tk.END, f"Found open ports {ports} on {ip}\n")
                self.update_chart()
            time.sleep(0.5)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def stop_scan(self):
        self.scanner.is_scanning = False
        with self.scanner.lock:
            self.scanner.results.clear()

    def export_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                if file_path.endswith('.json'):
                    json.dump(self.scanner.results, f)
                else:
                    for ip, ports in self.scanner.results.items():
                        f.write(f"{ip}: {', '.join(map(str, ports))}\n")

if __name__ == "__main__":
    app = ProfessionalGUI()
    app.mainloop()