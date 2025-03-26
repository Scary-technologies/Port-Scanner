import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import time
import ipaddress

root = tk.Tk()
root.title("Port Scanner v3.0")
root.geometry("800x650")
root.configure(bg="#1E1E1E")

style = ttk.Style()
style.theme_use('clam')

colors = {
    "background": "#1E1E1E",
    "primary": "#2A2F3D",
    "secondary": "#4ECCA3",
    "text": "#FFFFFF"
}

style.configure("TFrame", background=colors["background"])
style.configure("TLabel", background=colors["background"], foreground=colors["text"], font=("Segoe UI", 10))
style.configure("TButton", background=colors["secondary"], foreground=colors["text"], font=("Segoe UI", 10, "bold"))
style.configure("TEntry", fieldbackground=colors["primary"], foreground=colors["text"])
style.configure("Treeview", background=colors["primary"], foreground=colors["text"], fieldbackground=colors["primary"])

main_frame = ttk.Frame(root)
main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

input_frame = ttk.Frame(main_frame)
input_frame.pack(fill=tk.X, pady=10)

ttk.Label(input_frame, text="Target IP/Range:").grid(row=0, column=0, padx=5, sticky=tk.W)
entry_target = ttk.Entry(input_frame, width=40)
entry_target.grid(row=0, column=1, padx=5)
entry_target.insert(0, "192.168.1.1-100")

ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, padx=5, sticky=tk.W)
entry_ports = ttk.Entry(input_frame, width=40)
entry_ports.grid(row=1, column=1, padx=5)

ttk.Label(input_frame, text="Threads:").grid(row=2, column=0, padx=5, sticky=tk.W)
thread_selector = ttk.Combobox(input_frame, values=["50", "100", "200", "500"], width=10)
thread_selector.set("100")
thread_selector.grid(row=2, column=1, padx=5, sticky=tk.W)

notebook = ttk.Notebook(main_frame)
notebook.pack(fill=tk.BOTH, expand=True)

log_tab = ttk.Frame(notebook)
text_area = scrolledtext.ScrolledText(log_tab, font=("Consolas", 9), bg=colors["primary"], fg=colors["text"])
text_area.pack(fill=tk.BOTH, expand=True)
notebook.add(log_tab, text="Logs")

status_tab = ttk.Frame(notebook)
tree = ttk.Treeview(status_tab, columns=("ip", "port", "status"), show="headings")
tree.heading("ip", text="IP Address")
tree.heading("port", text="Port")
tree.heading("status", text="Status")
tree.pack(fill=tk.BOTH, expand=True)
notebook.add(status_tab, text="Active Scans")

open_ports_tab = ttk.Frame(notebook)
open_ports_tree = ttk.Treeview(open_ports_tab, columns=("ip", "ports"), show="headings")
open_ports_tree.heading("ip", text="IP Address")
open_ports_tree.heading("ports", text="Open Ports")
open_ports_tree.pack(fill=tk.BOTH, expand=True)
notebook.add(open_ports_tab, text="Open Ports")

status_frame = ttk.Frame(main_frame)
status_frame.pack(fill=tk.X, pady=10)
progress_label = ttk.Label(status_frame, text="Ready", foreground=colors["secondary"])
progress_label.pack(side=tk.LEFT)
progress = ttk.Progressbar(status_frame, mode="determinate")
progress.pack(side=tk.RIGHT)

control_frame = ttk.Frame(main_frame)
control_frame.pack(fill=tk.X, pady=10)
btn_scan = ttk.Button(control_frame, text="Start Scan", command=lambda: start_scan_thread())
btn_scan.pack(side=tk.LEFT, padx=5)
btn_stop = ttk.Button(control_frame, text="Stop Scan", state=tk.DISABLED, command=lambda: stop_scan())
btn_stop.pack(side=tk.LEFT, padx=5)
btn_export = ttk.Button(control_frame, text="Export", command=lambda: export_results())
btn_export.pack(side=tk.RIGHT, padx=5)

task_running = False
scanned_tasks = 0
total_tasks = 0
active_scans = {}
open_ports = {}
gui_queue = queue.Queue()

def parse_ip_range(target):
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

def validate_input():
    ips = parse_ip_range(entry_target.get())
    if not ips:
        messagebox.showerror("Error", "Invalid IP Range")
        return False
    try:
        start, end = map(int, entry_ports.get().split('-'))
        if not 1 <= start <= end <= 65535:
            raise ValueError
    except:
        messagebox.showerror("Error", "Invalid Port Range")
        return False
    return True

def update_gui():
    while not gui_queue.empty():
        task = gui_queue.get_nowait()
        if task[0] == "start":
            ip, port = task[1], task[2]
            tree.insert("", "end", values=(ip, port, "Scanning"))
        elif task[0] == "end":
            ip, port, success = task[1], task[2], task[3]
            for item in tree.get_children():
                if tree.item(item)["values"][0] == ip and tree.item(item)["values"][1] == port:
                    tree.delete(item)
            if success:
                if ip not in open_ports:
                    open_ports[ip] = []
                if port not in open_ports[ip]:
                    open_ports[ip].append(port)
                    open_ports_tree.insert("", "end", values=(ip, ", ".join(map(str, sorted(open_ports[ip])))))
    root.after(100, update_gui)

def scan_port(ip, port):
    global scanned_tasks
    if not task_running:
        return
    gui_queue.put(("start", ip, port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(1))
        result = sock.connect_ex((ip, port))
        service = socket.getservbyport(port, 'tcp') if result == 0 else ""
        if result == 0:
            text_area.insert(tk.END, f"[+] {ip}:{port} ({service}) OPEN\n")
            gui_queue.put(("end", ip, port, True))
        else:
            gui_queue.put(("end", ip, port, False))
        sock.close()
    except Exception as e:
        text_area.insert(tk.END, f"[!] {ip}:{port} ERROR: {str(e)}\n")
        gui_queue.put(("end", ip, port, False))
    scanned_tasks += 1
    progress["value"] = (scanned_tasks / total_tasks) * 100

def worker():
    while task_running and not q.empty():
        ip, port = q.get()
        scan_port(ip, port)
        q.task_done()

def start_scan_thread():
    global task_running, scanned_tasks, total_tasks, q
    if not validate_input():
        return
    task_running = True
    scanned_tasks = 0
    progress["value"] = 0
    btn_scan.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    text_area.delete('1.0', tk.END)
    open_ports_tree.delete(*open_ports_tree.get_children())
    
    ips = parse_ip_range(entry_target.get())
    start_port, end_port = map(int, entry_ports.get().split('-'))
    ports = range(start_port, end_port + 1)
    total_tasks = len(ips) * len(ports)
    progress_label.config(text=f"Scanning {total_tasks} tasks...")
    
    q = queue.Queue()
    for ip in ips:
        for port in ports:
            q.put((ip, port))
    
    for _ in range(int(thread_selector.get())):
        threading.Thread(target=worker, daemon=True).start()
    
    update_gui()

def stop_scan():
    global task_running
    task_running = False
    btn_scan.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    progress_label.config(text="Scan Stopped")

def export_results():
    file = filedialog.asksaveasfilename(defaultextension="*.txt")
    if file:
        with open(file, "w") as f:
            f.write(text_area.get("1.0", tk.END))
        messagebox.showinfo("Success", "Results exported successfully")

root.mainloop()