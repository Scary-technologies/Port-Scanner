import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import time
import os
import ipaddress
from tkinter.ttk import Combobox

# تنظیمات اولیه GUI
root = tk.Tk()
root.title("Professional Port Scanner v2.1")
root.geometry("800x650")
root.resizable(True, True)
root.configure(bg="#1E1E1E")

# استایل مدرن
style = ttk.Style()
style.theme_use('clam')

# پالت رنگی
colors = {
    "background": "#1E1E1E",
    "primary": "#2A2F3D",
    "secondary": "#4ECCA3",
    "text": "#FFFFFF",
    "warning": "#FF6B6B"
}

style.configure("TFrame", background=colors["background"])
style.configure("TLabel", background=colors["background"], foreground=colors["text"], font=("Segoe UI", 10))
style.configure("TButton", background=colors["secondary"], foreground=colors["text"], 
                font=("Segoe UI", 10, "bold"), borderwidth=0)
style.map("TButton", background=[("active", "#3DAF8A")])
style.configure("TEntry", fieldbackground=colors["primary"], foreground=colors["text"], 
                font=("Segoe UI", 10), borderwidth=1)
style.configure("TCombobox", fieldbackground=colors["primary"], foreground=colors["text"])
style.configure("Vertical.TScrollbar", background=colors["primary"], bordercolor=colors["secondary"])
style.configure("Horizontal.TProgressbar", background=colors["secondary"], troughcolor=colors["primary"])

# قاب اصلی
main_frame = ttk.Frame(root)
main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

# بخش ورودی اطلاعات
input_frame = ttk.Frame(main_frame)
input_frame.pack(fill=tk.X, pady=10)

ttk.Label(input_frame, text="Target Host:").grid(row=0, column=0, padx=5, sticky=tk.W)
entry_target = ttk.Entry(input_frame, width=40)
entry_target.grid(row=0, column=1, padx=5)

ttk.Label(input_frame, text="Port Range (e.g., 1-1024):").grid(row=1, column=0, padx=5, sticky=tk.W)
entry_ports = ttk.Entry(input_frame, width=40)
entry_ports.grid(row=1, column=1, padx=5)

ttk.Label(input_frame, text="Threads:").grid(row=2, column=0, padx=5, sticky=tk.W)
thread_selector = Combobox(input_frame, values=[str(i) for i in [50, 100, 200, 500]], width=10)
thread_selector.set("100")
thread_selector.grid(row=2, column=1, padx=5, sticky=tk.W)

# بخش پیشرفته
advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Options")
advanced_frame.pack(fill=tk.X, pady=10)

preset_ports_var = tk.StringVar()
preset_ports = ttk.Combobox(advanced_frame, textvariable=preset_ports_var, 
                           values=["Common Ports", "Web Servers", "Game Servers", "Full Scan"],
                           width=15)
preset_ports.set("Common Ports")
preset_ports.pack(side=tk.LEFT, padx=5)

timeout_var = tk.StringVar()
ttk.Label(advanced_frame, text="Timeout (s):").pack(side=tk.LEFT, padx=5)
timeout_entry = ttk.Entry(advanced_frame, textvariable=timeout_var, width=5)
timeout_entry.pack(side=tk.LEFT, padx=5)
timeout_var.set("1")

# نمایش نتایج
results_frame = ttk.Frame(main_frame)
results_frame.pack(fill=tk.BOTH, expand=True)

text_area = scrolledtext.ScrolledText(results_frame, width=85, height=15, 
                                     font=("Consolas", 9), bg=colors["primary"], fg=colors["text"])
text_area.pack(fill=tk.BOTH, expand=True)

# نوار وضعیت و پیشرفت
status_frame = ttk.Frame(main_frame)
status_frame.pack(fill=tk.X, pady=10)

progress_label = ttk.Label(status_frame, text="Ready", foreground=colors["secondary"])
progress_label.pack(side=tk.LEFT)

progress = ttk.Progressbar(status_frame, length=300, mode="determinate", style="Horizontal.TProgressbar")
progress.pack(side=tk.RIGHT)

# توابع اصلی
def validate_input():
    try:
        target = entry_target.get()
        ipaddress.ip_address(target)
    except ValueError:
        try:
            socket.gethostbyname(target)
        except:
            messagebox.showerror("Error", "Invalid target address")
            return False
    
    try:
        start_port, end_port = map(int, entry_ports.get().split('-'))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError
    except:
        messagebox.showerror("Error", "Invalid port range")
        return False
    
    return True

def update_preset_ports(event=None):
    presets = {
        "Common Ports": "20-1024",
        "Web Servers": "80-443",
        "Game Servers": "25565-27015",
        "Full Scan": "1-65535"
    }
    entry_ports.delete(0, tk.END)
    entry_ports.insert(0, presets[preset_ports.get()])

def scan_port(target, port):
    global scanned_ports
    if not task_running:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout_var.get()))
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    service_name = socket.getservbyport(port, 'tcp')
                except:
                    service_name = "unknown"
                result_text = f"[+] Port {port} ({service_name}) is open\n"
            else:
                result_text = ""
    except Exception as e:
        result_text = f"[!] Error scanning port {port}: {str(e)}\n"
    
    if result_text:
        text_area.insert(tk.END, result_text)
        text_area.see(tk.END)
    scanned_ports += 1
    progress['value'] = (scanned_ports / total_ports) * 100
    root.update_idletasks()

def worker():
    while task_running and not queue_ports.empty():
        port = queue_ports.get()
        scan_port(entry_target.get(), port)
        queue_ports.task_done()

def start_scan_thread():
    global task_running, scanned_ports, total_ports
    if not validate_input():
        return
    
    task_running = True
    scanned_ports = 0
    start_time = time.time()
    
    text_area.delete('1.0', tk.END)
    btn_scan.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    progress['value'] = 0
    
    start_port, end_port = map(int, entry_ports.get().split('-'))
    total_ports = end_port - start_port + 1
    progress_label.config(text=f"Scanning {total_ports} ports...")
    
    for port in range(start_port, end_port + 1):
        queue_ports.put(port)
    
    num_threads = min(int(thread_selector.get()), 500)
    for _ in range(num_threads):
        threading.Thread(target=worker, daemon=True).start()
    
    monitor_thread = threading.Thread(target=monitor_progress, args=(start_time,))
    monitor_thread.start()

def monitor_progress(start_time):
    while task_running:
        elapsed_time = time.time() - start_time
        progress_label.config(text=f"Scanned {scanned_ports}/{total_ports} ports - "
                              f"Elapsed: {elapsed_time:.1f}s")
        time.sleep(0.1)
    progress_label.config(text=f"Completed in {time.time() - start_time:.1f} seconds")

def stop_scan():
    global task_running
    task_running = False
    btn_scan.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    progress_label.config(text="Scan Stopped")

def export_results():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    if file_path:
        with open(file_path, "w") as f:
            f.write(text_area.get('1.0', tk.END))
        messagebox.showinfo("Export Successful", f"Results saved to:\n{file_path}")

# دکمه‌های کنترل
control_frame = ttk.Frame(main_frame)
control_frame.pack(fill=tk.X, pady=10)

btn_scan = ttk.Button(control_frame, text="Start Scan", command=start_scan_thread)
btn_scan.pack(side=tk.LEFT, padx=5)

btn_stop = ttk.Button(control_frame, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
btn_stop.pack(side=tk.LEFT, padx=5)

btn_export = ttk.Button(control_frame, text="Export Results", command=export_results)
btn_export.pack(side=tk.RIGHT, padx=5)

# مقداردهی اولیه
preset_ports.bind("<<ComboboxSelected>>", update_preset_ports)
update_preset_ports()
queue_ports = queue.Queue()
task_running = False
scanned_ports = 0
total_ports = 0

root.mainloop()