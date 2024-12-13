import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import random
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

"""
    @Author: xponch0x
    @Description: [R.I.N.G.O.] Basic Command Intrusion Response System {SIM}
    [Defensive Network Security Final Project]
"""

root = tk.Tk()
conn = None
cursor = None
simulation_log = None
defcon_var = None
defcon_label = None
start_button = None
stop_button = None
techniques_list = None
event_logs = None
name_var = None
description_var = None
severity_var = None
response_var = None
technique_var = None

ascii_title = """

.______         __     .__   __.     __       _______      ______       
|   _  \       |  |    |  \ |  |    |  |     /  _____|    /  __  \      
|  |_)  |      |  |    |   \|  |    |  |    |  |  __     |  |  |  |     
|      /       |  |    |  . `  |    |  |    |  | |_ |    |  |  |  |     
|  |\  \----.__|  |  __|  |\   |  __|  |  __|  |__| |  __|  `--'  |  __ 
| _| `._____(__)__| (__)__| \__| (__)__| (__)\______| (__)\______/  (__)

"""

def init_database():
    global conn, cursor
    conn = sqlite3.connect("command_response.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intrusion_command_techniques (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        description TEXT,
        severity TEXT,
        response TEXT             
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intrusion_command_events (
        id INTEGER PRIMARY KEY,
        timestamp DATETIME,
        source_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        response TEXT,
        is_active BOOLEAN                
        )
    """)
    
    prepopulate_techniques()

def prepopulate_techniques():
    global conn, cursor
    predefined = [
        {
            "name": "MALWARE INJECTION",
            "description": "INSERTING MALICIOUS CODE INTO A SYSTEM",
            "severity": "HIGH",
            "response": "ISOLATE SYSTEM, RUN FULL VIRUS SCAN, BLOCK SOURCE IP"
        },
        {
            "name": "PASSWORD BRUTE FORCE",
            "description": "ATTEMPTING MULTIPLE PASSWORDS TO GAIN ACCESS TO THE SYSTEM",
            "severity": "CRITICAL",
            "response": "TEMPORARILY LOCK ACCOUNT, IMPLEMENT IP BLOCK, RESET CREDENTIALS"
        },
        {
            "name": "NETWORK SCANNING",
            "description": "PROBING A NETWORK TO FIND POTENTIAL VULNERABILITIES",
            "severity": "LOW",
            "response": "LOG AND MONITOR SOURCE IP, UPDATE FIREWALL RULES"
        }
    ]
    
    for x in predefined:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO intrusion_command_techniques
               (name, description, severity, response)
               VALUES (?, ?, ?, ?)
            """, (x["name"], x["description"], x["severity"], x["response"]))
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()

def create_simulation_ui(parent):
    global defcon_label, start_button, stop_button, simulation_log, technique_var
    parent.configure(bg="#C0C0C0")
      
    parent.grid_rowconfigure(0, weight=0)
    parent.grid_rowconfigure(1, weight=0)
    parent.grid_rowconfigure(2, weight=0)
    parent.grid_rowconfigure(3, weight=0)
    parent.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(parent, text="NETWORK INTRUSION SIMULATOR", font=("Comic Sans MS", 16, "bold"), bg="#C0C0C0", fg="navy", anchor="center")
    title_label.grid(row=0, column=0,pady=10, sticky="ew")
    
    defcon_label = tk.Label(parent, textvariable=defcon_var, font=("Courier", 12, "bold"), bg="#C0C0C0", fg="green", anchor="center")
    defcon_label.grid(row=1, column=0, pady=10, sticky="ew")

    control_frame = tk.Frame(parent, bg="#C0C0C0")
    control_frame.grid(row=2, column=0, pady=10, sticky="ew")
    control_frame.grid_columnconfigure(0, weight=1)
    control_frame.grid_columnconfigure(1, weight=1)
    
    technique_label = tk.Label(control_frame, text="SELECT TECHNIQUE:", font=("MS Sans Serif", 10), bg="#C0C0C0")
    technique_label.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
    
    technique_var = tk.StringVar()
    techniques = get_technique_names()
    technique_dropdown = ttk.Combobox(control_frame, textvariable=technique_var, values=techniques, width=30, state="readonly", font=("MS Sans Serif", 10))
    technique_dropdown.grid(row=1, column=0, padx=5, pady=5)

    start_button = tk.Button(control_frame, text="START SIMULATION", command=start_simulation, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    start_button.grid(row=2, column=0, padx=5, pady=5)

    stop_button = tk.Button(control_frame, text="STOP SIMULATION", command=stop_simulation, state=tk.DISABLED, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    stop_button.grid(row=2, column=1, padx=5, pady=5)

    close_button = tk.Button(parent, text="CLOSE", command=root.quit, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2, bg="red", fg="white")
    close_button.grid(row=3, column=0, pady=10)

    simulation_log = tk.Text(parent, height=15, width=50, wrap=tk.WORD, font=("Courier", 10), bg="white", fg="black")
    simulation_log.grid(row=4, column=0, pady=10, padx=10, sticky="nsew")
    simulation_log.config(state=tk.DISABLED)

def create_technique_management_ui(parent):
    global name_var, description_var, severity_var, response_var, techniques_list
    parent.configure(bg="#C0C0C0")

    parent.grid_rowconfigure(0, weight=0)
    parent.grid_rowconfigure(1, weight=0)
    parent.grid_rowconfigure(2, weight=0)
    parent.grid_rowconfigure(3, weight=1)
    parent.grid_columnconfigure(0, weight=1)
      
    title_label = tk.Label(parent, text="INTRUSION TECHNIQUE MANAGEMENT", font=("Comic Sans MS", 16, "bold"), bg="#C0C0C0", fg="navy")
    title_label.grid(row=1, column=0, pady=10, sticky="ew")

    input_frame = tk.Frame(parent, bg="#C0C0C0")
    input_frame.grid(row=1, column=0, pady=10, sticky="ew")
      
    input_frame.grid_columnconfigure(0, weight=1)
    input_frame.grid_columnconfigure(1, weight=3)

    name_var = tk.StringVar(value="")
    description_var = tk.StringVar(value="")
    severity_var = tk.StringVar(value="LOW")
    response_var = tk.StringVar(value="")

    labels = ["TECHNIQUE NAME:", "DESCRIPTION:", "SEVERITY:", "RESPONSE:"]
    variables = [name_var, description_var, severity_var, response_var]
    
    for i, (label_text, var) in enumerate(zip(labels, variables)):
        label = tk.Label(input_frame, text=label_text, font=("MS Sans Serif", 10), bg='#C0C0C0')
        label.grid(row=i, column=0, padx=5, pady=5, sticky='e')
        
        if label_text == "SEVERITY:":
            severity_options = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            entry = ttk.Combobox(input_frame, textvariable=var, values=severity_options, 
                                 width=27, state="readonly", font=("MS Sans Serif", 10))
        else:
            entry = tk.Entry(input_frame, width=30, textvariable=var, font=("MS Sans Serif", 10))
        
        entry.grid(row=i, column=1, padx=5, pady=5, sticky="ew")

    add_button = tk.Button(parent, text="ADD TECHNIQUE", command=add_technique, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    add_button.grid(row=2, column=0, pady=10)

    techniques_list = tk.Text(parent, width=100, height=15, wrap=tk.WORD, font=("Courier", 10), bg="white", fg="black")
    techniques_list.grid(row=3, column=0, pady=10, sticky="nsew")

    close_button = tk.Button(parent, text="CLOSE", command=root.quit, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2, bg="red", fg="white")
    close_button.grid(row=4, column=0, pady=10)

    refresh()

def create_network_visual_ui(parent):
    parent.configure(bg="#C0C0C0")

    parent.grid_rowconfigure(0, weight=0)
    parent.grid_rowconfigure(1, weight=0)
    parent.grid_rowconfigure(2, weight=1)
    parent.grid_rowconfigure(3, weight=0)
    parent.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(parent, text="NETWORK TOPOLOGY ANALYZER", font=("Comic Sans MS", 16, "bold"), bg="#C0C0C0", fg="navy")
    title_label.grid(row=0, column=0, pady=10, sticky="ew")

    control_frame = tk.Frame(parent, bg="#C0C0C0")
    control_frame.grid(row=1, column=0, pady=10, sticky="ew")
    control_frame.grid_columnconfigure(0, weight=1)

    visual_frame = tk.Frame(parent, bg="#C0C0C0")
    visual_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
    visual_frame.grid_rowconfigure(0, weight=1)
    visual_frame.grid_columnconfigure(0, weight=1)

    log_display = tk.Text(parent, height=8, width=30, wrap=tk.WORD, font=("Courier", 10), bg="white", fg="black")
    log_display.grid(row=3, column=0, pady=10)

    generate_btn = tk.Button(control_frame, text="GENERATE NETWORK", command=lambda: generate_network_topology(visual_frame, log_display), font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    generate_btn.grid(row=0, column=0, pady=10)

    close_button = tk.Button(parent, text="CLOSE", command=root.quit, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2, bg="red", fg="white")
    close_button.grid(row=4, column=0, pady=10)

def generate_network_topology(visual_frame, log_display):
    for widget in visual_frame.winfo_children():
        widget.destroy()

    log_display.config(state=tk.NORMAL)
    log_display.delete(1.0, tk.END)

    graph = nx.barabasi_albert_graph(n=15, m=2)

    fig, ax = plt.subplots(figsize=(4, 2), facecolor="#C0C0C0")
    ax.set_facecolor("#C0C0C0")

    pos = nx.spring_layout(graph, seed=42)

    node_colors = ["blue", "green", "red", "yellow"]
    colors = [random.choice(node_colors) for _ in graph.nodes()]
      
    nx.draw_networkx_nodes(graph, pos, node_color=colors, node_size=200, ax=ax)
    nx.draw_networkx_edges(graph, pos, alpha=0.5, ax=ax)
    nx.draw_networkx_labels(graph, pos, ax=ax)
      
    ax.set_title("NETWORK TOPOLOGY", fontsize=10)
    ax.axis("off")

    canvas = FigureCanvasTkAgg(fig, master=visual_frame)
    canvas_widget = canvas.get_tk_widget()
    canvas_widget.grid(row=0, column=0, sticky="nsew")
    visual_frame.grid_rowconfigure(0, weight=1)
    visual_frame.grid_columnconfigure(0, weight=1)

    log_display.insert(tk.END, f"[NETWORK ANALYSIS]\n")
    log_display.insert(tk.END, f"TOTAL NODES: {len(graph.nodes())}\n")
    log_display.insert(tk.END, f"TOTAL CONNECTIONS: {len(graph.edges())}\n")
    log_display.config(state=tk.DISABLED)

def create_event_log_ui(parent):
    global event_logs
    parent.configure(bg="#C0C0C0")

    parent.grid_rowconfigure(0, weight=0)
    parent.grid_rowconfigure(1, weight=1)
    parent.grid_rowconfigure(2, weight=0)
    parent.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(parent, text="INTRUSION EVENT LOGS", font=("Comic Sans MS", 16, "bold"), bg="#C0C0C0", fg="navy")
    title_label.grid(row=0, column=0, pady=10, sticky="ew")

    event_logs = tk.Text(parent, width=100, height=30, wrap=tk.WORD, font=("Courier", 10), bg="white", fg="black")
    event_logs.grid(row=1, column=0, pady=10, sticky="nsew")
    event_logs.config(state=tk.DISABLED)

    button_frame = tk.Frame(parent, bg="#C0C0C0")
    button_frame.grid(row=2, column=0, pady=10)

    refresh_button = tk.Button(button_frame, text="REFRESH LOGS", command=refresh_event_logs, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    refresh_button.pack(side=tk.LEFT, padx=5)

    export_button = tk.Button(button_frame, text="EXPORT LOGS", command=export_event_logs, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2)
    export_button.pack(side=tk.LEFT, padx=5)

    close_button = tk.Button(parent, text="CLOSE", command=root.quit, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2, bg="red", fg="white")
    close_button.grid(row=3, column=0, pady=10)

    refresh_event_logs()
    
def create_about_ui(parent):
    parent.configure(bg="#C0C0C0")

    parent.grid_rowconfigure(0, weight=0)
    parent.grid_rowconfigure(1, weight=0)
    parent.grid_rowconfigure(2, weight=0)
    parent.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(parent, text="ABOUT STUDENT PROJECT", font=("Comic Sans MS", 16, "bold"), bg="#C0C0C0", fg="navy")
    title_label.grid(row=0, column=0, pady=10, sticky="ew")

    about_text = tk.Text(parent, width=70, height=15, wrap=tk.WORD, font=("Courier", 10), bg="white", fg="black", borderwidth=2, relief=tk.SUNKEN)
    about_text.grid(row=1, column=0, pady=10, padx=10, sticky="nsew")
    about_text.tag_configure("title", font=("Courier", 12, "bold"))
    about_text.tag_configure("section", font=("Courier", 10, "bold"))

    about_text.config(state=tk.NORMAL)
    about_text.insert(tk.END, "R.I.N.G.O.\n", "title")
    about_text.insert(tk.END, "\nVERSION: [1.0.0]\n", "section")
    about_text.insert(tk.END, "DEVELOPED: [2024]\n\n")
      
    about_text.insert(tk.END, "DISCLAIMER:\n", "section")
    about_text.insert(tk.END, "[THIS SOFTWARE IS FOR EDUCATIONAL PURPOSES AND DEMONSTRATION ONLY]")
    
    about_text.config(state=tk.DISABLED)

    close_button = tk.Button(parent, text="CLOSE:", command=root.quit, font=("MS Sans Serif", 10), relief=tk.RAISED, borderwidth=2, bg="red", fg="white")
    close_button.grid(row=2, column=0, pady=10)

def add_technique():
    global conn, cursor, name_var, description_var, severity_var, response_var
    name = name_var.get().strip().upper()
    description = description_var.get().strip().upper()
    severity = severity_var.get().strip().upper()
    response = response_var.get().strip().upper()
    
    if not all([name, description, severity, response]):
        messagebox.showerror("[ERROR]", "PLEASE FILL IN ALL FIELDS")
        return
    
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO intrusion_command_techniques
            (name, description, severity, response)
            VALUES (?, ?, ?, ?)
        """, (name, description, severity, response))
        conn.commit()
        
        name_var.set("")
        description_var.set("")
        severity_var.set("LOW")
        response_var.set("")

        techniques = get_technique_names()
        notebook = root.winfo_children()[1]
        simulation_frame = notebook.winfo_children()[0]
         
        for widget in simulation_frame.winfo_children():
            if isinstance(widget, tk.Frame):
               for subwidget in widget.winfo_children():
                  if isinstance(subwidget, ttk.Combobox):
                    subwidget["values"] = techniques
                    break
         
        refresh()
         
        messagebox.showinfo("[SUCCESS]", "SUCCESSFULLY ADDED TECHNIQUE")
    except sqlite3.IntegrityError:
        messagebox.showerror("[ERROR]", "ERROR ADDING TECHNIQUE")

def refresh():
    global techniques_list, cursor
    techniques_list.config(state=tk.NORMAL)
    techniques_list.delete(1.0, tk.END)
    cursor.execute("SELECT name, description, severity, response FROM intrusion_command_techniques")
    intrusion_command_techniques = cursor.fetchall()

    for name, description, severity, response in intrusion_command_techniques:
        techniques_list.insert(tk.END, f"{name} [{severity}]: {description} | Response: {response}\n\n")
      
    techniques_list.config(state=tk.DISABLED)

def refresh_event_logs():
    global event_logs, cursor
    event_logs.config(state=tk.NORMAL)
    event_logs.delete(1.0, tk.END)
      
    cursor.execute("""
        SELECT timestamp, source_ip, attack_type, severity, response, is_active 
        FROM intrusion_command_events 
        ORDER BY timestamp DESC
    """)
    events = cursor.fetchall()
      
    if not events:
        event_logs.insert(tk.END, "NO EVENT LOGS FOUND\n")
    else:
        for event in events:
            active_status = "ACTIVE" if event[5] else "NEUTRALIZED"
            log_entry = (f"TIMESTAMP: {event[0]}\n"
                         f"SOURCE IP: {event[1]}\n"
                         f"ATTACK TYPE: {event[2]}\n"
                         f"SEVERITY: {event[3]}\n"
                         f"RESPONSE: {event[4]}\n"
                         f"STATUS: {active_status}\n\n")
            event_logs.insert(tk.END, log_entry)
      
    event_logs.config(state=tk.DISABLED)

def export_event_logs():
    global cursor
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="EXPORT EVENT LOGS"
    )
    
    if file_path:
        try:
            cursor.execute("""
                SELECT timestamp, source_ip, attack_type, severity, response, is_active 
                FROM intrusion_command_events 
                ORDER BY timestamp DESC
            """)
            events = cursor.fetchall()
            
            with open(file_path, "w") as file:
                if not events:
                    file.write("NO EVENT LOGS FOUND\n")
                else:
                    for event in events:
                        active_status = "ACTIVE" if event[5] else "NEUTRALIZED"
                        log_entry = (f"TIMESTAMP: {event[0]}\n"
                                   f"SOURCE IP: {event[1]}\n"
                                   f"ATTACK TYPE: {event[2]}\n"
                                   f"SEVERITY: {event[3]}\n"
                                   f"RESPONSE: {event[4]}\n"
                                   f"STATUS: {active_status}\n\n")
                        file.write(log_entry)
            
            messagebox.showinfo("SUCCESS", "EXPORT SUCCESSFUL")
        except Exception as e:
            messagebox.showerror("ERROR", f"EXPORT FAILED: {str(e)}")

def generate_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def get_technique_names():
    global cursor
    cursor.execute("SELECT name FROM intrusion_command_techniques")
    return [technique[0] for technique in cursor.fetchall()]

def start_simulation():
    global technique_var, cursor, conn, simulation_log, defcon_var, defcon_label, start_button, stop_button
    technique = technique_var.get()

    if not technique:
        messagebox.showerror("[ERROR]", "SELECT A TECHNIQUE TO SIMULATE")
        return

    cursor.execute("""
        SELECT severity, response
        FROM intrusion_command_techniques
        WHERE name = ?
    """, (technique,))
    result = cursor.fetchone()
    severity, response = result if result else ("UNKOWN", "NO RESPONSE DEFINED")
      
    if severity == "LOW":
        defcon_level = "[DEFCON 4] ELEVATED THREAT"
        defcon_color = "green"
    elif severity == 'MEDIUM':
        defcon_level = "[DEFCON 3] INCREASED READINESS"
        defcon_color = "yellow"
    elif severity == "HIGH":
        defcon_level = "[DEFCON 2] FURTHER ESCALATION"
        defcon_color = "red"
    elif severity == "CRITICAL":
        defcon_level = "[DEFCON 1] MAXIMUM ALERT"
        defcon_color = "white"
    else:
        defcon_level = "[DEFCON 5] ALL SYSTEMS ARE ONLINE AND IN STANDBY"
        defcon_color = "blue"
    
    alert_message = (
        f"THREAT DETECTED!\n\n"
        f"TYPE: {technique}\n"
        f"SEVERITY: {severity}\n"
        f"RECOMMENDED RESPONSE: {response}\n\n"
        "ELIMINATE THREAT?"
    )
    
    simulation_log.config(state=tk.NORMAL)
    simulation_log.delete(1.0, tk.END)
    
    simulation_log.insert(tk.END, f"STARTING SIMULATION: {technique}\n")
    simulation_log.insert(tk.END, f"TIMESTAMP: {datetime.now()}\n")

    source_ip = generate_ip()
    simulation_log.insert(tk.END, f"SOURCE IP: {source_ip}\n")

    simulation_log.insert(tk.END, f"SEVERITY: [{severity}]\n")
    simulation_log.insert(tk.END, f"RESPONSE: {response}\n")
      
    threat_response = custom_messagebox(defcon_level, alert_message, "question")

    cursor.execute("""
        SELECT severity, response 
        FROM intrusion_command_techniques 
        WHERE name = ?
    """, (technique,))
    result = cursor.fetchone()
    severity, response = result if result else ("UNKNOWN", "NO RESPONSE DEFINED")
    
    try:
        if threat_response:
            simulation_log.insert(tk.END, "THREAT STATUS: NEUTRALIZED\n")
            messagebox.showinfo(
                "[DEFCON 5] THREAT ELIMINATED",
                "THREAT HAS BEEN ELIMINATED\n"
                "ALL ISSUES RESOLVED")

            cursor.execute("""
               INSERT INTO intrusion_command_events
               (timestamp, source_ip, attack_type, severity, response, is_active)
               VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now(), source_ip, technique, severity, "HANDLED", False))
            conn.commit()
            
            defcon_var.set("[DEFCON 5] ALL SYSTEMS ARE ONLINE AND IN STANDBY")
            defcon_label.config(fg="blue")
        else:
            are_you_positive = ("ARE YOU SURE YOU DONT WANT TO ACT?\n\n"
                                "[YES: THREAT STAYS ACTIVE] | [NO: THREAT IS NEUTRALIZED]\n")
            
            confirm_nonreact = custom_messagebox(defcon_level, are_you_positive, "question")

            if not confirm_nonreact:
                simulation_log.insert(tk.END, "THREAT STATUS: NEUTRALIZED\n")
               
                messagebox.showinfo(
               "[DEFCON 5] THREAT ELIMINATED",
               "THREAT HAS BEEN ELIMINATED\n"
               "ALL ISSUES RESOLVED")

                cursor.execute("""
                    INSERT INTO intrusion_command_events
                    (timestamp, source_ip, attack_type, severity, response, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (datetime.now(), source_ip, technique, severity, "HANDLED", False))
                conn.commit()
               
                defcon_var.set("[DEFCON 5] ALL SYSTEMS ARE ONLINE AND IN STANDBY")
                defcon_label.config(fg="blue")
            else:
                simulation_log.insert(tk.END, "THREAT STATUS: ACTIVE\n")

                cursor.execute("""
                    INSERT INTO intrusion_command_events
                    (timestamp, source_ip, attack_type, severity, response, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (datetime.now(), source_ip, technique, severity, "IGNORED", True))
                conn.commit()
               
                defcon_var.set(defcon_level)
                defcon_label.config(fg=defcon_color)
    except sqlite3.Error as e:
        simulation_log.insert(tk.END, f"DATABASE ERROR: {str(e)}\n")
      
    simulation_log.config(state=tk.DISABLED)
      
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

def custom_messagebox(title, message, message_type="info"):
    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    root.configure(bg="SystemButtonFace")
    
    frame = tk.Frame(root, padx=20, pady=20)
    frame.pack(fill="both", expand=True)

    msg_label = tk.Label(frame, text=message, wraplength=400, justify=tk.CENTER, font=("Arial", 10))
    msg_label.pack(pady=10)
      
    if message_type == "question":
        def on_yes():
            root.result = True
            root.destroy()
        def on_no():
            root.result = False
            root.destroy()
         
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
         
        yes_btn = tk.Button(btn_frame, text="YES", command=on_yes, width=10)
        no_btn = tk.Button(btn_frame, text="NO", command=on_no, width=10)
         
        yes_btn.pack(padx=5)
        no_btn.pack(padx=5)

        root.wait_window(root)
        return root.result

def stop_simulation():
    global defcon_var, defcon_label, simulation_log, start_button, stop_button
    defcon_var.set("[DEFCON 5] ALL SYSTEMS ARE ONLINE AND IN STANDBY")
    defcon_label.config(fg="blue")
      
    simulation_log.config(state=tk.NORMAL)
    simulation_log.insert(tk.END, f"SIMULATION STOPPED: {datetime.now()}\n\n")
    simulation_log.config(state=tk.DISABLED)
      
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    
def init_ui():
    global defcon_var, root
    root.title("Command Intrusion Response System")
    root.geometry("1024x800")
    root.configure(bg="#C0C0C0", relief=tk.RAISED, borderwidth=4)
    defcon_var = tk.StringVar(value="[DEFCON 5] ALL SYSTEMS ARE ONLINE AND IN STANDBY")
    
    title_label = tk.Label(root, text=ascii_title, font=("Courier", 10, "bold"), fg="green", bg="#C0C0C0")
    title_label.pack(pady=10)
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    
    notebook = ttk.Notebook(root, style="TNotebook")
    notebook.pack(expand=True, fill="both", padx=10, pady=10)
    
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background="#C0C0C0", borderwidth=2, relief="raised")
    style.configure("TNotebook.Tab", background="#C0C0C0", foreground="black", font=("MS Sans Serif", 10), padding=[10, 5])
    style.map("TNotebook.Tab", background=[("selected", "white")], expand=[("selected", [1, 1, 1, 1])])
    
    simulation_frame = tk.Frame(notebook, bg="#C0C0C0", relief=tk.RIDGE, borderwidth=2)
    notebook.add(simulation_frame, text="SIMULATION")
    simulation_frame.grid_rowconfigure(0, weight=1)
    simulation_frame.grid_columnconfigure(0, weight=1)
    
    technique_management_frame = tk.Frame(notebook, bg="#C0C0C0", relief=tk.RIDGE, borderwidth=2)
    notebook.add(technique_management_frame, text="TECHNIQUE MANAGEMENT")
    technique_management_frame.grid_rowconfigure(0, weight=1)
    technique_management_frame.grid_columnconfigure(0, weight=1)

    network_frame = tk.Frame(notebook, bg="#C0C0C0", relief=tk.RIDGE, borderwidth=2)
    notebook.add(network_frame, text="NETWORK VISUAL")
    network_frame.grid_rowconfigure(0, weight=1)
    network_frame.grid_columnconfigure(0, weight=1)
    
    event_log_frame = tk.Frame(notebook, bg="#C0C0C0", relief=tk.RIDGE, borderwidth=2)
    notebook.add(event_log_frame, text="EVENT LOGS")
    event_log_frame.grid_rowconfigure(0, weight=1)
    event_log_frame.grid_columnconfigure(0, weight=1)
      
    about_frame = tk.Frame(notebook, bg="#C0C0C0", relief=tk.RIDGE, borderwidth=2)
    notebook.add(about_frame, text="ABOUT")
    about_frame.grid_rowconfigure(0, weight=1)
    about_frame.grid_columnconfigure(0, weight=1)
      
    create_simulation_ui(simulation_frame)
    create_technique_management_ui(technique_management_frame)
    create_network_visual_ui(network_frame)
    create_event_log_ui(event_log_frame)
    create_about_ui(about_frame)

if __name__ == "__main__":
    init_database()
    init_ui()
    root.mainloop()