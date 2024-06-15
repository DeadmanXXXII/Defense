import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import *
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os

# Function to add tooltips to widgets
def add_tooltip(widget, text):
    tool_tip = ToolTip(widget)
    def enter(event):
        tool_tip.showtip(text)
    def leave(event):
        tool_tip.hidetip()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

class ToolTip:
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tipwindow = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

# EncryptionHandler class definition
class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    # Event handler for file creation
    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file deletion
    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file modification
    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Handle encryption for individual or group files
    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.encrypt_file(file_path)
        elif self.mode == "All":
            self.encrypt_all_files()

    # Determine if a file belongs to any of the specified groups
    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    # Encrypt a single file
    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

    # Placeholder method for encrypting all files in a directory
    def encrypt_all_files(self):
        # Implement logic to encrypt all files in self.directory
        pass

# DecryptionHandler class definition
class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    # Event handler for file creation
    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file deletion
    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Event handler for file modification
    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    # Handle decryption for individual or group files
    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.decrypt_file(file_path)
        elif self.mode == "All":
            self.decrypt_all_files()

    # Determine if a file belongs to any of the specified groups
    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    # Decrypt a single file
    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = self.fernet.decrypt(data)
        with open(file_path[:-len(".encrypted")], "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

    # Placeholder method for decrypting all files in a directory
    def decrypt_all_files(self):
        # Implement logic to decrypt all files in self.directory
        pass

# EncryptionApp class definition
class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Encryption")

        # Encryption GUI elements
        self.label1 = tk.Label(master, text="Select a directory to monitor:")
        self.label1.pack()
        add_tooltip(self.label1, "Choose the directory you want to monitor for encryption.")

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()
        add_tooltip(self.directory_button, "Click to select the directory to monitor.")

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()
        add_tooltip(self.label2, "Choose the encryption key file.")

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()
        add_tooltip(self.key_button, "Click to select the encryption key file.")

        self.label3 = tk.Label(master, text="Select trigger for encryption:")
        self.label3.pack()
        add_tooltip(self.label3, "Choose when to trigger the encryption process.")

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(master, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.pack()
        add_tooltip(self.encrypt_trigger_menu, "Select the trigger event for encryption (e.g., file creation, deletion, or modification).")

        self.label4 = tk.Label(master, text="Select encryption mode:")
        self.label4.pack()
        add_tooltip(self.label4, "Choose the encryption mode.")

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(master, self.encrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry)
        self.encrypt_mode_menu.pack()
        add_tooltip(self.encrypt_mode_menu, "Select the mode of encryption (e.g., Individual, Group, or All).")

        self.label5 = tk.Label(master, text="Enter group paths (comma-separated):")
        self.label5.pack()
        add_tooltip(self.label5, "Specify the group paths if the Group mode is selected.")

        self.group_paths_entry = tk.Entry(master, width=50)
        self.group_paths_entry.pack()
        self.group_paths_entry.config(state=tk.DISABLED)
        add_tooltip(self.group_paths_entry, "Enter the paths to be monitored in Group mode, separated by commas.")

        self.encrypt_label = tk.Label(master, text="Encryption Handler Status: Idle")
        self.encrypt_label.pack()
        add_tooltip(self.encrypt_label, "Shows the current status of the encryption handler.")

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()
        add_tooltip(self.start_button, "Click to start monitoring the selected directory for encryption.")

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack()
        add_tooltip(self.stop_button, "Click to stop monitoring.")

    # Method to toggle group paths entry
    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    # Method to select a directory
    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory: " + self.directory)

    # Method to select a key file
    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

    # Method to start monitoring
    def start_monitoring(self):
        if hasattr(self, 'directory') and hasattr(self, 'key_file'):
            groups = self.group_paths_entry.get().split(',') if self.encrypt_mode.get() == "Group" else None
            self.handler = EncryptionHandler(self.load_key(), self.encrypt_trigger.get(), self.encrypt_mode.get(), self.directory, groups)

            self.encrypt_observer = Observer()
            self.encrypt_observer.schedule(self.handler, self.directory, recursive=True)
            self.encrypt_observer.start()

            self.encrypt_label.config(text="Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory and a key file.")

    # Method to stop monitoring
    def stop_monitoring(self):
        if hasattr(self, 'encrypt_observer'):
            self.encrypt_observer.stop()
            self.encrypt_observer.join()

            self.encrypt_label.config(text="Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    # Method to load encryption key
    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

# DecryptionApp class definition
class DecryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Decryption")

        # Decryption GUI elements
        self.label1 = tk.Label(master, text="Select a directory to monitor:")
        self.label1.pack()
        add_tooltip(self.label1, "Choose the directory you want to monitor for decryption.")

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()
        add_tooltip(self.directory_button, "Click to select the directory to monitor.")

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()
        add_tooltip(self.label2, "Choose the decryption key file.")

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()
        add_tooltip(self.key_button, "Click to select the decryption key file.")

        self.label3 = tk.Label(master, text="Select trigger for decryption:")
        self.label3.pack()
        add_tooltip(self.label3, "Choose when to trigger the decryption process.")

        self.decrypt_trigger = tk.StringVar()
        self.decrypt_trigger.set("Create")
        self.decrypt_trigger_menu = tk.OptionMenu(master, self.decrypt_trigger, "Create", "Delete", "Modify")
        self.decrypt_trigger_menu.pack()
        add_tooltip(self.decrypt_trigger_menu, "Select the trigger event for decryption (e.g., file creation, deletion, or modification).")

        self.label4 = tk.Label(master, text="Select decryption mode:")
        self.label4.pack()
        add_tooltip(self.label4, "Choose the decryption mode.")

        self.decrypt_mode = tk.StringVar()
        self.decrypt_mode.set("Individual")
        self.decrypt_mode_menu = tk.OptionMenu(master, self.decrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry)
        self.decrypt_mode_menu.pack()
        add_tooltip(self.decrypt_mode_menu, "Select the mode of decryption (e.g., Individual, Group, or All).")

        self.label5 = tk.Label(master, text="Enter group paths (comma-separated):")
        self.label5.pack()
        add_tooltip(self.label5, "Specify the group paths if the Group mode is selected.")

        self.group_paths_entry = tk.Entry(master, width=50)
        self.group_paths_entry.pack()
        self.group_paths_entry.config(state=tk.DISABLED)
        add_tooltip(self.group_paths_entry, "Enter the paths to be monitored in Group mode, separated by commas.")

        self.decrypt_label = tk.Label(master, text="Decryption Handler Status: Idle")
        self.decrypt_label.pack()
        add_tooltip(self.decrypt_label, "Shows the current status of the decryption handler.")

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()
        add_tooltip(self.start_button, "Click to start monitoring the selected directory for decryption.")

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack()
        add_tooltip(self.stop_button, "Click to stop monitoring.")

    # Method to toggle group paths entry
    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    # Method to select a directory
    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory: " + self.directory)

    # Method to select a key file
    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

    # Method to start monitoring
    def start_monitoring(self):
        if hasattr(self, 'directory') and hasattr(self, 'key_file'):
            groups = self.group_paths_entry.get().split(',') if self.decrypt_mode.get() == "Group" else None
            self.handler = DecryptionHandler(self.load_key(), self.decrypt_trigger.get(), self.decrypt_mode.get(), self.directory, groups)

            self.decrypt_observer = Observer()
            self.decrypt_observer.schedule(self.handler, self.directory, recursive=True)
            self.decrypt_observer.start()

            self.decrypt_label.config(text="Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory and a key file.")

    # Method to stop monitoring
    def stop_monitoring(self):
        if hasattr(self, 'decrypt_observer'):
            self.decrypt_observer.stop()
            self.decrypt_observer.join()

            self.decrypt_label.config(text="Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)

self.stop_button.config(state=tk.DISABLED)

    # Method to load decryption key
    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

# Main application
if __name__ == "__main__":
    root = tk.Tk()

    # Create the notebook
    notebook = ttk.Notebook(root)
    notebook.pack(pady=10, expand=True)

    # Create frames for the tabs
    encryption_frame = Frame(notebook, width=400, height=400)
    decryption_frame = Frame(notebook, width=400, height=400)
    encryption_frame.pack(fill="both", expand=True)
    decryption_frame.pack(fill="both", expand=True)

    # Add tabs to the notebook
    notebook.add(encryption_frame, text="Encryption")
    notebook.add(decryption_frame, text="Decryption")

    # Initialize the apps
    EncryptionApp(encryption_frame)
    DecryptionApp(decryption_frame)

    root.mainloop()