import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os

# Tooltip class
class CreateToolTip(object):
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.show_tooltip()

    def leave(self, event=None):
        self.hide_tooltip()

    def show_tooltip(self):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="yellow", relief='solid', borderwidth=1)
        label.pack(ipadx=1)

    def hide_tooltip(self):
        tw = self.tooltip_window
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
        self.label1.grid(row=0, column=0, pady=5, padx=10, sticky="w")

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.grid(row=1, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.directory_button, "Click to select the directory to monitor")

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.grid(row=2, column=0, pady=5, padx=10, sticky="w")

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.grid(row=3, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.key_button, "Click to select the key file")

        self.label3 = tk.Label(master, text="Select trigger for encryption:")
        self.label3.grid(row=4, column=0, pady=5, padx=10, sticky="w")

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(master, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.grid(row=5, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.encrypt_trigger_menu, "Select when encryption should trigger")

        self.label4 = tk.Label(master, text="Select encryption mode:")
        self.label4.grid(row=6, column=0, pady=5, padx=10, sticky="w")

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(master, self.encrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry_encrypt)
        self.encrypt_mode_menu.grid(row=7, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.encrypt_mode_menu, "Select how files should be encrypted")

        self.label5 = tk.Label(master, text="Enter group paths (comma-separated):")
        self.label5.grid(row=8, column=0, pady=5, padx=10, sticky="w")

        self.group_paths_entry = tk.Entry(master, width=50)
        self.group_paths_entry.grid(row=9, column=0, pady=5, padx=10, sticky="w")
        self.group_paths_entry.config(state=tk.DISABLED)
        CreateToolTip(self.group_paths_entry, "Enter paths for group encryption (comma-separated)")

        self.encrypt_label = tk.Label(master, text="Encryption Handler Status: Idle")
        self.encrypt_label.grid(row=10, column=0, pady=5, padx=10, sticky="w")

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=11, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.start_button, "Start monitoring the selected directory for encryption")

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=12, column=0, pady=5, padx=10, sticky="w")
        CreateToolTip(self.stop_button, "Stop monitoring the selected directory")

    # Method to toggle group paths entry
    def toggle_group_entry_encrypt(self, mode):
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
        self.label1.grid(row=0, column=1, pady=5, padx=10, sticky="w")

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.grid(row=1, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.directory_button, "Click to select the directory to monitor")

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.grid(row=2, column=1, pady=5, padx=10, sticky="w")

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.grid(row=3, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.key_button, "Click to select the key file")

        self.label3 = tk.Label(master, text="Select trigger for decryption:")
        self.label3.grid(row=4, column=1, pady=5, padx=10, sticky="w")

        self.decrypt_trigger = tk.StringVar()
        self.decrypt_trigger.set("Create")
        self.decrypt_trigger_menu = tk.OptionMenu(master, self.decrypt_trigger, "Create", "Delete", "Modify")
        self.decrypt_trigger_menu.grid(row=5, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.decrypt_trigger_menu, "Select when decryption should trigger")

        self.label4 = tk.Label(master, text="Select decryption mode:")
        self.label4.grid(row=6, column=1, pady=5, padx=10, sticky="w")

        self.decrypt_mode = tk.StringVar()
        self.decrypt_mode.set("Individual")
        self.decrypt_mode_menu = tk.OptionMenu(master, self.decrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry_decrypt)
        self.decrypt_mode_menu.grid(row=7, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.decrypt_mode_menu, "Select how files should be decrypted")

        self.label5 = tk.Label(master, text="Enter group paths (comma-separated):")
        self.label5.grid(row=8, column=1, pady=5, padx=10, sticky="w")

        self.group_paths_entry = tk.Entry(master, width=50)
        self.group_paths_entry.grid(row=9, column=1, pady=5, padx=10, sticky="w")
        self.group_paths_entry.config(state=tk.DISABLED)
        CreateToolTip(self.group_paths_entry, "Enter paths for group decryption (comma-separated)")

        self.decrypt_label = tk.Label(master, text="Decryption Handler Status: Idle")
        self.decrypt_label.grid(row=10, column=1, pady=5, padx=10, sticky="w")

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=11, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.start_button, "Start monitoring the selected directory for decryption")

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=12, column=1, pady=5, padx=10, sticky="w")
        CreateToolTip(self.stop_button, "Stop monitoring the selected directory")

    # Method to toggle group paths entry
    def toggle_group_entry_decrypt(self, mode):
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


def main():
    root = tk.Tk()

    # Add headers and footers
    header_label = tk.Label(root, text="Labyrinth - File Encryption and Decryption Tool", font=("Helvetica", 16, "bold"))
    header_label.grid(row=0, column=0, columnspan=2, pady=10)

    # Create instances of both apps
    encryption_app = EncryptionApp(root)
    decryption_app = DecryptionApp(root)

    footer_label = tk.Label(root, text="Created by Blu Corbel", font=("Helvetica", 10))
    footer_label.grid(row=13, column=0, columnspan=2, sticky="e", pady=(0, 10))

    root.mainloop()


if __name__ == "__main__":
    main()