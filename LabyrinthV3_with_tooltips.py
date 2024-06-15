import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os

class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.encrypt_file(file_path)
        elif self.mode == "All":
            self.encrypt_all_files()

    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

    def encrypt_all_files(self):
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file_path.endswith(".encrypted"):
                    self.encrypt_file(file_path)

class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.decrypt_file(file_path)
        elif self.mode == "All":
            self.decrypt_all_files()

    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = self.fernet.decrypt(data)
        with open(file_path[:-len(".encrypted")], "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

    def decrypt_all_files(self):
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".encrypted"):
                    self.decrypt_file(file_path)

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Encryption")

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
        add_tooltip(self.stop_button, "Click to stop monitoring the selected directory.")

    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory: " + self.directory)

    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

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

    def stop_monitoring(self):
        if hasattr(self, 'encrypt_observer'):
            self.encrypt_observer.stop()
            self.encrypt_observer.join()

            self.encrypt_label.config(text="Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

class DecryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Decryption")

        self.label1 = tk.Label(master, text="Select a directory to monitor:")
        self.label1.pack()
        add_tooltip(self.label1, "Choose the directory you want to monitor for decryption.")

        self.directory_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.directory_button.pack()
        add_tooltip(self.directory_button, "Click to select the directory to monitor for decryption.")

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
        add_tooltip(self.stop_button, "Click to stop monitoring the selected directory.")

    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory: " + self.directory)

    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

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

    def stop_monitoring(self):
        if hasattr(self, 'decrypt_observer'):
            self.decrypt_observer.stop()
            self.decrypt_observer.join()

            self.decrypt_label.config(text="Handler Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

def add_tooltip(widget, text):
    tooltip = CreateToolTip(widget, text)

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

def main():
    root = tk.Tk()
root.title("Labyrinth - File Encryption and Decryption Tool")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

encrypt_frame = tk.Frame(notebook)
decrypt_frame = tk.Frame(notebook)
notebook.add(encrypt_frame, text="Encryption")
notebook.add(decrypt_frame, text="Decryption")

encryption_app = EncryptionApp(encrypt_frame)
decryption_app = DecryptionApp(decrypt_frame)

footer_label = tk.Label(root, text="Created by Blu Corbel", font=("Helvetica", 10))
footer_label.pack(side="bottom")

root.mainloop()

if __name__ == "__main__":
    main()