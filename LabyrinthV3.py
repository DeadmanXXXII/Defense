import os
import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

# EncryptionHandler class definition with additional trigger for directory access
class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode

    def on_created(self, event):
        if not event.is_directory and (self.trigger == "Create" or self.trigger == "Access"):
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

    def on_access(self, event):
        if not event.is_directory and self.trigger == "Access":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual":
            self.encrypt_file(file_path)
        elif self.mode == "Group":
            for path in self.get_group_paths(file_path):
                self.encrypt_file(path)
        elif self.mode == "All":
            self.encrypt_all_files(file_path)

    def get_group_paths(self, file_path):
        paths = []
        if os.path.isfile(file_path):
            paths.append(file_path)
        elif os.path.isdir(file_path):
            for root, _, files in os.walk(file_path):
                for file in files:
                    paths.append(os.path.join(root, file))
        return paths

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        encrypted_file_path = file_path + ".encrypted"
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

    def encrypt_all_files(self, dir_path):
        for root, _, files in os.walk(dir_path):
            for file in files:
                if not file.endswith(".encrypted"):
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path)

    def encrypt_group_files(self, paths):
        for path in paths:
            self.handle_file(path)

# DecryptionHandler class definition
class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)

    def on_created(self, event):
        pass

    def on_deleted(self, event):
        pass

    def on_modified(self, event):
        pass

    def handle_file(self, file_path):
        self.decrypt_file(file_path)

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = self.fernet.decrypt(data)
        decrypted_file_path = file_path[:-len(".encrypted")]
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

    def decrypt_group_files(self, paths):
        for path in paths:
            self.handle_file(path)

# EncryptionApp class definition
class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption")

        self.label1 = tk.Label(master, text="Select a directory or file to encrypt:")
        self.label1.pack()

        self.directory_button = tk.Button(master, text="Select Directory/File", command=self.select_directory)
        self.directory_button.pack()

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()

        self.label3 = tk.Label(master, text="Select trigger for encryption:")
        self.label3.pack()

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(master, self.encrypt_trigger, "Create", "Delete", "Modify", "Access")
        self.encrypt_trigger_menu.pack()

        self.label4 = tk.Label(master, text="Select encryption mode:")
        self.label4.pack()

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(master, self.encrypt_mode, "Individual", "Group", "All")
        self.encrypt_mode_menu.pack()

        self.encrypt_label = tk.Label(master, text="Encryption Handler Status: Idle")
        self.encrypt_label.pack()

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack()

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory/File: " + self.directory)

    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

    def start_monitoring(self):
        if hasattr(self, 'directory') and hasattr(self, 'key_file'):
            self.handler = EncryptionHandler(self.load_key(), self.encrypt_trigger.get(), self.encrypt_mode.get())

            self.encrypt_observer = Observer()
            self.encrypt_observer.schedule(self.handler, self.directory, recursive=True)
            self.encrypt_observer.start()

            self.encrypt_label.config(text="Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory or file and a key file.")

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

    def encrypt_group_files(self):
        paths = filedialog.askopenfilenames()
        if paths:
            self.handler.encrypt_group_files(paths)
            messagebox.showinfo("Encryption", "Files encrypted successfully.")

# DecryptionApp class definition
class DecryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("File Decryption")

        self.label1 = tk.Label(master, text="Select a directory or file to decrypt:")
        self.label1.pack()

        self.directory_button = tk.Button(master, text="Select Directory/File", command=self.select_directory)
        self.directory_button.pack()

        self.label2 = tk.Label(master, text="Select a key file:")
        self.label2.pack()

        self.key_button = tk.Button(master, text="Select Key File", command=self.select_key)
        self.key_button.pack()

        self.label3 = tk.Label(master, text="Decryption Mode:")
        self.label3.pack()

        self.decrypt_mode = tk.StringVar()
        self.decrypt_mode.set("Manual")
        self.decrypt_mode_menu = tk.OptionMenu(master, self.decrypt_mode, "Manual")
        self.decrypt_mode_menu.pack()

        self.decrypt_label = tk.Label(master, text="Decryption Handler Status: Idle")
        self.decrypt_label.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt Files Manually", command=self.decrypt_files_manually)
        self.decrypt_button.pack()

        self.start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack()

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.directory_button.config(text="Selected Directory/File: " + self.directory)

    def select_key(self):
        self.key_file = filedialog.askopenfilename()
        self.key_button.config(text="Selected Key File: " + self.key_file)

    def start_monitoring(self):
        if hasattr(self, 'directory') and hasattr(self, 'key_file'):
            self.handler = DecryptionHandler(self.load_key())

            self.decrypt_observer = Observer()
            self.decrypt_observer.schedule(self.handler, self.directory, recursive=True)
            self.decrypt_observer.start()

            self.decrypt_label.config(text="Handler Status: Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Please select a directory or file and a key file.")

    def stop_monitoring(self):
        if hasattr(self, 'decrypt_observer'):
            self.decrypt_observer.stop()
            self.decrypt_observer.join()

            self.decrypt_label.config(text="Handler Status: Running")

self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def load_key(self):
        with open(self.key_file, "rb") as f:
            return f.read()

    def decrypt_files_manually(self):
        paths = filedialog.askopenfilenames()
        if paths:
            self.handler.decrypt_group_files(paths)
            messagebox.showinfo("Decryption", "Files decrypted successfully.")

    def decrypt_group_files(self):
        paths = filedialog.askopenfilenames()
        if paths:
            self.handler.decrypt_group_files(paths)
            messagebox.showinfo("Decryption", "Files decrypted successfully.")

# Main function to start the application
def main():
    root = tk.Tk()
    root.title("File Encryption and Decryption Tool")

    # Create frames for Encryption and Decryption
    encryption_frame = tk.Frame(root, padx=10, pady=10)
    encryption_frame.pack(side="left")

    decryption_frame = tk.Frame(root, padx=10, pady=10)
    decryption_frame.pack(side="right")

    # Create instances of EncryptionApp and DecryptionApp within their respective frames
    encryption_app = EncryptionApp(encryption_frame)
    decryption_app = DecryptionApp(decryption_frame)

    # Add header and footer labels
    header_label = tk.Label(root, text="Labyrinth The File Encryption and Decryption Tool", font=("Helvetica", 14, "bold"))
    header_label.pack(side="top", pady=10)

    footer_label = tk.Label(root, text="Created by Blu Corbel", font=("Helvetica", 10))
    footer_label.pack(side="bottom", pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()