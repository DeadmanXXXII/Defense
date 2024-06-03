import hashlib
import os
import smtplib
from email.message import EmailMessage
import bcrypt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import messagebox

class FileModifiedHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        filename = event.src_path
        file_hash = calculate_file_hash(filename)
        check_for_breaches(file_hash)
        send_email_alert(f"File Change Detected: {filename}", f"The file {filename} has been modified. Hash: {file_hash}")

# Function to send email alert
def send_email_alert(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = 'recipient_email@gmail.com'
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('your_email@gmail.com', 'your_password')
    server.send_message(msg)
    server.quit()

# Function to calculate the hash of a file
def calculate_file_hash(filename):
    with open(filename, 'rb') as f:
        file_content = f.read()
        return hashlib.sha256(file_content).hexdigest()

# Function to check for breaches
def check_for_breaches(file_hash):
    # Example: Query a database to check if the hash exists in a list of known good hashes
    known_hashes = ['mocked_hash_1', 'mocked_hash_2']  # Replace with actual known hashes
    if file_hash not in known_hashes:
        block_network_access()
        quarantine_site()

# Function to quarantine site
def quarantine_site():
    # Actual logic to quarantine the site
    print('Site Quarantined')

# Function to block network access
def block_network_access():
    # Actual logic to block network access
    print('Network Access Blocked')

# Function to add super root account with password storage and encryption
def add_super_root_account(username, password):
    # Encrypt password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Store encrypted password (replace with your storage mechanism)
    print(f"Super root account '{username}' added with hashed password '{hashed_password}'")

# Start file monitoring
def start_file_monitoring(directory):
    event_handler = FileModifiedHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()

# Function to handle button click
def handle_click():
    username = entry_username.get()
    role = entry_role.get()
    password = entry_password.get()
    filename = entry_filename.get()
    attacker_ip = entry_attacker_ip.get()

    # Add super root account
    add_super_root_account(username, password)

    # Start file monitoring
    start_file_monitoring(os.path.dirname(filename))

    messagebox.showinfo("Process Completed", "Process completed successfully")

# Create GUI
root = tk.Tk()
root.title("Security Script")
root.geometry("400x400")

# Username
label_username = tk.Label(root, text="Username:")
label_username.pack()
entry_username = tk.Entry(root)
entry_username.pack()

# Role
label_role = tk.Label(root, text="Role:")
label_role.pack()
entry_role = tk.Entry(root)
entry_role.pack()

# Password
label_password = tk.Label(root, text="Password:")
label_password.pack()
entry_password = tk.Entry(root, show="*")
entry_password.pack()

# Filename
label_filename = tk.Label(root, text="Filename:")
label_filename.pack()
entry_filename = tk.Entry(root)
entry_filename.pack()

# Attacker IP
label_attacker_ip = tk.Label(root, text="Attacker IP:")
label_attacker_ip.pack()
entry_attacker_ip = tk.Entry(root)
entry_attacker_ip.pack()

# Button
button_submit = tk.Button(root, text="Submit", command=handle_click)
button_submit.pack()

root.mainloop()