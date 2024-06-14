import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet

class KeyGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Key Generator")

        # Header Label
        self.header_label = tk.Label(master, text="Labyrinth Key", font=("Helvetica", 16, "bold"))
        self.header_label.pack(pady=10)

        self.label = tk.Label(master, text="Click 'Generate Key' to create a new key.")
        self.label.pack(pady=10)

        self.generate_button = tk.Button(master, text="Generate Key", command=self.generate_key)
        self.generate_button.pack(pady=10)

        self.key_display = tk.Text(master, height=10, width=60)
        self.key_display.pack(pady=10)

        self.save_button = tk.Button(master, text="Save Key to File", command=self.save_key)
        self.save_button.pack(pady=10)

        # Footer Label
        self.footer_label = tk.Label(master, text="Created by Blu Corbel", font=("Helvetica", 10))
        self.footer_label.pack(side="bottom", pady=10)

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_display.delete("1.0", tk.END)
        self.key_display.insert(tk.END, key.decode())

    def save_key(self):
        key = self.key_display.get("1.0", tk.END).strip()
        if not key:
            messagebox.showerror("Error", "No key to save. Generate a key first.")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if filename:
            try:
                with open(filename, "wb") as f:
                    f.write(key.encode())
                messagebox.showinfo("Key Saved", f"Key saved successfully to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key:\n{e}")

def main():
    root = tk.Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()