import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog
from PIL import Image, ImageTk
from cryptography.fernet import Fernet

class SecureNotepadApp:
    def __init__(self):

        self.root = tk.Tk()
        self.root.title("Secure Notepad")

        self.load_and_display_image()

        self.title_label = tk.Label(self.root, text="Enter Title:")
        self.title_label.pack()
        self.title_entry = tk.Entry(self.root, width=40)
        self.title_entry.pack()

        self.note_label = tk.Label(self.root, text="Enter Note:")
        self.note_label.pack()
        self.note_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=40, height=10)
        self.note_text.pack(pady=10)
        save_note_button = tk.Button(self.root, text="Save Note", command=self.save_note)
        save_note_button.pack()

        open_note_button = tk.Button(self.root, text="Open Note", command=self.open_note)
        open_note_button.pack()

    def load_and_display_image(self):
        try:
            img = Image.open("photo.png")
            img = img.resize((400, 200), 3)
            photo = ImageTk.PhotoImage(img)
            label = tk.Label(self.root, image=photo)
            label.image = photo
            label.pack()
        except FileNotFoundError:
            messagebox.showerror("Error", "Image file (photo.png) not found.")

    def save_note(self):
        title = self.title_entry.get()
        note = self.note_text.get("1.0", tk.END)
        master_key = Fernet.generate_key()
        encrypted_note = self.encrypt(note, master_key)
        filename = f"{title}_encrypted.txt"
        key_filename = f"{title}_master_key.txt"
        with open(filename, "wb") as file:
            file.write(encrypted_note)
        with open(key_filename, "wb") as key_file:
            key_file.write(master_key)

        messagebox.showinfo("Success", f"Note '{title}' saved securely.\nMaster Key saved in: {key_filename}")

    def open_note(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted Note File", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                master_key, encrypted_note = self.read_file(file_path)
                entered_master_key = self.prompt_for_master_key()
                if entered_master_key and entered_master_key == master_key.decode():
                    decrypted_note = self.decrypt(encrypted_note, master_key)
                    self.note_text.delete("1.0", tk.END)
                    self.note_text.insert(tk.END, decrypted_note)
                    messagebox.showinfo("Success", f"Note opened securely.")
                else:
                    messagebox.showerror("Error", "Incorrect master key.")
            except Exception as e:
                messagebox.showerror("Error", f"Error opening note: {str(e)}")

    def read_file(self, file_path):
        with open(file_path, "rb") as file:
            encrypted_note = file.read()
        key_filename = file_path.replace("_encrypted.txt", "_master_key.txt")
        with open(key_filename, "rb") as key_file:
            master_key = key_file.read()
        return master_key, encrypted_note

    def prompt_for_master_key(self):
        return simpledialog.askstring("Master Key", "Enter the Master Key:")

    def encrypt(self, data, key):
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(data.encode())
        return encrypted_data

    def decrypt(self, encrypted_data, key):
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureNotepadApp()
    app.run()
