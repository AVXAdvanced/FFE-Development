import os
import requests
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from packaging import version
import urllib.request
import re

def fesys_gen_key():
    return Fernet.generate_key()

def fesys_save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def fesys_encrypt_file(file_path, cipher):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_file_path = file_path + ".enc"
        encrypted_data = cipher.encrypt(file_data)
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        return "File successfully encrypted!"
    except Exception as e:
        return f"Error: {str(e)}"

def fesys_decrypt_file(file_path, keys):
    try:
        if not file_path.endswith(".enc"):
            return "Maybe try a .enc file... 'Cuz that ain't one!"
        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        for key in keys:
            cipher = Fernet(key)
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
                decrypted_file_path = file_path[:-4]
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                return "File successfully decrypted!"
            except Exception as e:
                continue
        return "That's not the right key. Try a different one."
    except Exception as e:
        return f"Error: {str(e)}"

class HoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self["background"] = self.brighten_color(self.default_bg, 20)

    def on_leave(self, e):
        self["background"] = self.default_bg

    def brighten_color(self, color, brightness_factor):
        if isinstance(color, str) and color.startswith("#") and len(color) == 7: #added checks
            try:
                r, g, b = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
                r = min(255, r + brightness_factor)
                g = min(255, g + brightness_factor)
                b = min(255, b + brightness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        else:
            return color

class FFEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor - Version N8 - ffe_lyra_d_04052025_n8")
        self.geometry("1070x700")
        self.configure(bg="#1e1c29") 
        self.minsize(1070, 700)

        self.main_key = self.load_main_key()
        self.cipher = Fernet(self.main_key)

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#1e1c29", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12)) 
        self.create_widgets()
        self.load_files()
        self.decrypting = False

    def fesys_load_key(self, filename):
        with open(filename, "rb") as key_file:
            return key_file.read()

    def create_widgets(self):
        toolbar = tk.Frame(self, bg="#282536")
        toolbar.pack(fill=tk.X)
        toolbar.columnconfigure(2, weight=1)

        self.back_button = HoverButton(toolbar, text="Back", command=self.go_back, state=tk.DISABLED,
                                        bg="#343047", fg="white", relief="flat", font=("Segoe UI", 11)) 
        self.back_button.pack(side=tk.LEFT, padx=8)

        self.forward_button = HoverButton(toolbar, text="Forward", command=self.go_forward, state=tk.DISABLED,
                                            bg="#343047", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=8)

        self.drive_selector = tk.StringVar(value=self.current_path)
        self.drive_menu = tk.OptionMenu(toolbar, self.drive_selector, *self.get_drives(), command=self.update_drive)
        self.drive_menu.config(bg="#444", fg="white", font=("Segoe UI", 11), relief="flat")
        self.drive_menu.pack(side=tk.LEFT, padx=200, expand=True, fill=tk.X)

        self.file_listbox.pack(pady=20, padx=20, expand=True, fill=tk.BOTH)
        self.file_listbox.bind("<Double-1>", self.on_file_double_click)

        encrypt_button = HoverButton(toolbar, text="Encrypt", command=self.encrypt_file, bg="#469c57", fg="white", relief="flat", font=("Segoe UI", 11))
        encrypt_button.pack(side=tk.LEFT, padx=8, pady=8)

        decrypt_button = HoverButton(toolbar, text="Decrypt", command=self.decrypt_file, bg="#469c57", fg="white", relief="flat", font=("Segoe UI", 11))
        decrypt_button.pack(side=tk.LEFT, padx=8, pady=8)

        delete_button = HoverButton(toolbar, text="Delete", command=self.delete_file, bg="#bf3e3b", fg="white", relief="flat", font=("Segoe UI", 11))
        delete_button.pack(side=tk.LEFT, padx=8, pady=8)

        update_button = HoverButton(toolbar, text="Update", command=self.update_ffe, bg="#343047", fg="white", relief="flat", font=("Segoe UI", 11))
        update_button.pack(side=tk.LEFT, padx=8, pady=8)

        help_button = HoverButton(toolbar, text="Help", command=self.show_help, bg="#343047", fg="white", relief="flat", font=("Segoe UI", 11))
        help_button.pack(side=tk.LEFT, padx=8, pady=8)

        about_button = HoverButton(toolbar, text="About", command=self.show_about, bg="#343047", fg="white", relief="flat", font=("Segoe UI", 11))
        about_button.pack(side=tk.LEFT, padx=8, pady=8)

        self.status_label = tk.Label(self, text="Select a file to encrypt. Double click folders to navigate.", bg="#1e1c29", fg="white", font=("Segoe UI", 11)) #FONT C
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    def get_drives(self):
        drives = []
        for drive in range(65, 91):
            drive_letter = chr(drive) + ":\\"
            if os.path.exists(drive_letter):
                drives.append(drive_letter)
        return drives

    def load_files(self):
        try:
            self.file_listbox.delete(0, tk.END)
            self.file_paths = []

            for entry in os.listdir(self.current_path):
                full_path = os.path.join(self.current_path, entry)

                if entry.startswith('.') or (os.name == 'nt' and os.stat(full_path).st_file_attributes & 2):
                    continue

                is_dir = os.path.isdir(full_path)

                if is_dir:
                    display_name = f"📁 {entry}/"
                elif entry.endswith(".enc"):
                    display_name = f"🔒 {entry}"
                else:
                    display_name = f"📄 {entry}"

                self.file_listbox.insert(tk.END, display_name)
                self.file_paths.append(full_path)

            self.status_label.config(text=f"Showing files in {self.current_path}")
            self.back_button.config(state=tk.NORMAL if self.history_index > 0 else tk.DISABLED)
            self.forward_button.config(state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load files: {str(e)}")

    def on_file_double_click(self, event):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                self.current_path = full_path
                self.history.append(self.current_path)
                self.history_index += 1
                self.load_files()
            elif os.path.isfile(full_path):
                self.status_label.config(text=f"Selected file: {full_path}")
            else:
                messagebox.showerror("Error", f"Invalid selection: {self.file_listbox.get(selected_index)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.current_path = self.history[self.history_index]
            self.load_files()

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.current_path = self.history[self.history_index]
            self.load_files()

    def update_drive(self, new_drive):
        self.current_path = new_drive
        self.history = [self.current_path]
        self.history_index = 0
        self.load_files()

    def load_main_key(self):
        if not os.path.exists("main_key.key"):
            key = Fernet.generate_key()
            with open("main_key.key", "wb") as key_file:
                key_file.write(key)
            messagebox.showinfo("There you go!", "We didn't find a key file, so we made one for you :)")
        key = self.fesys_load_key("main_key.key")
        return key

    def encrypt_file(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                messagebox.showerror("Nope", "Can't encrypt a directory. Select a file.")
                return

            result = fesys_encrypt_file(full_path, self.cipher)
            self.status_label.config(text=result)
            self.load_files()

        except IndexError:
            messagebox.showerror("Where'd it go?", "File? I don't see no file. Select one!")
        except Exception as e:
            messagebox.showerror("Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def decrypt_file(self):
        if self.decrypting:
            return
        self.decrypting = True

        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                messagebox.showerror("Nope", "Can't decrypt a directory. Please Select a file.")
                self.decrypting = False
                return

            if not full_path.endswith(".enc"):
                messagebox.showerror("Nope", "That's not a .enc file... Try a different file.")
                self.decrypting = False
                return

            try:
                with open(full_path, "rb") as encrypted_file:
                    encrypted_data = encrypted_file.read()

                decrypted_data = self.cipher.decrypt(encrypted_data)
                decrypted_file_path = full_path[:-4]
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                self.status_label.config(text="File successfully decrypted!")
                self.load_files()
            except Exception as e:
                self.status_label.config(text=f"Failed to decrypt file: {str(e)}")
                messagebox.showerror("Nope", f"Failed to decrypt file: {str(e)}")

        except IndexError:
            messagebox.showerror("Where'd it go?", "File? I don't see no file. Select one!")
        self.decrypting = False

    def show_about(self):
        messagebox.showinfo("About", """Friend File Encryptor 
LYRA Development Build

Version N8
Build: ffe_lyra_d_04052025_n8

(c)2025 AVX_Advanced
All Rights Reserved.
                         """)

    def show_help(self):
        messagebox.showinfo("Help", """     Help isn't availible for Development Builds.
     Refer to the FFE-Development GitHub README.md
     for any information.

     Issues WILL NOT be answered for these builds.
        """)

    def delete_file(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                messagebox.showerror("Nope", "Cannot delete a directory. Please Select a file.")
                return

            if os.path.exists(full_path):
                confirm = messagebox.askyesno("Sure?", f"Do you really want to get rid of '{os.path.basename(full_path)}'?")
                if confirm:
                    os.remove(full_path)
                    self.status_label.config(text=f"Yay it's gone.. one could say it's deleted!")
                    self.load_files()
            else:
                messagebox.showerror("Where'd it go?", "File? I can't find no file. Try again!")

        except IndexError:
            messagebox.showerror("Where'd it go?", "File? I don't see no file. Select one!")
        except Exception as e:
            messagebox.showerror("Nope", f"Guess that one's staying. Couldn't delete {str(e)}")

    def update_ffe(self):
        
        try:
           current_version = "9999.9999.9999"

           url = f"https://api.github.com/repos/AVXAdvanced/FFE/releases/latest"
           response = requests.get(url)
           response.raise_for_status()

           latest_release = response.json()
           release_name = latest_release["name"]
           match = re.search(r"Version (\d+\.\d+\.\d+)", release_name)

           if match:
               latest_version = match.group(1)
           else:
               messagebox.showerror("Error", "An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually.")
               return

           if version.parse(latest_version) > version.parse(current_version):
               confirm = messagebox.askyesno("Update Available", f"Version {latest_version} is available. Would you like to download it?")
               if confirm:
                   asset_url = latest_release["assets"][0]["browser_download_url"]
                   filename = latest_release["assets"][0]["name"]
                   download_path = os.path.join(os.path.expanduser("~"), "Downloads", filename) 

                   self.status_label.config(text=f"Downloading {filename}...")
                   urllib.request.urlretrieve(asset_url, download_path)
                   self.status_label.config(text=f"{filename} was downloaded into your downloads folder. Double-Click it to install.")
                   messagebox.showinfo("Update Complete", f"{filename} was downloaded into your downloads folder. Double-Click it to install.")
               else:
                   self.status_label.config(text="Update canceled.")
                   messagebox.showinfo("Update", "Update canceled.")

           else:
               messagebox.showinfo("Update", "You're already up to date.")
               self.status_label.config(text="You're already up to date.")

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Update Error", f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error checking updates: {e}")
        except KeyError as e:
            messagebox.showerror("Update Error", f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error parsing GitHub API: {e}")
        except Exception as e:
            messagebox.showerror("Update Error", f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    app = FFEApp()
    app.mainloop()
