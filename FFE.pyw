import os
import requests
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from packaging import version
import re
import webbrowser
import threading
import platform



def get_downloads_dir():
    """Get the user's downloads directory based on platform"""
    if platform.system() == "Windows":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders') as key:
                downloads_dir = winreg.QueryValueEx(key, '{374DE290-123F-4565-9164-39C4925E467B}')[0]
                return downloads_dir
        except:
            return os.path.join(os.path.expanduser("~"), "Downloads")
    elif platform.system() == "Darwin": # macOS
        return os.path.join(os.path.expanduser("~"), "Downloads")
    else:  # Linux and others
        try:
            with open(os.path.expanduser("~/.config/user-dirs.dirs"), "r") as f:
                for line in f:
                    if line.startswith("XDG_DOWNLOAD_DIR"):
                        return os.path.expanduser(line.split("=")[1].strip().strip('"'))
        except:
            return os.path.join(os.path.expanduser("~"), "Downloads")

def fesys_gen_key():
    return Fernet.generate_key()


def fesys_save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)


def fesys_encrypt_file(file_path, main_key):
    try:
        cipher_main = Fernet(main_key)
        new_key = Fernet.generate_key()
        cipher_file = Fernet(new_key)

        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = cipher_file.encrypt(file_data)
        encrypted_key = cipher_main.encrypt(new_key)
        encrypted_file_path = file_path + ".enc"

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data + b"|||" + encrypted_key)

        return f"File '{os.path.basename(file_path)}' successfully encrypted!"
    except Exception as e:
        return f"Error during encryption: {str(e)}"


def fesys_decrypt_file(file_path, main_key):
    try:
        if not file_path.endswith(".enc"):
            return "Only .enc files can be decrypted."

        cipher_main = Fernet(main_key)

        with open(file_path, "rb") as encrypted_file:
            full_encrypted_data = encrypted_file.read()

        try:
            encrypted_data, encrypted_key = full_encrypted_data.split(b"|||")
        except ValueError:
            return "Error: Encrypted file is corrupted or not in the correct format."

        decrypted_key = cipher_main.decrypt(encrypted_key)
        cipher_file = Fernet(decrypted_key)
        decrypted_data = cipher_file.decrypt(encrypted_data)
        decrypted_file_path = file_path[:-4]

        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        return f"File '{os.path.basename(file_path[:-4])}' successfully decrypted!"
    except Exception as e:
        return f"Error during decryption: {str(e)}"


class HoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = self["background"]
        self.bright_bg = self.brighten_color(self.default_bg, 20)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self["background"] = self.bright_bg

    def on_leave(self, e):
        self["background"] = self.default_bg

    def brighten_color(self, color, brightness_factor):
        if isinstance(color, str) and color.startswith("#") and len(color) == 7:
            try:
                r, g, b = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
                r = min(255, r + brightness_factor)
                g = min(255, g + brightness_factor)
                b = min(255, b + brightness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        else:
            return color


class ThemeColors:
    THEMES = {
        "FFE Default": {
            "bg": "#0a1f24",
            "secondary_bg": "#0f2436",
            "accent": "#164954",
            "success": "#1a7d88",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        }
    }

    @staticmethod
    def get_dialog_colors(dialog_type, theme_name):
        """Get colors for different dialog types based on theme"""
        theme = ThemeColors.THEMES[theme_name]
        colors = {
            "info": theme["accent"],
            "warning": theme["warning"],
            "error": theme["error"],
            "question": theme["success"]
        }
        return colors.get(dialog_type, theme["accent"])

    @staticmethod
    def get_button_text_color(theme_name, button_type):
        return "white"


class ModernDialog(tk.Toplevel):
    TITLE_FONT_SIZE = 29
    VERSION_FONT_SIZE = 16
    CONTENT_FONT_SIZE = 11
    
    def __init__(self, parent, title, message, dialog_type="info", title_font_size=None, **kwargs):
        super().__init__(parent)
        self.result = None
        
        if hasattr(parent, 'current_theme'):
            self.theme_name = parent.current_theme
        else:
            self.theme_name = "FFE Default"
        
        theme = ThemeColors.THEMES[self.theme_name]
        
        self.title_font_size = title_font_size if title_font_size is not None else self.TITLE_FONT_SIZE
        
        self.title(title)
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)
        
        self.main_frame = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        self.main_frame.pack(expand=True, fill="both")

        if "[[TITLE]]" in message:
            parts = message.split("[[TITLE]]", 1)
            title_part = parts[0]
            remaining = parts[1]
            
            if "[[VERSION]]" in remaining:
                version_part, content = remaining.split("[[VERSION]]", 1)
            else:
                version_part = ""
                content = remaining

            header_frame = tk.Frame(self.main_frame, bg=theme["secondary_bg"])
            header_frame.pack(anchor="w", pady=(0, 10))

            title_label = tk.Label(
                header_frame, text=title_part, bg=theme["secondary_bg"], fg=theme["text"],
                font=("Segoe UI", self.title_font_size, "bold"), justify="left"
            )
            title_label.pack(anchor="w", pady=0)
            
            if version_part:
                version_label = tk.Label(
                    header_frame, text=version_part.strip(), bg=theme["secondary_bg"], fg=theme["text"],
                    font=("Segoe UI", self.VERSION_FONT_SIZE), justify="left"
                )
                version_label.pack(anchor="w", pady=0)
            
            message_label = tk.Label(
                self.main_frame, text=content.lstrip(), bg=theme["secondary_bg"], fg=theme["text"],
                font=("Segoe UI", self.CONTENT_FONT_SIZE), justify="left", wraplength=400
            )
            message_label.pack(pady=(0, 20), anchor="w")
        else:
            message_label = tk.Label(
                self.main_frame, text=message, bg=theme["secondary_bg"], fg=theme["text"],
                font=("Segoe UI", self.CONTENT_FONT_SIZE), justify="left", wraplength=400
            )
            message_label.pack(pady=(0, 20), anchor="w")

        self.content_frame = tk.Frame(self.main_frame, bg=theme["secondary_bg"])
        self.content_frame.pack(fill="x", expand=True)
        
        self.button_frame = tk.Frame(self.main_frame, bg=theme["secondary_bg"])
        
    def add_buttons(self, dialog_type="info"):
        theme = ThemeColors.THEMES[self.theme_name]
        accent_color = ThemeColors.get_dialog_colors(dialog_type, self.theme_name)
        
        self.button_frame.pack(fill="x", pady=(20, 0))
        
        if dialog_type == "question":
            self.button_frame.grid_columnconfigure(0, weight=1)
            self.button_frame.grid_columnconfigure(1, weight=1)
            
            yes_btn = HoverButton(
                self.button_frame, text="Yes", command=self.yes_click, bg=accent_color,
                fg=ThemeColors.get_button_text_color(self.theme_name, dialog_type), font=("Segoe UI", 11), relief="flat"
            )
            yes_btn.grid(row=0, column=0, sticky="ew", padx=2, pady=5)
            
            no_btn = HoverButton(
                self.button_frame, text="No", command=self.no_click, bg=theme["accent"],
                fg=ThemeColors.get_button_text_color(self.theme_name, "accent"), font=("Segoe UI", 11), relief="flat"
            )
            no_btn.grid(row=0, column=1, sticky="ew", padx=2, pady=5)
        else:
            ok_btn = HoverButton(
                self.button_frame, text="OK", command=self.ok_click, bg=accent_color,
                fg=ThemeColors.get_button_text_color(self.theme_name, dialog_type), font=("Segoe UI", 11), relief="flat"
            )
            ok_btn.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        
        self.center_window()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.ok_click)
        self.focus_set()

    def get_content_frame(self):
        return self.content_frame

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        
    def ok_click(self):
        self.result = True
        self.destroy()
        
    def yes_click(self):
        self.result = True
        self.destroy()
        
    def no_click(self):
        self.result = False
        self.destroy()

def show_modern_info(parent, title, message):
    dialog = ModernDialog(parent, title, message, "info")
    dialog.add_buttons()
    dialog.wait_window()
    return dialog.result

def show_modern_warning(parent, title, message):
    dialog = ModernDialog(parent, title, message, "warning")
    dialog.add_buttons()
    dialog.wait_window()
    return dialog.result

def show_modern_error(parent, title, message):
    dialog = ModernDialog(parent, title, message, "error")
    dialog.add_buttons()
    dialog.wait_window()
    return dialog.result

def show_modern_question(parent, title, message):
    dialog = ModernDialog(parent, title, message, "question")
    dialog.add_buttons("question")
    dialog.wait_window()
    return dialog.result

class FESys(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor - Version 2.2.0")
        self.geometry("1070x800")
        self.configure(bg="#0a1f24")
        self.minsize(1070, 800)

        self.current_theme = "FFE Default"
        self.main_key = self.load_main_key()

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#0f2436", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12),
                                       selectbackground="#216176", selectforeground="white")
        self.file_listbox.bind("<Double-1>", self.file_dc_act)
        self.create_widgets()
        self.acc_files()
        self.decrypting = False
        self.hovered_index = None
        self.brighten_factor = 20

        self.ffe_websrv_chk("https://www.github.com/AVXAdvanced/FFE", self.no_ffe_web)

    def no_ffe_web(self):
        show_modern_warning(self, "Online Features Unavailable", """FFE's Online Features aren't available.

This means that certain features such as Updates may
not be available. 

This problem may be caused by the following:

- You aren't connected to the Internet
- You're using a VPN
- Your Internet Settings are misconfigured
- The FFE GitHub is experiencing issues

Check the items listed above. If you
cannot resolve the issue yourself,
try again later.

Error Code: FxOSNA8217

You can continue using FFE without Online Features.
        """)

    def ffe_websrv_chk(self, url, on_failure):
        def check_web():
            try:
                requests.get(url, timeout=4.273)
            except requests.exceptions.RequestException as e:
                self.after(0, on_failure)

        thread = threading.Thread(target=check_web)
        thread.daemon = True
        thread.start()

    def brighten_color(self, color_hex, factor):
        if isinstance(color_hex, str) and color_hex.startswith("#") and len(color_hex) == 7:
            try:
                r, g, b = tuple(int(color_hex[i:i + 2], 16) for i in (1, 3, 5))
                r = min(255, r + factor)
                g = min(255, g + factor)
                b = min(255, b + factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color_hex
        return color_hex

    def on_select(self, event):
        try:
            selected_index = self.file_listbox.curselection()[0]
            file_path = self.file_paths[selected_index]
            # You could do something here based on the selected file if you want
            self.status_label.config(text=f"Selected: {os.path.basename(file_path)}")
            pass

        except IndexError:
            pass

    def fesys_load_key(self, filename):
        with open(filename, "rb") as key_file:
            return key_file.read()

    def create_widgets(self):  # toolbar_ui_crt_def (act on stup)
        toolbar = tk.Frame(self, bg="#0a1f24")
        # Align toolbar with file listbox
        toolbar.pack(fill=tk.X, padx=10, pady=6)
        toolbar.columnconfigure(2, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                       bg="#164954", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=5)

        self.forward_button = HoverButton(toolbar, text=" Forward ", command=self.go_forward, state=tk.DISABLED,
                                          bg="#164954", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=5)

        self.refresh_button = HoverButton(toolbar, text=" Refresh ", command=self.acc_files, bg="#164954", fg="white",
                                          relief="flat", font=("Segoe UI", 11))
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.drive_selector = tk.StringVar(value=self.current_path)
        self.drive_menu = tk.OptionMenu(toolbar, self.drive_selector, *self.acc_hdd(), command=self.update_drive)
        self.drive_menu["menu"].config(bg="#164954", fg="white", relief="flat", font=("Segoe UI", 11))
        self.drive_menu.config(bg="#164954", fg="white", font=("Segoe UI", 11), relief="flat")
        self.drive_menu.pack(side=tk.LEFT, padx=20, expand=True, fill=tk.X)

        # Keep original file listbox padding
        self.file_listbox.pack(pady=(1, 2), padx=15, expand=True, fill=tk.BOTH)
        self.file_listbox.bind("<Double-1>", self.file_dc_act)

        encrypt_button = HoverButton(toolbar, text=" Encrypt ", command=self.encrypt_file, bg="#1a7d88", fg="white",
                                     relief="flat", font=("Segoe UI", 11))
        encrypt_button.pack(side=tk.LEFT, padx=4, pady=6)

        decrypt_button = HoverButton(toolbar, text=" Decrypt ", command=self.decrypt_file, bg="#1a7d88", fg="white",
                                     relief="flat", font=("Segoe UI", 11))
        decrypt_button.pack(side=tk.LEFT, padx=4, pady=6)

        delete_button = HoverButton(toolbar, text=" Delete ", command=self.del_f, bg="#bf3e3b", fg="white",
                                    relief="flat", font=("Segoe UI", 11))
        delete_button.pack(side=tk.LEFT, padx=4, pady=6)

        update_button = HoverButton(toolbar, text=" Update ", command=self.update_ffe, bg="#164954", fg="white",
                                    relief="flat", font=("Segoe UI", 11))
        update_button.pack(side=tk.LEFT, padx=4, pady=6)

        help_button = HoverButton(toolbar, text=" Help ", command=self.show_help, bg="#164954", fg="white",
                                  relief="flat", font=("Segoe UI", 11))
        help_button.pack(side=tk.LEFT, padx=4, pady=6)

        about_button = HoverButton(toolbar, text=" About ", command=self.show_about, bg="#164954", fg="white",
                                   relief="flat", font=("Segoe UI", 11))
        about_button.pack(side=tk.LEFT, padx=4, pady=6)

        self.status_label = tk.Label(self, text="Select a file to encrypt. Double click folders to navigate.",
                                     bg="#0a1f24", fg="white", font=("Segoe UI", 11))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    def acc_hdd(self):
        drives = [chr(drive) + ":\\" for drive in range(65, 91) if os.path.exists(chr(drive) + ":\\")]
        return drives

    def acc_files(self):
        try:
            self.file_listbox.delete(0, tk.END)
            file_paths = []
            display_names = []

            for entry in os.listdir(self.current_path):
                full_path = os.path.join(self.current_path, entry)

                if entry.startswith('.') or (os.name == 'nt' and os.stat(full_path).st_file_attributes & 2):
                    continue

                if os.path.isdir(full_path):
                    display_name = f"📁 {entry}/"
                elif entry.endswith(".enc"):
                    display_name = f"🔒 {entry}"
                else:
                    display_name = f"📄 {entry}"

                display_names.append(display_name)
                file_paths.append(full_path)

            for name in display_names:
                self.file_listbox.insert(tk.END, name)

            self.file_paths = file_paths
            self.status_label.config(text=f"Showing files in {self.current_path}")
            self.back_button.config(state=tk.NORMAL if self.history_index > 0 else tk.DISABLED)
            self.forward_button.config(state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED)
        except Exception as e:
            show_modern_error(self, "Error", f"Failed to load files: {str(e)}")

    def file_dc_act(self, event):  # file doubleclick act (on act enbl)
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isfile(full_path):
                self.status_label.config(text=f"Selected file: {full_path}")
            elif os.path.isdir(full_path):
                self.current_path = full_path
                self.history.append(self.current_path)
                self.history_index += 1
                self.acc_files()
            else:
                show_modern_error(self, "Error", f"Invalid selection: {self.file_listbox.get(selected_index)}")

        except IndexError:
            pass  # No selection, so nothing to do
        except Exception as e:
            show_modern_error(self, "Error", f"Failed to open file: {str(e)}")

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.current_path = self.history[self.history_index]
            self.acc_files()

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.current_path = self.history[self.history_index]
            self.acc_files()

    def update_drive(self, new_drive):
        self.current_path = new_drive
        self.history = [new_drive]  # Directly set the history with the new path
        self.history_index = 0
        self.acc_files()

    def load_main_key(self):
        if not os.path.exists("main_key.key"):
            key = Fernet.generate_key()
            with open("main_key.key", "wb") as key_file:
                key_file.write(key)
            show_modern_warning(self, "Key File Missing", """FFE has created a new Key File.

FFE couldn't find your Key File, so a new one was created.
If you think this is a mistake, please
check the following:

- Is your Key File in the same directory as "FFE.exe"?
- Is your Key File named "main_key.key"?
- Is your Key File corrupted?

If you've just opened FFE, this is normal 
and you can simply ignore this warning.
            """)
        key = self.fesys_load_key("main_key.key")
        return key

    def encrypt_file(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't encrypt a directory. Select a file.")
                return

            result = fesys_encrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def decrypt_file(self):
        if self.decrypting:
            return
        self.decrypting = True

        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't decrypt a directory. Please Select a file.")
                self.decrypting = False
                return

            if not full_path.endswith(".enc"):
                show_modern_error(self, "Nope", "Only .enc files can be decrypted.")
                self.decrypting = False
                return

            result = fesys_decrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Failed to decrypt file: {str(e)}")
        finally:
            self.decrypting = False

# about window - in VS code changes might not show up, save file and re-run
# File -> Save / File -> Save All / Ctrl + S 

# TODO: pull about box from aetherion (chk other elements, pull themed)

    def show_about(self):
        about_text = """Friend File Encryptor[[TITLE]]Version 2.2.0[[VERSION]]
Build: ffe_083025_211_lyra
Build Date: 9/6/2025
Windows Edition (x64)

"It's never been easier to share files...
...while avoiding unwanted guests..."

Connect With Us:"""
        dialog = ModernDialog(self, "About Friend File Encryptor", about_text)
        content_frame = dialog.get_content_frame()
        
        theme = ThemeColors.THEMES[self.current_theme]
        links_frame = tk.Frame(content_frame, bg=theme["secondary_bg"])
        links_frame.pack(fill="x", pady=(10, 0))
        
        social_links = [
            ("GitHub", "https://github.com/AVXAdvanced/FFE"),
            ("X/Twitter", "https://x.com/ffe_world"),
            ("Product Hunt", "https://producthunt.com/products/ffe")
        ]
        
        for label, url in social_links:
            link_frame = tk.Frame(links_frame, bg=theme["secondary_bg"])
            link_frame.pack(fill="x", pady=3)
            
            tk.Label(
                link_frame, text=f"• {label}", bg=theme["secondary_bg"], fg=theme["text"],
                font=("Segoe UI", 11)
            ).pack(side="left")
            
            HoverButton(
                link_frame, text="Visit", command=lambda u=url: webbrowser.open_new(u),
                bg=theme["accent"], fg="white", relief="flat", font=("Segoe UI", 10),
                width=6, height=1, padx=10, pady=2
            ).pack(side="right")
        
        separator = tk.Frame(content_frame, height=2, bg=theme["accent"])
        separator.pack(fill="x", pady=(15, 15))
        
        tk.Label(
            content_frame, text="(c) 2025 AVX_Advanced. All rights reserved.",
            bg=theme["secondary_bg"], fg=theme["text"], font=("Segoe UI", 11)
        ).pack(anchor="w")
        
        dialog.add_buttons()
        dialog.wait_window()

    def show_help(self):
        response = show_modern_question(self, "Documentation & Support", """Access FFE's documentation and support resources:

Documentation:
• User Guide - Complete usage instructions
• Wiki - Detailed feature documentation
• FAQ - Common questions and solutions

Support Options:
• Community Discussions - Ask questions
• Issue Tracker - Report technical issues
• Feature Requests - Suggest improvements

Would you like to access these resources now?""")

        if response:
            webbrowser.open_new("https://github.com/AVXAdvanced/FFE")

    def del_f(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Cannot delete a directory. Please Select a file.")
                return

            if os.path.exists(full_path):
                if show_modern_question(self, "Sure?",
                                              f"Do you really want to get rid of '{os.path.basename(full_path)}'? "):
                    os.remove(full_path)
                    self.status_label.config(text=f"Yay it's gone.. one could say it's deleted!")
                    self.acc_files()
            else:
                show_modern_error(self, "Where'd it go?",
                                     "We couldn't find that file. You might not have sufficient permissions to modify it.")

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Guess that one's staying. Couldn't delete {str(e)}")

    def update_ffe(self):
        try:
            current_version = "2.2.0"
            url = f"https://api.github.com/repos/AVXAdvanced/FFE/releases/latest"
            response = requests.get(url)
            response.raise_for_status()

            latest_release = response.json()
            release_name = latest_release["name"]
            match = re.search(r"Version (\d+\.\d+\.\d+)", release_name)

            if match:
                latest_version = match.group(1)
            else:
                if show_modern_question(self, "Update Check Failed", """Unable to verify latest version information.

Would you like to check for updates manually?"""):
                    webbrowser.open_new("https://github.com/AVXAdvanced/FFE")
                return

            if version.parse(latest_version) > version.parse(current_version):
                downloads_dir = get_downloads_dir()
                if show_modern_question(self, "Update Available", f"""A new version of FFE is available.

Current Version: {current_version}
Latest Version: {latest_version}

Download Location:
{downloads_dir}

Would you like to download the update now?"""):
                    asset_url = latest_release["assets"][0]["browser_download_url"]
                    filename = latest_release["assets"][0]["name"]
                    download_path = os.path.join(downloads_dir, filename)
                    
                    # Open download URL in browser
                    webbrowser.open_new(asset_url)
                    show_modern_info(self, "Downloading Update", f"Your download will begin shortly and will be saved to:\n\n{download_path}")
            else:
                show_modern_info(self, "Up to Date", """Your version of FFE is up to date.

No updates are currently available.""")

        except requests.exceptions.RequestException:
            show_modern_error(self, "Connection Error", """Unable to check for updates.

Please verify your internet connection and try again.""")
            self.status_label.config(text="Update check failed: Connection error")
        except Exception as e:
            show_modern_error(self, "Update Error", f"""An unexpected error occurred while checking for updates.

Technical Details:
{str(e)}

Please try again later.""")
            self.status_label.config(text="Update check failed: Unexpected error")


if __name__ == "__main__":
    app = FESys()
    app.mainloop()