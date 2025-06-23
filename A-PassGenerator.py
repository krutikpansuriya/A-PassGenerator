import customtkinter as ctk
import tkinter.messagebox as mb
import hashlib, base64, pyperclip, os, time, hmac
from cryptography.fernet import Fernet
import uuid

# Constants
MASTER_FILE = "master.enc"
MIN_PIN_LENGTH = 6

class SecureString:
    """Securely store sensitive strings in memory"""
    def __init__(self, value: str):
        self._value = bytearray(value.encode('utf-8'))
        self._length = len(self._value)
        
    def get(self) -> str:
        return self._value.decode('utf-8')
    
    def wipe(self):
        """Overwrite memory with null bytes"""
        for i in range(self._length):
            self._value[i] = 0
        self._length = 0
        
    def __del__(self):
        self.wipe()

def get_device_id() -> str:
    """Get unique device identifier (MAC address)"""
    return str(uuid.getnode())

def derive_key(pin: str) -> bytes:
    """Derive encryption key from PIN using device-specific salt"""
    device_id = get_device_id()
    salt = hashlib.sha256(device_id.encode()).digest()
    fernet_key = hashlib.pbkdf2_hmac(
        'sha256', 
        pin.encode(), 
        salt, 
        600000,  
        dklen=32
    )
    return base64.urlsafe_b64encode(fernet_key)

def encrypt_master(master_password: str, key: bytes):
    """Encrypt master password using Fernet encryption"""
    f = Fernet(key)
    encrypted = f.encrypt(master_password.encode())
    with open(MASTER_FILE, "wb") as f_out:
        f_out.write(encrypted)

def decrypt_master(key: bytes) -> str:
    """Decrypt master password from file"""
    if not os.path.exists(MASTER_FILE):
        return None
    with open(MASTER_FILE, "rb") as f_in:
        encrypted = f_in.read()
    f = Fernet(key)
    return f.decrypt(encrypted).decode()

def generate_password(master: str, identifier: str) -> str:
    """Generate deterministic password from master and identifier"""
    h = hmac.new(
        key=master.encode('utf-8'),
        msg=identifier.encode('utf-8'),
        digestmod=hashlib.sha256
    )
    hashed = h.hexdigest()
    
    # Construct password with required character types
    chars = [c for c in hashed if c.islower()][0]  # Lowercase
    chars += ([c for c in hashed if c.isupper()] or ['A'])[0]  # Uppercase
    chars += [c for c in hashed if c.isdigit()][0]  # Digit
    chars += "-"  # Special character
    
    # Fill remaining length with unique allowed chars
    allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'
    index = 0
    while len(chars) < 16 and index < len(hashed):
        c = hashed[index]
        if c in allowed and c not in chars:
            chars += c
        index += 1
    
    return ''.join(chars[:16])  # Final 16-char password

class App(ctk.CTk):
    """Main application class"""
    def __init__(self):
        super().__init__()
        self.title("A-PassGenerator")
        self.geometry("320x420")
        self.iconbitmap('icon.ico')
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Security variables
        self.key = None
        self.master_password = None  # SecureString holder
        
        # UI variables
        self.pin_var = ctk.StringVar()
        self.master_var = ctk.StringVar()
        self.identifier_var = ctk.StringVar()
        self.generated_var = ctk.StringVar()
        self.show_pw = ctk.BooleanVar(value=False)
        self.encryption_visible = False
        
        self.setup_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.last_activity = time.time()
        self.check_activity()  # Start inactivity timer

    def on_closing(self):
        """Secure cleanup on exit"""
        if self.master_password:
            self.master_password.wipe()
        self.destroy()

    def check_activity(self):
        """Check for inactivity and lock app"""
        if time.time() - self.last_activity > 120:  # 2 minutes
            if self.master_password:
                self.master_password.wipe()
                self.setup_pin_unlock_ui()
        self.after(1000, self.check_activity)  # Check every second

    def reset_inactivity_timer(self):
        """Reset timer on user activity"""
        self.last_activity = time.time()

    def setup_ui(self):
        """Initialize UI based on first-run status"""
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)
        if not os.path.exists(MASTER_FILE):
            self.setup_pin_create_ui()
        else:
            self.setup_pin_unlock_ui()

    def clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.frame.winfo_children():
            widget.destroy()

    def setup_pin_create_ui(self):
        """First-time setup UI"""
        self.clear_frame()
        ctk.CTkLabel(self.frame, text="Set Unlock PIN (min 6 characters)").pack(pady=10)
        pin_entry = ctk.CTkEntry(self.frame, textvariable=self.pin_var, show="*")
        pin_entry.pack()
        self.after(100, pin_entry.focus)

        ctk.CTkLabel(self.frame, text="Set Master Password").pack(pady=10)
        mp_entry = ctk.CTkEntry(self.frame, textvariable=self.master_var, show="*")
        mp_entry.pack()

        save_btn = ctk.CTkButton(self.frame, text="Save", command=self.save_master)
        save_btn.pack(pady=10)
        self.bind("<Return>", lambda e: self.save_master())
        self.reset_inactivity_timer()

    def setup_pin_unlock_ui(self):
        """Unlock UI for existing users"""
        self.clear_frame()
        ctk.CTkLabel(self.frame, text="Enter Unlock PIN").pack(pady=10)
        pin_entry = ctk.CTkEntry(self.frame, textvariable=self.pin_var, show="*")
        pin_entry.pack()
        self.after(100, pin_entry.focus)
        
        unlock_btn = ctk.CTkButton(self.frame, text="Unlock", command=self.unlock)
        unlock_btn.pack(pady=10)
        self.bind("<Return>", lambda e: self.unlock())
        self.reset_inactivity_timer()

    def save_master(self):
        """Save new master password setup"""
        pin = self.pin_var.get()
        if len(pin) < MIN_PIN_LENGTH:
            mb.showerror("Error", f"PIN must be at least {MIN_PIN_LENGTH} characters")
            return
            
        self.key = derive_key(pin)
        encrypt_master(self.master_var.get(), self.key)
        self.master_password = SecureString(self.master_var.get())
        self.master_var.set("")  # Clear plaintext
        self.setup_main_ui()

    def unlock(self):
        """Unlock with existing PIN"""
        try:
            pin = self.pin_var.get()
            self.key = derive_key(pin)
            decrypted = decrypt_master(self.key)
            self.master_password = SecureString(decrypted)
            self.setup_main_ui()
        except Exception:
            # Exit application completely on wrong PIN
            self.destroy()
            os._exit(1)

    def setup_main_ui(self):
        """Main application UI"""
        self.clear_frame()
        self.unbind("<Return>")
        self.reset_inactivity_timer()

        # Password generation section
        ctk.CTkLabel(self.frame, text="Identifier").pack(pady=5)
        ident_entry = ctk.CTkEntry(self.frame, textvariable=self.identifier_var)
        ident_entry.pack()
        ident_entry.focus()
        ident_entry.bind("<Key>", lambda e: self.reset_inactivity_timer())

        self.output_label = ctk.CTkLabel(self.frame, text="********", font=("Courier", 16))
        self.output_label.pack(pady=10)

        ctk.CTkCheckBox(self.frame, text="Show Password", variable=self.show_pw, 
                        command=self.toggle_pw).pack()
        generate_btn = ctk.CTkButton(self.frame, text="Generate/Copy Password", 
                                    command=self.generate_pw)
        generate_btn.pack(pady=10)
        generate_btn.bind("<Button-1>", lambda e: self.reset_inactivity_timer())

        self.bind("<Return>", lambda e: self.generate_pw())

        # Encryption tools section
        self.toggle_btn = ctk.CTkButton(self.frame, text="Show Encryption Tools", 
                                      command=self.toggle_encryption_section)
        self.toggle_btn.pack(pady=10)
        self.toggle_btn.bind("<Button-1>", lambda e: self.reset_inactivity_timer())

        # Encryption widgets container
        self.encryption_frame = ctk.CTkFrame(self.frame)

        self.textbox = ctk.CTkTextbox(self.encryption_frame, height=100)
        self.textbox.pack()
        self.textbox.bind("<Key>", lambda e: self.reset_inactivity_timer())

        ctk.CTkButton(self.encryption_frame, text="Encrypt", 
                     command=self.encrypt_text).pack(pady=5)
        ctk.CTkButton(self.encryption_frame, text="Decrypt", 
                     command=self.decrypt_text).pack(pady=5)
        self.output_box = ctk.CTkLabel(self.encryption_frame, text="", wraplength=400)
        self.output_box.pack(pady=10)

    def toggle_pw(self):
        """Toggle password visibility"""
        self.output_label.configure(
            text=self.generated_var.get() if self.show_pw.get() else "*" * len(self.generated_var.get())
        )
        self.reset_inactivity_timer()

    def generate_pw(self):
        """Generate and copy password to clipboard"""
        # Securely access master password
        master = self.master_password.get()
        pw = generate_password(master, self.identifier_var.get())
        self.generated_var.set(pw)
        self.toggle_pw()
        pyperclip.copy(pw)
        #mb.showinfo("Copied", "Password copied to clipboard!")
        # Clear temporary reference
        master = ""
        self.reset_inactivity_timer()

    def toggle_encryption_section(self):
        """Toggle encryption tools visibility"""
        if self.encryption_visible:
            self.encryption_frame.pack_forget()
            self.toggle_btn.configure(text="Show Encryption Tools")
        else:
            self.encryption_frame.pack(pady=10)
            self.toggle_btn.configure(text="Hide Encryption Tools")
        self.encryption_visible = not self.encryption_visible
        self.reset_inactivity_timer()

    def encrypt_text(self):
        """Encrypt text and copy to clipboard"""
        text = self.textbox.get("1.0", "end").strip()
        try:
            encrypted = Fernet(self.key).encrypt(text.encode()).decode()
            pyperclip.copy(encrypted)
            self.output_box.configure(text="Encrypted and Copied")
            #mb.showinfo("Encrypted", "Text encrypted and copied to clipboard!")
        except Exception as e:
            self.output_box.configure(text="Error: " + str(e))
        finally:
            self.reset_inactivity_timer()

    def decrypt_text(self):
        """Decrypt text and copy to clipboard"""
        text = self.textbox.get("1.0", "end").strip()
        try:
            decrypted = Fernet(self.key).decrypt(text.encode()).decode()
            pyperclip.copy(decrypted)
            self.output_box.configure(text="Decrypted and Copied")
            #mb.showinfo("Decrypted", "Text decrypted and copied to clipboard!")
        except Exception as e:
            self.output_box.configure(text="Error: " + str(e))
        finally:
            self.reset_inactivity_timer()

if __name__ == "__main__":
    app = App()
    app.mainloop()