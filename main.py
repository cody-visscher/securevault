import customtkinter as ctk
from tkinter import messagebox as mb
from hashlib import sha256
from encrypt import encrypt
from decrypt import decrypt
import os

class PassStore:
    def __init__ (self, password):
        self.password = password

def add_user():
    add_frame = ctk.CTkFrame(root)

    def close():
        password = pass1_entry.get()
        verify = pass2_entry.get()
        if password == verify and len(password) > 7:
            os.mkdir(f'C:\\users\\{user}\\SecureVault')
            file=open(f'c:\\users\\{user}\\SecureVault\\passhash.sha', 'wb')
            contents = sha256(password.encode()).digest()
            file.write(contents)
            file.close()
            add_frame.destroy()
            login()
        else:
            incorrect = ctk.CTkLabel(add_frame, text="Passwords Do Not Match", font=("Arial", 10), text_color='red')
            incorrect.pack(pady=10)
    def exit():
        root.destroy()

    label = ctk.CTkLabel(add_frame, text="Create Password", font=("Arial", 25))
    pass1_entry = ctk.CTkEntry(add_frame, width=280, height=56, placeholder_text="Enter Password", show="*")
    pass2_entry = ctk.CTkEntry(add_frame, width=280, height=56, placeholder_text="Verify Password", show="*")
    confirm_button = ctk.CTkButton(add_frame, text='Confirm', command=close)
    cancel_button = ctk.CTkButton(add_frame, text="Cancel", command=exit)
    label.pack(pady=10)
    pass1_entry.pack(pady=10)
    pass2_entry.pack(pady=10)
    confirm_button.pack(pady=10)
    cancel_button.pack(pady=10)
    add_frame.pack(padx=10, pady=20, fill='both')

def login():
    login_frame = ctk.CTkFrame(root)

    def close():
        file = open(f'C:\\users\\{user}\\SecureVault\\passhash.sha', 'rb')
        passhash = file.read()
        password = pass_entry.get().encode()
        passwordobj.password = password
        if sha256(password).digest() == passhash:
            app_frame = ctk.CTkFrame(root)
    
            def encrypt_files():
                filestoencrypt = ctk.filedialog.askopenfilenames(initialdir="C:\\")
                filenames=[i.split('/')[-1] for i in filestoencrypt]
                for i in range(len(filestoencrypt)):
                    if filestoencrypt[i][-5:] == '.cody':
                        mb.showerror("Cody's Secure Vault", f"{filestoencrypt[i]} is already in encrypted format.")
                    else:
                        newpath = f"C:\\users\\{user}\\SecureVault\\{filenames[i]}.cody"
                        contents = encrypt(filestoencrypt[i], password)
                        file = open(newpath, 'wb')
                        file.write(contents)
                        file.close()
                        file = open(filestoencrypt[i], 'wb')
                        file.write(bytes(len(contents)))
                        file.close()
                        os.remove(filestoencrypt[i])

            def decrypt_files():
                filestodecrypt = ctk.filedialog.askopenfilenames(initialdir=f"C:\\users\\{user}\\SecureVault")
                for i in filestodecrypt:
                    if i[-5:] != '.cody':
                        mb.showerror("Cody's Secure Vault", f"{i} is not in encrypted format.")
                    else:
                        contents = decrypt(i, password)
                        file = open(i, 'wb')
                        file.write(contents)
                        file.close()
                        os.rename(i, i[:-5])
                        decrypted_files.append(i[:-5])

            label = ctk.CTkLabel(app_frame, text="Choose Operation", font=("Arial", 25))
            encrypt_button = ctk.CTkButton(app_frame, text='Encrypt Files', command=encrypt_files)
            decrypt_button = ctk.CTkButton(app_frame, text='Decrypt Files', command=decrypt_files)
            label.pack(pady=20)
            encrypt_button.pack(pady=10)
            decrypt_button.pack(pady=10)
            app_frame.pack(pady=20, padx=40)
            login_frame.destroy()
        else:
            incorrect = ctk.CTkLabel(login_frame, text="Incorrect Password", font=("Arial",10), text_color='red')
            incorrect.pack(pady=10)

    def exit():
        root.destroy()

    label = ctk.CTkLabel(login_frame, text='Login', font=("Arial", 25))
    pass_entry = ctk.CTkEntry(login_frame, width=280, height=56, placeholder_text="Enter Password", show="*")
    login_button = ctk.CTkButton(login_frame, text="Login", command=close)
    cancel_button = ctk.CTkButton(login_frame, text="Cancel", command=exit)
    label.pack(pady=10)
    pass_entry.pack(pady=10)
    login_button.pack(pady=10)
    cancel_button.pack(pady=10)
    login_frame.pack(padx=10, pady=20)

passwordobj = PassStore(None)
ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('blue')
decrypted_files = []
root = ctk.CTk()
root.title("Cody's Secure Vault")
root.geometry('400x400')
user = os.getlogin()
path = f'C:\\users\\{user}\\SecureVault'
check_file = os.path.exists(path)
if not check_file:
    add_user()
else:
    login()
root.mainloop()
for i in range(len(decrypted_files)):
    if os.path.exists(decrypted_files[i]):
        newpath = f"C:\\users\\{user}\\SecureVault\\{decrypted_files[i].split('/')[-1]}.cody"
        contents = encrypt(decrypted_files[i], passwordobj.password)
        file = open(newpath, 'wb')
        file.write(contents)
        file.close()
        file = open(decrypted_files[i], 'wb')
        file.write(bytes(len(contents)))
        file.close()
        os.remove(decrypted_files[i])