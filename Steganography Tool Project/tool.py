"""
stego_tool_full.py
A single-file Tkinter Steganography tool with:
- AES-GCM (symmetric) using PBKDF2 passphrase
- RSA hybrid (RSA encrypts AES key; AES-GCM encrypts message)
- SHA-256 hashing option (non-reversible)
- Blowfish (symmetric) optional
- Auto-save to same folder (default) and "Overwrite original if PNG" option
- Capacity meter, progress bar, log records (file + Treeview)
- Logo loading, RSA key generation/loading
Requires: pillow, stegano, pycryptodome
"""

import os
import uuid
import struct
import base64
import time
import logging
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from stegano import lsb

# Crypto (PyCryptodome)
try:
    from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except Exception as e:
    raise ImportError("PyCryptodome is required. Install: pip install pycryptodome") from e

# ---------- Logging ----------
LOG_FILENAME = "stego_logs.txt"
logging.basicConfig(filename=LOG_FILENAME,
                    level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# ---------- Globals ----------
open_file = None          # currently opened image path
stego_obj = None          # returned by lsb.hide (object with .save())
logo_photo = None
log_summary = {}          # {filepath: {'enc':n, 'dec':m, 'last_action':str, 'last_time':ts}}

# defaults
AUTOSAVE_DEFAULT = True

# ---------- Crypto helpers ----------
# AES-GCM with PBKDF2
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LEN = 32
PBKDF2_ITER = 100_000

def aes_encrypt_b64(passphrase: str, plaintext: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITER)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    packed = salt + nonce + tag + ciphertext
    return base64.b64encode(packed).decode('utf-8')

def aes_decrypt_b64(passphrase: str, b64payload: str) -> str:
    packed = base64.b64decode(b64payload)
    salt = packed[:SALT_SIZE]
    nonce = packed[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    tag = packed[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
    ciphertext = packed[SALT_SIZE+NONCE_SIZE+16:]
    key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITER)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# Blowfish (CBC with simple padding) — note: not authenticated
def blowfish_encrypt_b64(passphrase: str, plaintext: str) -> str:
    # derive key from passphrase (use PBKDF2)
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITER)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    bs = Blowfish.block_size
    data = plaintext.encode('utf-8')
    pad_len = (bs - len(data) % bs)
    data += bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(data)
    packed = salt + iv + ciphertext
    return base64.b64encode(packed).decode('utf-8')

def blowfish_decrypt_b64(passphrase: str, b64payload: str) -> str:
    packed = base64.b64decode(b64payload)
    salt = packed[:SALT_SIZE]
    iv = packed[SALT_SIZE:SALT_SIZE+8]  # Blowfish iv size = block_size = 8
    ciphertext = packed[SALT_SIZE+8:]
    key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITER)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    data = cipher.decrypt(ciphertext)
    pad_len = data[-1]
    return data[:-pad_len].decode('utf-8')

# RSA hybrid
# Pack format: b'RSA' + 2-byte big endian len_of_enc_key + enc_key + nonce(12) + tag(16) + ciphertext
def rsa_hybrid_encrypt_b64(public_key_pem: bytes, plaintext: str) -> str:
    pub = RSA.import_key(public_key_pem)
    rsa_cipher = PKCS1_OAEP.new(pub)
    # generate random AES key
    aes_key = get_random_bytes(KEY_LEN)
    # AES-GCM encrypt plaintext with aes_key
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    # encrypt aes_key with RSA pub
    enc_key = rsa_cipher.encrypt(aes_key)
    packed = b'RSA' + struct.pack(">H", len(enc_key)) + enc_key + nonce + tag + ciphertext
    return base64.b64encode(packed).decode('utf-8')

def rsa_hybrid_decrypt_b64(private_key_pem: bytes, b64payload: str) -> str:
    packed = base64.b64decode(b64payload)
    if not packed.startswith(b'RSA'):
        raise ValueError("Not RSA hybrid payload")
    offset = 3
    enc_key_len = struct.unpack(">H", packed[offset:offset+2])[0]; offset += 2
    enc_key = packed[offset:offset+enc_key_len]; offset += enc_key_len
    nonce = packed[offset:offset+NONCE_SIZE]; offset += NONCE_SIZE
    tag = packed[offset:offset+16]; offset += 16
    ciphertext = packed[offset:]
    priv = RSA.import_key(private_key_pem)
    rsa_cipher = PKCS1_OAEP.new(priv)
    aes_key = rsa_cipher.decrypt(enc_key)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# SHA-256 hashing
def sha256_hex(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()

# ---------- Image capacity helpers ----------
def estimate_capacity_bytes(pil_image: Image.Image) -> int:
    # Using 1 LSB per channel -> w*h*3 bits => //8 bytes
    w, h = pil_image.convert('RGB').size
    return (w * h * 3) // 8

def convert_to_temp_png_and_get_path(src_path: str) -> str:
    img = Image.open(src_path)
    # If animated GIF, use first frame
    if getattr(img, "is_animated", False) or getattr(img, "n_frames", 1) > 1:
        img.seek(0)
    rgb = img.convert('RGBA')
    folder = os.path.dirname(src_path) or os.getcwd()
    base = os.path.splitext(os.path.basename(src_path))[0]
    temp_name = f"{base}_tmp_{uuid.uuid4().hex[:8]}.png"
    temp_path = os.path.join(folder, temp_name)
    rgb.save(temp_path, format='PNG')
    return temp_path

# ---------- GUI ----------
win = tk.Tk()
win.geometry('980x640')
win.title("Steganography Tool By SAM")
win.config(bg='#0f1114')

# ---- UI elements ----
# header: logo + title + load logo
logo_photo = None
def load_logo_action():
    global logo_photo
    p = filedialog.askopenfilename(title="Select Logo", filetypes=(("image", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"),))
    if not p:
        return
    try:
        im = Image.open(p)
        im.thumbnail((140, 56))
        logo_photo = ImageTk.PhotoImage(im)
        logo_lbl.config(image=logo_photo)
        logo_lbl.image = logo_photo
    except Exception as e:
        messagebox.showerror("Logo error", str(e))

logo_lbl = tk.Label(win, bg='#0f1114')
logo_lbl.place(x=16, y=10, width=140, height=56)
tk.Button(win, text="Load Logo", command=load_logo_action, bg='#263238', fg='white', bd=0, cursor='hand2').place(x=170,y=26)
title_lbl = tk.Label(win, text="Steganography Tool By SAM", font=('Segoe UI', 20, 'bold'), bg='#0f1114', fg='#00c853')
title_lbl.place(x=280, y=18)

# left: preview
preview_lbl = tk.Label(win, bg='#1a1c20')
preview_lbl.place(x=20, y=90, width=380, height=300)

# center: text
text_frame = tk.Frame(win, bg='#0f1114')
text_frame.place(x=420, y=90, width=380, height=300)
text_area = tk.Text(text_frame, font=('Segoe UI', 12), wrap=tk.WORD, bg='#121417', fg='white', insertbackground='white')
text_area.pack(fill='both', expand=True)

# right: controls + logs
controls_frame = tk.Frame(win, bg='#0f1114')
controls_frame.place(x=820, y=90, width=140, height=420)

# Algorithm selector
tk.Label(controls_frame, text="Algorithm", bg='#0f1114', fg='white').pack(pady=(8,2))
algo_var = tk.StringVar(value="AES")
algo_box = ttk.Combobox(controls_frame, textvariable=algo_var, values=("AES", "RSA (hybrid)", "SHA-256", "Blowfish"), state='readonly', width=15)
algo_box.pack()

# RSA keys info
rsa_pub_path_var = tk.StringVar(value="")
rsa_priv_path_var = tk.StringVar(value="")

def generate_rsa_keys():
    bits = 2048
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    folder = filedialog.askdirectory(title="Select folder to save RSA keypair (choose folder)")
    if not folder:
        return
    priv_path = os.path.join(folder, "rsa_private.pem")
    pub_path = os.path.join(folder, "rsa_public.pem")
    with open(priv_path, "wb") as f:
        f.write(priv)
    with open(pub_path, "wb") as f:
        f.write(pub)
    rsa_pub_path_var.set(pub_path)
    rsa_priv_path_var.set(priv_path)
    messagebox.showinfo("RSA keys", f"Saved:\n{priv_path}\n{pub_path}")

def load_rsa_pub():
    p = filedialog.askopenfilename(title="Select RSA public key (.pem)", filetypes=(("PEM", "*.pem"),("All files","*.*")))
    if p:
        rsa_pub_path_var.set(p)

def load_rsa_priv():
    p = filedialog.askopenfilename(title="Select RSA private key (.pem)", filetypes=(("PEM", "*.pem"),("All files","*.*")))
    if p:
        rsa_priv_path_var.set(p)

tk.Button(controls_frame, text="Gen RSA keypair", command=generate_rsa_keys, width=16).pack(pady=4)
tk.Button(controls_frame, text="Load RSA public", command=load_rsa_pub, width=16).pack(pady=2)
tk.Button(controls_frame, text="Load RSA private", command=load_rsa_priv, width=16).pack(pady=2)
tk.Label(controls_frame, textvariable=rsa_pub_path_var, bg='#0f1114', fg='#bdbdbd', wraplength=130).pack(pady=(4,0))
tk.Label(controls_frame, textvariable=rsa_priv_path_var, bg='#0f1114', fg='#bdbdbd', wraplength=130).pack()

# passphrase/secret key
tk.Label(controls_frame, text="Passphrase:", bg='#0f1114', fg='white').pack(pady=(8,2))
key_var = tk.StringVar()
tk.Entry(controls_frame, textvariable=key_var, show='*', width=18).pack()

# Overwrite option
overwrite_var = tk.BooleanVar(value=False)
tk.Checkbutton(controls_frame, text="Overwrite original if PNG", variable=overwrite_var, bg='#0f1114', fg='white').pack(pady=(8,0))

# autosave note (always ON)
tk.Label(controls_frame, text="Autosave: ON (saves to same folder)", bg='#0f1114', fg='#bdbdbd', wraplength=130).pack(pady=(6,8))

# Buttons bottom center
def open_image_action():
    global open_file
    path = filedialog.askopenfilename(title="Open Image",
        filetypes=(("Images","*.png;*.jpg;*.jpeg;*.bmp;*.tiff;*.gif"),("All files","*.*")))
    if not path:
        return
    try:
        im = Image.open(path)
        if getattr(im, "is_animated", False) or getattr(im, "n_frames", 1) > 1:
            res = messagebox.askyesno("Animated", "Animated image detected. Use first frame only?")
            if not res:
                return
            im.seek(0)
        preview = im.copy()
        preview.thumbnail((380,300))
        photo = ImageTk.PhotoImage(preview)
        preview_lbl.config(image=photo)
        preview_lbl.image = photo
        open_file = path
        # capacity
        tmp = convert_to_temp_png_and_get_path(path)
        cap = estimate_capacity_bytes(Image.open(tmp))
        try:
            os.remove(tmp)
        except:
            pass
        capacity_var.set(f"Capacity: {cap} bytes")
        status_var.set(f"Opened: {os.path.basename(open_file)}")
    except Exception as e:
        messagebox.showerror("Open error", str(e))
        open_file = None

def hide_action():
    global stego_obj, open_file
    if not open_file:
        messagebox.showerror("Error", "Open an image first")
        return
    alg = algo_var.get()
    payload_text = text_area.get(1.0, tk.END).rstrip("\n")
    if alg == "SHA-256":
        if not payload_text:
            messagebox.showerror("Error", "Enter message to hash and hide")
            return
        payload = sha256_hex(payload_text)
    elif alg == "AES":
        passphrase = key_var.get().strip()
        if not passphrase:
            messagebox.showerror("Error", "Enter passphrase for AES")
            return
        payload = aes_encrypt_b64(passphrase, payload_text)
    elif alg == "Blowfish":
        passphrase = key_var.get().strip()
        if not passphrase:
            messagebox.showerror("Error", "Enter passphrase for Blowfish")
            return
        payload = blowfish_encrypt_b64(passphrase, payload_text)
    elif alg == "RSA (hybrid)":
        # need public key
        pubpath = rsa_pub_path_var.get()
        if not pubpath:
            messagebox.showerror("Error", "Load RSA public key first")
            return
        with open(pubpath, "rb") as f:
            pubpem = f.read()
        payload = rsa_hybrid_encrypt_b64(pubpem, payload_text)
    else:
        messagebox.showerror("Error", "Unknown algorithm")
        return

    # Convert to PNG temp, check capacity (payload bytes)
    try:
        tmp = convert_to_temp_png_and_get_path(open_file)
        cap = estimate_capacity_bytes(Image.open(tmp))
        payload_size = len(payload.encode('utf-8'))
        if payload_size > cap:
            os.remove(tmp)
            messagebox.showerror("Too large", f"Payload {payload_size} bytes > capacity {cap} bytes")
            return
        # progress simulate: fill proportionally
        frac = int((payload_size / cap) * 100)
        progress['value'] = max(5, frac//4)  # initial bump
        win.update_idletasks()

        # hide using stegano
        stego_obj = lsb.hide(tmp, payload)
        # save automatically to same folder:
        folder = os.path.dirname(open_file) or os.getcwd()
        base = os.path.splitext(os.path.basename(open_file))[0]
        suggested = os.path.join(folder, f"{base}_stego.png")
        # Overwrite original if PNG and option checked
        if overwrite_var.get() and os.path.splitext(open_file)[1].lower() == ".png":
            save_path = open_file
        else:
            save_path = suggested
        stego_obj.save(save_path)
        # cleanup tmp
        try: os.remove(tmp)
        except: pass

        # update progress fully
        progress['value'] = 100
        win.update_idletasks()

        # Logging + Treeview update
        record_action(open_file, "Encrypt/Hide", len(payload.encode('utf-8')))
        status_var.set(f"Hidden & saved: {os.path.basename(save_path)}")
        messagebox.showinfo("Done", f"Hidden & saved: {save_path}")
    except Exception as e:
        messagebox.showerror("Hide error", str(e))
        try: os.remove(tmp)
        except: pass

def show_action():
    global open_file
    if not open_file:
        messagebox.showerror("Error", "Open the stego image first")
        return
    alg = algo_var.get()
    try:
        revealed = lsb.reveal(open_file)
        if revealed is None:
            messagebox.showinfo("No message", "No hidden message found")
            return
        # now reverse based on algorithm
        if alg == "SHA-256":
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, revealed)
        elif alg == "AES":
            passphrase = key_var.get().strip()
            if not passphrase:
                messagebox.showerror("Error", "Enter passphrase to decrypt AES")
                return
            dg = aes_decrypt_b64(passphrase, revealed)
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, dg)
        elif alg == "Blowfish":
            passphrase = key_var.get().strip()
            if not passphrase:
                messagebox.showerror("Error", "Enter passphrase to decrypt Blowfish")
                return
            dg = blowfish_decrypt_b64(passphrase, revealed)
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, dg)
        elif alg == "RSA (hybrid)":
            privpath = rsa_priv_path_var.get()
            if not privpath:
                messagebox.showerror("Error", "Load RSA private key for decryption")
                return
            with open(privpath, "rb") as f:
                privpem = f.read()
            dg = rsa_hybrid_decrypt_b64(privpem, revealed)
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, dg)
        else:
            messagebox.showerror("Error", "Unknown algorithm")
            return
        record_action(open_file, "Decrypt/Reveal", len(revealed.encode('utf-8')))
        status_var.set(f"Revealed from: {os.path.basename(open_file)}")
        messagebox.showinfo("Done", "Message revealed (see text area)")
    except Exception as e:
        messagebox.showerror("Reveal error", str(e))

# Buttons
btn_cfg = {"font": ('Segoe UI', 11, 'bold'), "width": 18, "height": 1, "bd": 0, "cursor": "hand2"}
tk.Button(win, text="Open Image", bg='#2979ff', fg='white', command=open_image_action, **btn_cfg).place(x=120, y=410)
tk.Button(win, text="Hide (Encrypt+Hide)", bg='#d50000', fg='white', command=hide_action, **btn_cfg).place(x=340, y=410)
tk.Button(win, text="Show (Reveal+Decrypt)", bg='#ff9100', fg='white', command=show_action, **btn_cfg).place(x=560, y=410)

# progress & capacity
progress = ttk.Progressbar(win, length=540, mode="determinate")
progress.place(x=120, y=460)
capacity_var = tk.StringVar(value="Capacity: N/A")
tk.Label(win, textvariable=capacity_var, bg='#0f1114', fg='white').place(x=120, y=490)

# status
status_var = tk.StringVar(value="No file opened")
tk.Label(win, textvariable=status_var, bg='#0f1114', fg='white').place(x=20, y=600)

# ----- Log records (Treeview on bottom-right) -----
tv_frame = tk.Frame(win, bg='#0f1114')
tv_frame.place(x=420, y=500, width=540, height=120)
tk.Label(tv_frame, text="Log Records (image -> enc_count / dec_count / last action / time)", bg='#0f1114', fg='white').pack(anchor='w')
cols = ("file", "enc", "dec", "last", "time")
tree = ttk.Treeview(tv_frame, columns=cols, show='headings', height=4)
for c in cols:
    tree.heading(c, text=c)
tree.column("file", width=200)
tree.column("enc", width=60)
tree.column("dec", width=60)
tree.column("last", width=120)
tree.column("time", width=120)
tree.pack(fill='both', expand=True)

def record_action(filepath: str, action: str, payload_size:int=0):
    # update log_summary dict and file
    fname = os.path.abspath(filepath)
    entry = log_summary.get(fname, {"enc":0,"dec":0,"last_action":"-","last_time":"-"})
    if action.lower().startswith("encrypt") or action.lower().startswith("hide"):
        entry["enc"] += 1
    elif action.lower().startswith("decrypt") or action.lower().startswith("reveal"):
        entry["dec"] += 1
    entry["last_action"] = action
    entry["last_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    log_summary[fname] = entry
    # write to log file
    logging.info(f"{action} -> {fname} | payload_bytes={payload_size}")
    refresh_treeview()

def refresh_treeview():
    # clear
    for r in tree.get_children():
        tree.delete(r)
    for fpath, v in log_summary.items():
        tree.insert("", "end", values=(os.path.basename(fpath), v["enc"], v["dec"], v["last_action"], v["last_time"]))

# show existing log file summary (if exists) — quick parse for counts (best-effort)
def load_existing_log_summary():
    if not os.path.exists(LOG_FILENAME):
        return
    try:
        with open(LOG_FILENAME, "r", encoding="utf-8") as f:
            for line in f:
                # best-effort parse: look for "Encrypt/Hide" or "Decrypt/Reveal" and filename
                if "Encrypt/Hide" in line or "Encrypt/Hide" in line or "Encrypt" in line:
                    parts = line.strip().split("->")
                    if len(parts) >= 2:
                        fname = parts[1].split("|")[0].strip()
                        fname = fname
                        rec = log_summary.get(fname, {"enc":0,"dec":0,"last_action":"-","last_time":"-"})
                        rec["enc"] += 1
                        rec["last_action"] = "Encrypt/Hide"
                        rec["last_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_summary[fname] = rec
                elif "Decrypt/Reveal" in line or "Decrypt" in line or "Reveal" in line:
                    parts = line.strip().split("->")
                    if len(parts) >= 2:
                        fname = parts[1].split("|")[0].strip()
                        rec = log_summary.get(fname, {"enc":0,"dec":0,"last_action":"-","last_time":"-"})
                        rec["dec"] += 1
                        rec["last_action"] = "Decrypt/Reveal"
                        rec["last_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_summary[fname] = rec
    except:
        pass
    refresh_treeview()

# bootstrap load existing logs if any
load_existing_log_summary()

# ---------- Limitations note ----------
note = (
    "Notes: Input images: PNG, JPEG, BMP, TIFF, static GIF supported. Animated GIFs use first frame.\n"
    "PDFs are not supported directly. Hiding is done inside a PNG (lossless). Payload size must fit image capacity.\n"
    "RSA uses hybrid mode; generate and load RSA keys to use RSA encryption.\n"
    "Use 'Overwrite original if PNG' carefully — it replaces the original PNG file."
)
tk.Label(win, text=note, bg='#0f1114', fg='#bdbdbd', justify='left', wraplength=940).place(x=20, y=520)

win.mainloop()
