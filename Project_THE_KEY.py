import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import os
import hashlib

# --- CONSTANTS AND STYLING ---
BG_COLOR = "#1A1A1A"          # Dark gray/Off-black (Matrix Aesthetic)
FG_COLOR = "#98FB98"        # Bright Lime Green (Improved Readability)
ACCENT_COLOR = "#32CD32"    # Medium Green (Button Base)
ERROR_COLOR = "#FF4136"

# Global dictionary to hold image references (CRITICAL for Tkinter Image Preview)
global_image_refs = {}

# --- CORE ENCRYPTION & DECRYPTION FUNCTIONS ---

# VIGENERE CIPHER (Text)
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    plaintext = "".join(filter(str.isalpha, plaintext.upper()))
    ciphertext = ""
    key_index = 0
    if not plaintext or not key: return "Error: Message and Key cannot be empty."
    for char in plaintext:
        plain_val = ord(char) - ord('A')
        key_val = ord(key[key_index % len(key)]) - ord('A')
        encrypted_val = (plain_val + key_val) % 26
        ciphertext += chr(encrypted_val + ord('A'))
        key_index += 1
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    ciphertext = "".join(filter(str.isalpha, ciphertext.upper()))
    decrypted_text = ""
    key_index = 0
    if not ciphertext or not key: return "Error: Encrypted text and Key cannot be empty."
    
    for char in ciphertext:
        cipher_val = ord(char) - ord('A')
        key_val = ord(key[key_index % len(key)]) - ord('A')
        decrypted_val = (cipher_val - key_val) % 26
        decrypted_text += chr(decrypted_val + ord('A'))
        key_index += 1
        
    return decrypted_text

# MORSE CODE (Text/Visual)
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 
    'Z': '--..',
    ' ': ' / '
}
DECODE_MORSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

def morse_encrypt(message):
    message = message.upper()
    morse_sequence = []
    for char in message:
        if char in MORSE_CODE_DICT:
            morse_sequence.append(MORSE_CODE_DICT[char])
        elif char.isalpha() or char.isdigit():
            pass
    return ' '.join(morse_sequence)

def morse_decrypt(morse_sequence):
    morse_sequence = morse_sequence.strip()
    code_elements = morse_sequence.split(' ')
    decoded_message = []
    for code in code_elements:
        if code == '/':
            decoded_message.append(' ')
        elif code in DECODE_MORSE_DICT:
            decoded_message.append(DECODE_MORSE_DICT[code])
    return ''.join(decoded_message)

# LSB STEGANOGRAPHY (Image)
def text_to_binary(text):
    binary_string = ''.join(format(ord(char), '08b') for char in text)
    binary_string += '1111111111111110'
    return binary_string

def binary_to_text(binary_string):
    text = "".join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8) if len(binary_string[i:i+8]) == 8)
    return text

def hide_message_in_image(image_path, message, output_path):
    try:
        img = Image.open(image_path).convert("RGB")
        width, height = img.size
        binary_message = text_to_binary(message)
        message_length = len(binary_message)
        if (width * height * 3) < message_length:
             return f"Error: Image is too small. Needed {message_length} bits."
        message_index = 0
        for row in range(height):
            for col in range(width):
                if message_index < message_length:
                    pixel = list(img.getpixel((col, row)))
                    for i in range(3):
                        if message_index < message_length:
                            channel_value = pixel[i]
                            channel_value = channel_value & 0b11111110
                            channel_value = channel_value | int(binary_message[message_index])
                            pixel[i] = channel_value
                            message_index += 1
                    img.putpixel((col, row), tuple(pixel))
                else:
                    img.save(output_path)
                    return f"SUCCESS! Image saved to: {os.path.basename(output_path)}"

        img.save(output_path)
        return f"SUCCESS! Image saved to: {os.path.basename(output_path)}"
    except FileNotFoundError: return f"Error: Image file not found at '{image_path}'"
    except Exception as e: return f"An error occurred: {e}"

def extract_image_message(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        binary_message_bits = ""
        delimiter = '1111111111111110'
        for row in range(img.height):
            for col in range(img.width):
                pixel = list(img.getpixel((col, row)))
                for i in range(3):
                    binary_message_bits += str(pixel[i] & 1)
                    if delimiter in binary_message_bits:
                        message_end_index = binary_message_bits.find(delimiter)
                        final_binary_message = binary_message_bits[:message_end_index]
                        return binary_to_text(final_binary_message)
        return "Error: Delimiter not found. No message extracted."
    except FileNotFoundError: return f"Error: Image file not found at '{image_path}'"
    except Exception as e: return f"An error occurred: {e}"

# DIGITAL FINGERPRINT (SHA-256)
def calculate_sha256(filepath):
    if not os.path.exists(filepath): return "File Not Found"
    
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while True:
            chunk = file.read(4096)
            if not chunk: break
            hasher.update(chunk)
    return hasher.hexdigest()

# --- UTILITY: RESULT DISPLAY (Unchanged) ---
def show_result_box(title, message, is_reveal=False):
    result_window = tk.Toplevel(root)
    result_window.title(title)
    bg_color = '#F0FFF0' if is_reveal else '#FFFFFF'
    result_window.configure(bg=bg_color)
    tk.Label(result_window, text=title, font=("Helvetica", 14, "bold"), bg=bg_color).pack(padx=10, pady=5)
    output_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, width=50, height=10, font=("Courier", 10))
    output_text.pack(padx=10, pady=10)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, message)
    output_text.config(state=tk.DISABLED)
    result_window.update_idletasks()
    width = result_window.winfo_width()
    height = result_window.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    result_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    tk.Button(result_window, text="Close", command=result_window.destroy).pack(pady=5)

# --- VIEW DEFINITIONS ---

def setup_common_frame(parent_tab, title):
    frame = tk.Frame(parent_tab, bg=BG_COLOR)
    frame.pack(fill='both', expand=True, padx=20, pady=20)
    tk.Label(frame, text=title, font=("Helvetica", 14, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=10)
    return frame

def setup_text_ciphers(notebook):
    tab = ttk.Frame(notebook, style='Dark.TFrame')
    notebook.add(tab, text='1. Text Ciphers')
    
    # Vigenère Encryption
    frame_encrypt = tk.Frame(tab, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_encrypt.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_encrypt, text="Vigenère Encryption", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    
    tk.Label(frame_encrypt, text="Plaintext:", fg=FG_COLOR, bg=BG_COLOR).pack(pady=2)
    msg_entry = ttk.Entry(frame_encrypt, width=40); msg_entry.pack()
    
    tk.Label(frame_encrypt, text="Key:", fg=FG_COLOR, bg=BG_COLOR).pack(pady=2)
    key_entry = ttk.Entry(frame_encrypt, width=40); key_entry.pack()
    
    def execute_encrypt():
        result = vigenere_encrypt(msg_entry.get(), key_entry.get())
        show_result_box("Encryption Result", f"Encrypted Ciphertext:\n\n{result}")
    ttk.Button(frame_encrypt, text="ENCRYPT", command=execute_encrypt, style='Green.TButton').pack(pady=10)

    # Vigenère Decryption (Step 1 of Puzzle)
    frame_decrypt = tk.Frame(tab, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_decrypt.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_decrypt, text="Vigenère Decryption", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    
    tk.Label(frame_decrypt, text="Ciphertext:", fg=FG_COLOR, bg=BG_COLOR).pack(pady=2)
    cipher_entry = ttk.Entry(frame_decrypt, width=40); cipher_entry.pack()
    
    tk.Label(frame_decrypt, text="Key:", fg=FG_COLOR, bg=BG_COLOR).pack(pady=2)
    key_entry_d = ttk.Entry(frame_decrypt, width=40); key_entry_d.pack()
    
    def execute_decrypt():
        result = vigenere_decrypt(cipher_entry.get(), key_entry_d.get())
        
        # Check for the specific video reveals
        if result == "THEKEYFORAUDIOFILEISINTHEIMAGEJOURNEYPNG":
            display_msg = (
                f"*** PUZZLE STEP 1 COMPLETE ***\n\n"
                f"Decrypted Instruction:\n\nTHE KEY FOR AUDIO FILE IS IN THE IMAGE JOURNEY.PNG\n\n"
                f"--- Proceed to Multimedia Stego to continue the mission. ---"
            )
            show_result_box("Vigenère Decryption Result", display_msg, is_reveal=True)
        elif result in ["JUSTICEISNOTFORSALE", "SECRECYISAWEAPON"]:
             display_msg = (
                f"*** PROJECT REVEALED: COVERT MESSAGE ***\n\n"
                f"Decrypted Code (No Spaces):\n{result}\n\n"
                f"The message hidden in the video is revealed!"
            )
             show_result_box("Vigenère Decryption Result", display_msg, is_reveal=True)
        else:
            show_result_box("Vigenère Decryption Result", f"Decrypted Message:\n{result}")
            
    ttk.Button(frame_decrypt, text="DECRYPT TEXT", command=execute_decrypt, style='Green.TButton').pack(pady=10)

    # Morse Code Encoder/Decoder - (Unchanged)
    frame_morse = tk.Frame(tab, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_morse.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_morse, text="Morse Code Encoder/Decoder", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    morse_entry = ttk.Entry(frame_morse, width=50); morse_entry.pack(pady=5)
    def execute_morse_enc_dec():
        input_text = morse_entry.get()
        if not input_text: return messagebox.showwarning("Input Error", "Please enter text or Morse code.")
        
        if any(c in input_text for c in '.-'):
            result = morse_decrypt(input_text)
            show_result_box("Morse Decryption Result", f"Input: {input_text}\n\nDecoded Message:\n{result}")
        else:
            result = morse_encrypt(input_text)
            show_result_box("Morse Encoding Result", f"Input: {input_text}\n\nEncoded Morse:\n{result}")
    ttk.Button(frame_morse, text="ENCODE / DECODE MORSE", command=execute_morse_enc_dec, style='Green.TButton').pack(pady=10)


def setup_multimedia_stego(notebook):
    tab = ttk.Frame(notebook, style='Dark.TFrame')
    notebook.add(tab, text='2. Multimedia Stego')
    
    # Placeholder for the central image preview (Top Half)
    preview_frame = tk.Frame(tab, bg=BG_COLOR); preview_frame.pack(pady=10, padx=10, fill='x')
    
    # Image Preview Area Label
    image_preview_label = tk.Label(preview_frame, bg=BG_COLOR, text="Image Preview Area (150x150)", fg="gray", width=25, height=10, relief=tk.RIDGE, bd=1)
    image_preview_label.pack(pady=5, anchor='center')

    # LSB STEGANOGRAPHY (Image) (Bottom Half)
    frame_image_stego = tk.Frame(tab, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_image_stego.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_image_stego, text="Image Stego (Hide/Reveal)", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    
    img_path_var = tk.StringVar(value="Select Image File..."); 
    
    tk.Label(frame_image_stego, text="Message to Hide:", fg=FG_COLOR, bg=BG_COLOR).pack(pady=2)
    img_msg_entry = ttk.Entry(frame_image_stego, width=40); img_msg_entry.pack(pady=5)
    
    # Function to update image preview
    def update_image_preview(filepath):
        try:
            original_image = Image.open(filepath)
            original_image.thumbnail((150, 150), Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(original_image)
            
            # CRITICAL: Keep a reference!
            global_image_refs['preview'] = photo 
            
            image_preview_label.config(image=photo, text="", width=150, height=150)
            image_preview_label.image = photo 
            
        except Exception:
            image_preview_label.config(image='', text="Could not load preview", fg=ERROR_COLOR, width=25, height=10)
            global_image_refs.pop('preview', None)

    def select_image_stego_file():
        filepath = filedialog.askopenfilename(title="Select Image File", filetypes=(("PNG files", "*.png"), ("All files", "*.*")))
        if filepath:
            img_path_var.set(filepath)
            update_image_preview(filepath)
    
    def execute_encrypt_image():
        output_filepath = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")], title="Save Encrypted Image As")
        if output_filepath:
            result = hide_message_in_image(img_path_var.get(), img_msg_entry.get(), output_filepath)
            messagebox.showinfo("Encryption Result", result)
    
    def execute_decrypt_image_stego():
        result = extract_image_message(img_path_var.get())
        if result == "AU2440128":
            display_msg = (
                f"*** PUZZLE STEP 2 COMPLETE ***\n\n"
                f"Extracted Secret Code:\n\n{result}\n\n"
                f"--- This code is the PASSWORD to unlock the final song file. ---"
            )
            show_result_box("Image Extraction Result", display_msg, is_reveal=True)
        elif not result.startswith("Error"):
             show_result_box("Image Extraction Result", f"*** PROJECT REVEALED ***\n\nExtracted Message:\n{result}", is_reveal=True)
        else: messagebox.showerror("Extraction Failed", result)

    ttk.Button(frame_image_stego, text="Select Image File", command=select_image_stego_file, style='Green.TButton').pack(pady=5)
    tk.Label(frame_image_stego, textvariable=img_path_var, wraplength=350, fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    
    btn_frame = tk.Frame(frame_image_stego, bg=BG_COLOR); btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text="ENCRYPT IMAGE", command=execute_encrypt_image, style='Green.TButton').pack(side='left', padx=5)
    ttk.Button(btn_frame, text="DECRYPT IMAGE", command=execute_decrypt_image_stego, style='Green.TButton').pack(side='left', padx=5)


def setup_digital_forensics(notebook):
    tab = ttk.Frame(notebook, style='Dark.TFrame')
    notebook.add(tab, text='3. Digital Forensics')
    
    frame_hash = setup_common_frame(tab, "SHA-256 Digital Fingerprint Checker")
    
    tk.Label(frame_hash, text="Verify file integrity and detect tampering. This proves that even invisible changes (like steganography) alter the file's unique 'fingerprint'.", wraplength=500, font=("Helvetica", 11), fg='gray', bg=BG_COLOR).pack(pady=10)
    
    # HASH CALCULATOR
    frame_calc = tk.Frame(frame_hash, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_calc.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_calc, text="Calculate SHA-256 Hash", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)

    file_path_var = tk.StringVar(value="Select File to Hash...")
    
    def select_file():
        filepath = filedialog.askopenfilename(title="Select File (Image/Audio/Any)")
        if filepath: file_path_var.set(filepath)
            
    def execute_hash():
        filepath = file_path_var.get()
        hash_value = calculate_sha256(filepath)
        
        result_message = (
            f"File: {os.path.basename(filepath)}\n\n"
            f"SHA-256 HASH (Digital Fingerprint):\n{hash_value}\n\n"
            f"Note: Any modification, even invisible, will completely change this hash."
        )
        show_result_box("SHA-256 Hash Result", result_message)

    ttk.Button(frame_calc, text="Select File", command=select_file, style='Green.TButton').pack(pady=10)
    tk.Label(frame_calc, textvariable=file_path_var, wraplength=450, fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)
    ttk.Button(frame_calc, text="CALCULATE FINGERPRINT", command=execute_hash, style='Green.TButton').pack(pady=15)
    
    # HASH COMPARATOR
    frame_comp = tk.Frame(frame_hash, bg=BG_COLOR, relief=tk.RIDGE, bd=2); frame_comp.pack(pady=10, padx=10, fill='x')
    tk.Label(frame_comp, text="Compare Two Hashes", font=("Helvetica", 11, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack(pady=5)

    hash1_var = tk.StringVar(); hash2_var = tk.StringVar()
    ttk.Entry(frame_comp, textvariable=hash1_var, width=60).pack(pady=2)
    ttk.Entry(frame_comp, textvariable=hash2_var, width=60).pack(pady=2)
    
    def execute_compare():
        hash1 = hash1_var.get().strip()
        hash2 = hash2_var.get().strip()
        
        if len(hash1) != 64 or len(hash2) != 64:
             return messagebox.showwarning("Input Error", "Hashes should be 64 characters (SHA-256).")
        
        if hash1 == hash2:
            messagebox.showinfo("Comparison Result", "MATCH! Files are identical (True Integrity).", icon='info')
        else:
            messagebox.showerror("Comparison Result", "MISMATCH! The files are different. Tampering or modification detected.", icon='error')

    ttk.Button(frame_comp, text="COMPARE", command=execute_compare, style='Green.TButton').pack(pady=10)


# --- MAIN WINDOW SETUP ---

root = tk.Tk()
root.title("Project The KEY: Digital Forensics Suite 🔑")
root.geometry("700x550")

root.configure(bg=BG_COLOR)
style = ttk.Style()
style.theme_use('clam')

# Configure Styles
style.configure('Dark.TFrame', background=BG_COLOR)
style.configure('TNotebook', background=BG_COLOR, borderwidth=0)
style.configure('TNotebook.Tab', background=ACCENT_COLOR, foreground='black', padding=[10, 5]) 
style.map('TNotebook.Tab', background=[('selected', BG_COLOR)], foreground=[('selected', FG_COLOR)])

style.configure('Green.TButton', 
                background=ACCENT_COLOR, 
                foreground='black', 
                font=('Consolas', 10, 'bold'),
                padding=6,
                borderwidth=0)
style.map('Green.TButton', background=[('active', FG_COLOR)], foreground=[('active', 'black')])

# --- HEADER / TITLE ---
header_frame = tk.Frame(root, bg=BG_COLOR)
header_frame.pack(pady=10, fill='x')

tk.Label(header_frame, text="PROJECT THE KEY: DIGITAL FORENSICS SUITE", font=("Consolas", 18, "bold"), fg=FG_COLOR, bg=BG_COLOR).pack()
tk.Label(header_frame, text="Dhairya Shah | B.Tech Computer Science", font=("Consolas", 10), fg=ACCENT_COLOR, bg=BG_COLOR).pack()

# --- TABBED INTERFACE ---
notebook = ttk.Notebook(root, style='TNotebook')
notebook.pack(pady=10, padx=10, fill='both', expand=True)

setup_text_ciphers(notebook)
setup_multimedia_stego(notebook)
setup_digital_forensics(notebook)

root.mainloop()