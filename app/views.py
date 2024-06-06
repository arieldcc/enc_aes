from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from datetime import datetime
# from memory_profiler import memory_usage
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from app import app

import platform

if platform.system() == 'Windows':
    import psutil  # Gunakan psutil di Windows
else:
    import resource  # Gunakan resource di Unix

app.secret_key = 'your_secret_key'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'db', 'data.db')

# Pastikan folder 'uploads' ada
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Fungsi untuk pad data ke ukuran blok yang sesuai dengan AES
def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

# Fungsi untuk enkripsi data biner
def encrypt_image(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    plaintext = pad(plaintext)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Dapatkan tanggal dan jam saat ini
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    enc_file_name = f'enc_{timestamp}.enc'
    enc_file_path = os.path.join(UPLOAD_FOLDER, enc_file_name)
    
    with open(enc_file_path, 'wb') as f:
        f.write(nonce + ciphertext)
    
    return enc_file_path

def decrypt_imagersa(file_path, key, file_ext):
    with open(file_path, 'rb') as f:
        nonce, ciphertext = f.read(16), f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = plaintext.rstrip(b"\0")

    # Save decrypted file with format desk_tanggal_jam.extension
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    dec_file_name = f'desk_{timestamp}{file_ext}'
    dec_file_path = os.path.join(UPLOAD_FOLDER, dec_file_name)
    
    with open(dec_file_path, 'wb') as f:
        f.write(plaintext)
    
    return dec_file_path

# Fungsi untuk dekripsi data biner
def decrypt_image(file_path, key, file_ext):
    with open(file_path, 'rb') as f:
        nonce, ciphertext = f.read(16), f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = plaintext.rstrip(b"\0")

    # Simpan file dekripsi dengan format desk_tanggal_jam.ekstensi
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    dec_file_name = f'desk_{timestamp}{file_ext}'
    dec_file_path = os.path.join(UPLOAD_FOLDER, dec_file_name)
    
    with open(dec_file_path, 'wb') as f:
        f.write(plaintext)
    
    return dec_file_path

def get_encryption_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT nama_file_asli, ekstensi_file, nama_file_enc, nama_file_bin, key_enc, ukuran_file, waktu_eksekusi, memori_digunakan, key_aes_rsa FROM data_enkripsi where key_enc IS NOT NULL')
    data = cursor.fetchall()
    conn.close()
    return data

def get_encryption_datarsa():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT nama_file_asli, ekstensi_file, nama_file_enc, nama_file_bin, key_enc, ukuran_file, waktu_eksekusi, memori_digunakan, key_aes_rsa FROM data_enkripsi where key_enc IS NULL')
    data = cursor.fetchall()
    conn.close()
    return data

def get_decryption_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''SELECT nama_file_enc, ekstensi_file, file_desk, ukuran_file_desk, waktu_eksekusi_desk, memori_digunakan_desk, keterangan 
                      FROM data_enkripsi where key_enc IS NOT NULL''')
    data = cursor.fetchall()
    conn.close()
    return data

def get_decryption_datarsa():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''SELECT nama_file_enc, ekstensi_file, file_desk, ukuran_file_desk, waktu_eksekusi_desk, memori_digunakan_desk, keterangan 
                      FROM data_enkripsi where key_enc IS NULL''')
    data = cursor.fetchall()
    conn.close()
    return data

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            start_time = datetime.now()

            now = datetime.now()
            formatted_time = now.strftime("%H_%M_%S-%d_%m_%Y")

            original_filename = file.filename
            original_ext = os.path.splitext(original_filename)[1]

            # Simpan file asli
            original_file_path = os.path.join(UPLOAD_FOLDER, original_filename)
            file.save(original_file_path)

            # Generate new filename for encryption
            new_filename = f"aes-{formatted_time}.bin"
            encrypted_file_path = os.path.join(UPLOAD_FOLDER, new_filename)
            
            key = get_random_bytes(16)  # Kunci 128-bit

            if platform.system() == 'Windows':
                process = psutil.Process(os.getpid())
                mem_usage_before = process.memory_info().rss / (1024 * 1024)  # Dalam MB
            else:
                mem_usage_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Dalam MB

            enc_file_path = encrypt_image(original_file_path, key)

            if platform.system() == 'Windows':
                mem_usage_after = process.memory_info().rss / (1024 * 1024)  # Dalam MB
            else:
                mem_usage_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Dalam MB

            memory_used = mem_usage_after - mem_usage_before
            end_time = datetime.now()
            execution_time = end_time - start_time

            # Simpan data enkripsi ke database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO data_enkripsi 
                              (nama_file_asli, ekstensi_file, nama_file_enc, nama_file_bin, key_enc, ukuran_file, waktu_eksekusi, memori_digunakan) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                           (original_filename, original_ext, os.path.basename(enc_file_path), os.path.basename(encrypted_file_path), key.hex(), 
                            os.path.getsize(original_file_path), str(execution_time), f"{memory_used:.2f} MB"))
            conn.commit()
            conn.close()

            flash(f'File dienkripsi: {enc_file_path}. Kunci: {key.hex()}')
            return redirect(url_for('encrypt'))
    data = get_encryption_data()
    return render_template('encrypt.html', data=data)

@app.route('/encryptrsa', methods=['GET', 'POST'])
def encryptrsa():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            start_time = datetime.now()

            now = datetime.now()
            formatted_time = now.strftime("%H_%M_%S-%d_%m_%Y")

            original_filename = file.filename
            original_ext = os.path.splitext(original_filename)[1]

            # Save the original file
            original_file_path = os.path.join(UPLOAD_FOLDER, original_filename)
            file.save(original_file_path)

            # Generate RSA key pair
            rsa_key = RSA.generate(2048)
            public_key = rsa_key.publickey()
            cipher_rsa = PKCS1_OAEP.new(public_key)

            # Generate AES key
            aes_key = get_random_bytes(16)  # 128-bit key

            # Encrypt AES key with RSA public key
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # Save the RSA private key
            private_key_path = os.path.join(UPLOAD_FOLDER, f'private_key_{formatted_time}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(rsa_key.export_key())

            # Save the encrypted AES key to a file
            encrypted_aes_key_path = os.path.join(UPLOAD_FOLDER, f'encrypted_aes_key_{formatted_time}.bin')
            with open(encrypted_aes_key_path, 'wb') as f:
                f.write(encrypted_aes_key)

            if platform.system() == 'Windows':
                process = psutil.Process(os.getpid())
                mem_usage_before = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            # Encrypt the file using AES key (implement encrypt_image function accordingly)
            enc_file_path = encrypt_image(original_file_path, aes_key)

            if platform.system() == 'Windows':
                mem_usage_after = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            memory_used = mem_usage_after - mem_usage_before
            end_time = datetime.now()
            execution_time = end_time - start_time

            # Save encryption data to the database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO data_enkripsi 
                              (nama_file_asli, ekstensi_file, nama_file_enc, nama_file_bin, key_enc, ukuran_file, waktu_eksekusi, memori_digunakan, private_key_path, encrypted_aes_key_path) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (original_filename, original_ext, os.path.basename(enc_file_path), os.path.basename(enc_file_path), None, 
                            os.path.getsize(original_file_path), str(execution_time), f"{memory_used:.2f} MB", private_key_path, encrypted_aes_key_path))
            conn.commit()
            conn.close()

            flash(f'File dienkripsi: {enc_file_path}. Kunci telah dienkripsi dengan RSA.')
            return redirect(url_for('encrypt'))
    data = get_encryption_datarsa()
    return render_template('encrypt_rsa.html', data=data)

@app.route('/decryptrsa', methods=['GET', 'POST'])
def decryptrsa():
    if request.method == 'POST':
        enc_filename = request.form['enc_filename']
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT private_key_path, encrypted_aes_key_path, ekstensi_file, file_desk FROM data_enkripsi WHERE nama_file_enc = ?', (enc_filename,))
        row = cursor.fetchone()
        
        if row:
            private_key_path, encrypted_aes_key_path, file_ext, file_desk = row
            if file_desk:  # Check if file_desk is already filled
                flash(f'Data telah dilakukan Deskripsi: {file_desk}. Tidak bisa diproses ulang.')
                conn.close()
                return redirect(url_for('decrypt'))

            # Read the RSA private key
            with open(private_key_path, 'rb') as f:
                private_key = RSA.import_key(f.read())

            # Read the encrypted AES key
            with open(encrypted_aes_key_path, 'rb') as f:
                encrypted_aes_key = f.read()

            # Decrypt the AES key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            start_time = datetime.now()

            file_path = os.path.join(UPLOAD_FOLDER, enc_filename)

            if platform.system() == 'Windows':
                process = psutil.Process(os.getpid())
                mem_usage_before = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            dec_file_path = decrypt_imagersa(file_path, aes_key, file_ext)

            if platform.system() == 'Windows':
                mem_usage_after = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            memory_used = mem_usage_after - mem_usage_before
            end_time = datetime.now()
            execution_time = end_time - start_time

            # Update decryption data in the database
            cursor.execute('''UPDATE data_enkripsi SET 
                              file_desk = ?, ukuran_file_desk = ?, waktu_eksekusi_desk = ?, memori_digunakan_desk = ?
                              WHERE nama_file_enc = ?''',
                           (os.path.basename(dec_file_path), os.path.getsize(dec_file_path), str(execution_time), f"{memory_used:.2f} MB", enc_filename))
            conn.commit()
            conn.close()

            flash(f'File didekripsi: {dec_file_path}')
            return redirect(url_for('decrypt'))
    data = get_decryption_datarsa()
    return render_template('decrypt.html', data=data)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        enc_filename = request.form['enc_filename']
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT key_enc, key_aes_rsa, ekstensi_file, file_desk FROM data_enkripsi WHERE nama_file_enc = ?', (enc_filename,))
        row = cursor.fetchone()
        
        if row:
            key_enc, key_aes_rsa, file_ext, file_desk = row
            if file_desk:  # Check if file_desk is already filled
                flash(f'Data telah dilakukan Deskripsi: {file_desk}. Tidak bisa diproses ulang.')
                conn.close()
                return redirect(url_for('decrypt'))

            if key_enc:
                key = bytes.fromhex(key_enc)
                keterangan = "Key standar AES"
            elif key_aes_rsa:
                key = bytes.fromhex(key_aes_rsa)
                keterangan = "Key AES+RSA"
            else:
                flash('Kunci enkripsi tidak ditemukan.')
                conn.close()
                return redirect(url_for('decrypt'))
            
            start_time = datetime.now()

            file_path = os.path.join(UPLOAD_FOLDER, enc_filename)

            if platform.system() == 'Windows':
                process = psutil.Process(os.getpid())
                mem_usage_before = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            dec_file_path = decrypt_image(file_path, key, file_ext)

            if platform.system() == 'Windows':
                mem_usage_after = process.memory_info().rss / (1024 * 1024)  # In MB
            else:
                mem_usage_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # In MB

            memory_used = mem_usage_after - mem_usage_before
            end_time = datetime.now()
            execution_time = end_time - start_time

            # Update decryption data in the database
            cursor.execute('''UPDATE data_enkripsi SET 
                              file_desk = ?, ukuran_file_desk = ?, waktu_eksekusi_desk = ?, memori_digunakan_desk = ?, keterangan = ?
                              WHERE nama_file_enc = ?''',
                           (os.path.basename(dec_file_path), os.path.getsize(dec_file_path), str(execution_time), f"{memory_used:.2f} MB", keterangan, enc_filename))
            conn.commit()
            conn.close()

            flash(f'File didekripsi: {dec_file_path}')
            return redirect(url_for('decrypt'))
    data = get_decryption_data()
    return render_template('decrypt.html', data=data)

@app.route('/decrypt_', methods=['GET', 'POST'])
def decrypt_():
    if request.method == 'POST':
        enc_filename = request.form['enc_filename']
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT key_enc, key_aes_rsa, ekstensi_file, file_desk FROM data_enkripsi WHERE nama_file_enc = ?', (enc_filename,))
        row = cursor.fetchone()
        
        if row:
            key, file_ext, file_desk = row
            if file_desk:  # Cek apakah file_desk sudah terisi
                flash(f'Data telah dilakukan Deskripsi: {file_desk}. Tidak bisa diproses ulang.')
                conn.close()
                return redirect(url_for('decrypt'))
            
            key = bytes.fromhex(key)
            start_time = datetime.now()

            file_path = os.path.join(UPLOAD_FOLDER, enc_filename)

            if platform.system() == 'Windows':
                process = psutil.Process(os.getpid())
                mem_usage_before = process.memory_info().rss / (1024 * 1024)  # Dalam MB
            else:
                mem_usage_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Dalam MB

            dec_file_path = decrypt_image(file_path, key, file_ext)

            if platform.system() == 'Windows':
                mem_usage_after = process.memory_info().rss / (1024 * 1024)  # Dalam MB
            else:
                mem_usage_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Dalam MB

            memory_used = mem_usage_after - mem_usage_before
            end_time = datetime.now()
            execution_time = end_time - start_time

            # Update data dekripsi di database
            cursor.execute('''UPDATE data_enkripsi SET 
                              file_desk = ?, ukuran_file_desk = ?, waktu_eksekusi_desk = ?, memori_digunakan_desk = ?
                              WHERE nama_file_enc = ?''',
                           (os.path.basename(dec_file_path), os.path.getsize(dec_file_path), str(execution_time), f"{memory_used:.2f} MB", enc_filename))
            conn.commit()
            conn.close()

            flash(f'File didekripsi: {dec_file_path}')
            return redirect(url_for('decrypt'))
    data = get_decryption_data()
    return render_template('decrypt.html', data=data)

@app.route('/delete/<enc_filename>', methods=['POST'])
def delete(enc_filename):
    # Hapus data dari database dan file dari direktori
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT nama_file_enc, nama_file_bin, file_desk, nama_file_asli FROM data_enkripsi WHERE nama_file_enc = ?', (enc_filename,))
    row = cursor.fetchone()
    if row:
        # Hapus file dari direktori
        enc_file_path = os.path.join(UPLOAD_FOLDER, row[0])
        bin_file_path = os.path.join(UPLOAD_FOLDER, row[1])
        # desk_file_path = os.path.join(UPLOAD_FOLDER, row[2])
        nama_file_asli = os.path.join(UPLOAD_FOLDER, row[3])
        
        if os.path.exists(enc_file_path):
            os.remove(enc_file_path)
        if os.path.exists(bin_file_path):
            os.remove(bin_file_path)
        # if os.path.exists(desk_file_path) and row[2]:  # Hanya hapus jika file_desk tidak kosong
        #     os.remove(desk_file_path)
        if os.path.exists(nama_file_asli) and row[3]:
            os.remove(nama_file_asli)

        # Hapus data dari tabel
        cursor.execute('DELETE FROM data_enkripsi WHERE nama_file_enc = ?', (enc_filename,))
        conn.commit()
        flash(f'Data dan file terkait {enc_filename} telah dihapus.')
    conn.close()
    return redirect(url_for('encrypt'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/uploads/<filename>')
def view_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path) and filename:
        return send_from_directory(UPLOAD_FOLDER, filename)
    else:
        flash('File tidak ditemukan!')
        return redirect(url_for('decrypt'))
    
@app.route('/uploads/<filename>')
def view_file_desk(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path) and filename:
        return send_from_directory(UPLOAD_FOLDER, filename)
    else:
        flash('File tidak ditemukan atau belum di Deskripsi!')
        return redirect(url_for('decrypt'))