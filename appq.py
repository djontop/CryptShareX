from flask import Flask, render_template, request, redirect, url_for, send_file
from cryptography.fernet import Fernet
import os
import json

app = Flask(__name__)

encryption_key = Fernet.generate_key()
private_key_dict = {}  
cipher_suite = Fernet(encryption_key)

metadata_file = 'metadata.json'

if os.path.exists(metadata_file) and os.path.getsize(metadata_file) > 0:
    try:
        with open(metadata_file, 'r') as metadata:
            private_key_dict = json.load(metadata)
    except json.JSONDecodeError as e:
        print(f"Error loading metadata file: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        return redirect(request.url)

    file_content = file.read()

    encryption_choice = request.form.get('encryption_choice')

    if encryption_choice == '1':
        encrypted_content = cipher_suite.encrypt(file_content)
        private_key = None  # For files encrypted without a private key
    elif encryption_choice == '2':
        private_key = Fernet.generate_key()
        private_key_dict[file.filename] = private_key
        private_cipher_suite = Fernet(private_key)

        encrypted_content = private_cipher_suite.encrypt(file_content)

        with open(metadata_file, 'w') as metadata:
            json.dump(private_key_dict, metadata)
    else:
        return "Invalid encryption choice"

    encrypted_file_path = f'encrypted_{file.filename}'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    return render_template('encrypt_success.html', key=private_key.decode() if private_key else encryption_key.decode(),
                           filename=encrypted_file_path)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        file = request.files['file']
        private_key = request.form.get('private_key')

        if file and private_key:
            if file.filename in private_key_dict:
                private_cipher_suite = Fernet(private_key_dict[file.filename])
                decrypted_content = private_cipher_suite.decrypt(file.read())
                decrypted_file_path = f'decrypted_{file.filename}'
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_content)

                return render_template('decrypt_success.html', filename=decrypted_file_path)
            else:
                return "File was not encrypted with a private key"

    return render_template('decrypt.html')

@app.route('/download/<filename>')
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
