from flask import Flask, render_template, request, redirect, url_for, send_file
from cryptography.fernet import Fernet
import os
import json
import base64
import requests
import qrcode
from PIL import Image
from io import BytesIO
import cv2
from werkzeug.utils import secure_filename
from stegano import lsb

app = Flask(__name__)

encryption_key = Fernet.generate_key()
private_key_dict = {}  
cipher_suite = Fernet(encryption_key)

metadata_file = 'metadata.json'

gofile_api_url = 'https://store1.gofile.io/uploadFile'

if os.path.exists(metadata_file) and os.path.getsize(metadata_file) > 0:
    try:
        with open(metadata_file, 'r') as metadata:
            private_key_dict = json.load(metadata)
    except json.JSONDecodeError as e:
        print(f"Error loading metadata file: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.errorhandler(UnboundLocalError)
def handle_unbound_local_error(error):
    custom_error_message = "An error occurred during file upload. Please check your input and try again."
    return render_template('error.html', error_message=custom_error_message)

@app.errorhandler(IndexError)
def handle_index_error(error):
    custom_error_message = "An error occurred: Unable to access the requested information. Please try again."
    return render_template('error.html', error_message=custom_error_message)

def upload_to_gofile(file_path):
    files = {'file': open(file_path, 'rb')}
    
    try:
        response = requests.post(gofile_api_url, files=files)

        if response.status_code == 200:
            return response.json()
        else:
            return {'error': 'Failed to upload to GoFile'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request failed: {e}'}

def decode_qr_code(qr_code):
    try:
        qr_code_path = os.path.join('uploads', secure_filename(qr_code.filename))

        os.makedirs(os.path.dirname(qr_code_path), exist_ok=True)

        qr_code.save(qr_code_path)  

        abs_qr_code_path = os.path.abspath(qr_code_path)

        if not os.path.isfile(abs_qr_code_path):
            print(f"Error decoding QR code: File does not exist at {abs_qr_code_path}.")
            return None

        img = cv2.imread(abs_qr_code_path)
        qr_code_data = cv2.QRCodeDetector().detectAndDecode(img)[0]

        if qr_code_data:
            print("Decoded QR Code Data:", qr_code_data) 
            return qr_code_data
        else:
            print("No QR code data found.")
            return None
    except Exception as e:
        print("Error decoding QR code:", str(e))  
        return None
    
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
        private_key = None  
    elif encryption_choice == '2':
        if file.filename in private_key_dict:
            private_key_dict[file.filename] = Fernet.generate_key().decode()
        else:
            private_key = Fernet.generate_key()
            private_key_dict[file.filename] = private_key.decode()  

        private_cipher_suite = Fernet(private_key_dict[file.filename])

        encrypted_content = private_cipher_suite.encrypt(file_content)

        with open(metadata_file, 'w') as metadata:
            json.dump(private_key_dict, metadata)
    elif encryption_choice == '3':
        private_key = Fernet.generate_key()
        private_key_dict[file.filename] = private_key.decode()  

        private_cipher_suite = Fernet(private_key_dict[file.filename])

        encrypted_content = private_cipher_suite.encrypt(file_content)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(private_key_dict[file.filename])
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_byte_array = BytesIO()
        img.save(img_byte_array, format='PNG')
        img_data = base64.b64encode(img_byte_array.getvalue()).decode()

        with open(metadata_file, 'w') as metadata:
            json.dump(private_key_dict, metadata)
    else:
        return "Invalid encryption choice"

    encrypted_file_path = f'{file.filename}'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    gofile_response = upload_to_gofile(encrypted_file_path)

    return render_template('encrypt_success.html', key=private_key_dict[file.filename] if private_key else "Not applicable",
                           filename=encrypted_file_path, gofile_link=gofile_response.get('data', {}).get('downloadPage', ''),
                           qr_code=img_data if encryption_choice == '3' else None)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        file = request.files['file']
        decryption_choice = request.form.get('decryption_choice')
        private_key = request.form.get('private_key')
        qr_code = request.files['qr_code'] if decryption_choice == '2' else None

        if file and (private_key or qr_code):
            if file.filename in private_key_dict:
                stored_private_key_str = private_key_dict[file.filename]
                stored_private_key = stored_private_key_str.encode()

                if stored_private_key and decryption_choice == '1':
                    if private_key.encode() == stored_private_key:
                        private_cipher_suite = Fernet(stored_private_key)
                        decrypted_content = private_cipher_suite.decrypt(file.read())
                        decrypted_file_path = f'decrypted_{file.filename}'
                        with open(decrypted_file_path, 'wb') as decrypted_file:
                            decrypted_file.write(decrypted_content)

                        gofile_response = upload_to_gofile(decrypted_file_path)
                        
                        return render_template('decrypt_success.html', filename=decrypted_file_path,
                                               gofile_link=gofile_response.get('data', {}).get('downloadPage', ''))
                    else:
                        return "Incorrect private key. File cannot be decrypted."
                elif qr_code and decryption_choice == '2':
                    private_key_from_qr = decode_qr_code(qr_code)
                    if private_key_from_qr:
                        private_cipher_suite = Fernet(private_key_from_qr)
                        decrypted_content = private_cipher_suite.decrypt(file.read())
                        decrypted_file_path = f'decrypted_{file.filename}'
                        with open(decrypted_file_path, 'wb') as decrypted_file:
                            decrypted_file.write(decrypted_content)

                        gofile_response = upload_to_gofile(decrypted_file_path)

                        return render_template('decrypt_success.html', filename=decrypted_file_path,
                                               gofile_link=gofile_response.get('data', {}).get('downloadPage', ''))
                    else:
                        return "Error decoding QR code. Please make sure the QR code is valid."
                else:
                    return "File was not encrypted with a private key or QR code, and cannot be decrypted."
            else:
                return "File information not found. It may not have been encrypted using this application."

    return render_template('decrypt.html')


@app.route('/encode', methods=['POST'])
def encode():
    if 'image' not in request.files or 'message' not in request.form:
        return redirect(url_for('index'))

    image_data = request.files['image'].stream.read()
    
    image_file = BytesIO(image_data)

    secret_image = lsb.hide(image_file, request.form['message'])

    secret_image.save('static/secret.png')

    return render_template('result.html', image_path='static/secret.png')

@app.route('/decode_result', methods=['POST'])
def decode_result():
    if 'image' not in request.files:
        return redirect(url_for('decode'))

    image_data = request.files['image'].stream.read()

    image_file = BytesIO(image_data)
    decoded_message = lsb.reveal(image_file)

    return render_template('decode_result.html', decoded_message=decoded_message)

@app.route('/download/<filename>')
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
