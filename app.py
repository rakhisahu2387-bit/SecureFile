from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
import os
import tempfile

app = Flask(__name__)


def create_key(password):
    """
    Converts the user's password into a Fernet-compatible key.
    """
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    file = request.files.get("file")
    password = request.form.get("password")

    if not file or not password:
        return render_template(
            "index.html",
            message="Please select a file and enter a key.",
            message_type="error"
        )

    try:
        data = file.read()

        key = create_key(password)
        cipher = Fernet(key)

        encrypted_data = cipher.encrypt(data)

        original_name = file.filename
        encrypted_name = original_name + ".enc"

        output_path = os.path.join(tempfile.gettempdir(), encrypted_name)

        with open(output_path, "wb") as output:
            output.write(encrypted_data)

        return send_file(
            output_path,
            as_attachment=True,
            download_name=encrypted_name
        )

    except Exception as e:
        return render_template(
            "index.html",
            message=f"Encryption failed: {e}",
            message_type="error"
        )


@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    file = request.files.get("file")
    password = request.form.get("password")

    if not file or not password:
        return render_template(
            "index.html",
            message="Please select an encrypted file and enter the key.",
            message_type="error"
        )

    try:
        encrypted_data = file.read()

        key = create_key(password)
        cipher = Fernet(key)

        decrypted_data = cipher.decrypt(encrypted_data)

        original_name = file.filename

        if original_name.endswith(".enc"):
            original_name = original_name[:-4]
        else:
            original_name = "decrypted_" + original_name

        output_path = os.path.join(tempfile.gettempdir(), original_name)

        with open(output_path, "wb") as output:
            output.write(decrypted_data)

        return send_file(
            output_path,
            as_attachment=True,
            download_name=original_name
        )

    except InvalidToken:
        return render_template(
            "index.html",
            message="Decryption failed! The key is incorrect or the file is invalid.",
            message_type="error"
        )

    except Exception as e:
        return render_template(
            "index.html",
            message=f"Decryption failed: {e}",
            message_type="error"
        )


if __name__ == "__main__":
    app.run(debug=True)