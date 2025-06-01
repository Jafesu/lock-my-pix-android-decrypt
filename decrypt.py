import argparse
import hashlib
import logging
import os
import binascii
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',
    handlers=[
        logging.FileHandler("LockMyPix_decryption_log.log"),
        logging.StreamHandler()
    ]
)

# Encrypted -> Real Extension Map
EXTENSION_MAP = {
    ".vp3": ".mp4", ".vo1": ".webm", ".v27": ".mpg", ".vb9": ".avi",
    ".v77": ".mov", ".v78": ".wmv", ".v82": ".dv", ".vz9": ".divx",
    ".vi3": ".ogv", ".v1u": ".h261", ".v6m": ".h264", ".6zu": ".jpg",
    ".tr7": ".gif", ".p5o": ".png", ".8ur": ".bmp", ".33t": ".tiff",
    ".20i": ".webp", ".v93": ".heic", ".v91": ".flv", ".v80": ".3gpp",
    ".vo4": ".ts", ".v99": ".mkv", ".vr2": ".mpeg", ".vv3": ".dpg",
    ".v81": ".rmvb", ".vz8": ".vob", ".wi2": ".asf", ".vi4": ".h263",
    ".v2u": ".f4v", ".v76": ".m4v", ".v75": ".ram", ".v74": ".rm",
    ".v3u": ".mts", ".v92": ".dng", ".r89": ".ps", ".v79": ".3gp",
}

# Known file signature magic bytes (hex)
FILE_SIGNATURES = {
    ".jpg": "ffd8ff",
    ".png": "89504e47",
    ".gif": "47494638",
    ".bmp": "424d",
    ".tiff": "4949",     # Intel byte order TIFF
    ".webp": "52494646", # RIFF
    ".mp4": "00000018",
    ".webm": "1a45dfa3",
    ".avi": "52494646",
    ".mov": "00000014",
    ".mpg": "000001ba",
    ".wmv": "3026b275",
    ".mkv": "1a45dfa3",
    ".flv": "464c56",
    ".3gp": "00000018",
    ".ts": "4740",
}

def create_cipher(password):
    key = hashlib.sha1(password.encode()).digest()[:16]
    counter = Counter.new(128, initial_value=int.from_bytes(key, "big"))
    return AES.new(key, AES.MODE_CTR, counter=counter)

def test_password(input_dir, password, force=False):
    key = hashlib.sha1(password.encode()).digest()[:16]
    iv = key
    cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))

    found_test_file = False

    for file in os.listdir(input_dir):
        path = os.path.join(input_dir, file)
        if not Path(path).is_file():
            continue

        ext = os.path.splitext(file)[1]
        real_ext = EXTENSION_MAP.get(ext)
        if real_ext and real_ext in FILE_SIGNATURES:
            found_test_file = True
            with open(path, "rb") as f:
                dec_data = cipher.decrypt(f.read(16))
                header = binascii.hexlify(dec_data).decode("utf8").lower()
                expected = FILE_SIGNATURES[real_ext].lower()
                if header.startswith(expected):
                    logging.info(f"Password is valid based on {file}")
                    return True
                else:
                    logging.warning(f"Header mismatch in {file}: expected {expected}, got {header}")

    if not found_test_file:
        logging.warning("No known file types found to test password.")

    if force:
        logging.warning("Forcing decryption despite failed header check.")
        return True

    logging.error("Password validation failed. Use --force to bypass.")
    return False

def write_decrypted(output_dir, filename, data):
    orig_ext = os.path.splitext(filename)[1]
    new_ext = EXTENSION_MAP.get(orig_ext, ".unknown")

    if new_ext == ".unknown":
        logging.warning(f"Unknown extension for {filename}, defaulting to .unknown")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    output_file = output_path / (filename + new_ext)
    with open(output_file, "wb") as f:
        f.write(data)
        logging.info(f"Decrypted: {output_file}")

def decrypt_files(password, input_dir, output_dir):
    if not Path(input_dir).exists():
        logging.error(f"Input directory does not exist: {input_dir}")
        raise SystemExit(1)

    for file in os.listdir(input_dir):
        encrypted_path = os.path.join(input_dir, file)
        if not Path(encrypted_path).is_file():
            continue

        logging.info(f"Decrypting: {file}")
        cipher = create_cipher(password)
        with open(encrypted_path, "rb") as f:
            dec_data = cipher.decrypt(f.read())
            write_decrypted(output_dir, file, dec_data)

def main():
    parser = argparse.ArgumentParser(description="LockMyPix Decryption Tool")
    parser.add_argument("password", help="Password used for decryption")
    parser.add_argument("input", help="Directory containing encrypted files")
    parser.add_argument("output", help="Directory to write decrypted files")
    parser.add_argument("--force", action="store_true", help="Force decryption even if password check fails")

    args = parser.parse_args()

    if not test_password(args.input, args.password, args.force):
        logging.error("Aborting due to failed password check.")
        return

    decrypt_files(args.password, args.input, args.output)
    logging.info("Decryption complete.")

if __name__ == "__main__":
    main()
