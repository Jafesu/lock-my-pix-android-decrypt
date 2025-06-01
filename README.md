# lock-my-pix-android-decrypt

Python tools for decrypting files exported from the LockMyPix Android app.
Includes a decryption script for known passwords and a PIN brute-force tool for recovering 4–10 digit PINs.

---

## 🔐 Decryption Script

Decrypts LockMyPix-encrypted files using a known password.
Supports validation via file magic headers (e.g., `.jpg`, `.png`) and optional `--force` override.

### ✅ Usage

```bash
python lockmypix_decrypt.py password input_dir output_dir [--force]
```

### 📄 Arguments

| Name         | Description                                               |
| ------------ | --------------------------------------------------------- |
| `password`   | The password or PIN used to encrypt the files             |
| `input_dir`  | Path to directory containing encrypted files              |
| `output_dir` | Path to directory where decrypted files will be saved     |
| `--force`    | (Optional) Skip password validation using file signatures |

---

## 🔓 PIN Brute-Force Script

Attempts to brute-force the PIN used to encrypt a `.6zu` file (usually a `.jpg`).
Supports 4 to 10 digit numeric PINs and parallel processing for faster results.

### ✅ Usage

```bash
python lockmypix_bruteforce.py input_file.6zu [--max 6]
```

### 📄 Arguments

| Name    | Description                             |
| ------- | --------------------------------------- |
| `input` | Path to the `.6zu` encrypted image file |
| `--max` | (Optional) Max PIN length (default: 10) |

---

## 📦 Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

**Contents of `requirements.txt`:**

```
pycryptodome
```

---
