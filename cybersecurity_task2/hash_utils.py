import hashlib

def generate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()

def save_hash(filename):
    file_hash = generate_hash(filename)

    with open(filename + ".hash", "w") as hash_file:
        hash_file.write(file_hash)

    return file_hash

def verify_hash(filename, hash_file_name):
    current_hash = generate_hash(filename)

    with open(hash_file_name, "r") as hash_file:
        original_hash = hash_file.read().strip()

    return current_hash == original_hash