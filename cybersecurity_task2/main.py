from auth import authenticate
from crypto_utils import encrypt_file, decrypt_file
from hash_utils import save_hash, verify_hash
from logger import log_event


def login():
    print("\n===== LOGIN =====")

    username = input("Username: ")
    password = input("Password: ")

    if authenticate(username, password):
        print("\nLogin Successful!")
        log_event(f"User {username} logged in")
        return True

    print("\nInvalid Credentials")
    return False


def encrypt_menu():
    filename = input("Enter file name to encrypt: ")

    try:
        encrypt_file(filename)

        encrypted_file = filename + ".encrypted"

        save_hash(encrypted_file)

        log_event(f"Encrypted {filename}")
        log_event(f"Hash generated for {encrypted_file}")

        print("\nFile encrypted successfully!")
        print(f"Encrypted File: {encrypted_file}")

    except Exception as e:
        print("Error:", e)


def verify_menu():
    filename = input("Enter encrypted file name: ")

    hash_file = filename + ".hash"

    try:
        if verify_hash(filename, hash_file):
            print("\nIntegrity Verified")
            log_event(f"Integrity verified for {filename}")
        else:
            print("\nFile Tampered")
            log_event(f"Tampering detected in {filename}")

    except Exception as e:
        print("Error:", e)


def decrypt_menu():
    filename = input("Enter encrypted file name: ")

    try:
        decrypt_file(filename)

        log_event(f"Decrypted {filename}")

        print("\nFile decrypted successfully!")

    except Exception as e:
        print("Error:", e)


def view_logs():
    try:
        with open("logs.txt", "r") as file:
            print("\n===== AUDIT LOGS =====\n")
            print(file.read())

    except FileNotFoundError:
        print("No logs found.")


def main():

  
    print(" SECURE FILE TRANSFER APPLICATION ")
   

    if not login():
        return

    while True:

        print("\n")
        print("1. Encrypt File")
        print("2. Verify Integrity")
        print("3. Decrypt File")
        print("4. View Audit Logs")
        print("5. Exit")

        choice = input("\nSelect Option: ")

        if choice == "1":
            encrypt_menu()

        elif choice == "2":
            verify_menu()

        elif choice == "3":
            decrypt_menu()

        elif choice == "4":
            view_logs()

        elif choice == "5":
            print("\nThank you for using Secure File Transfer.")
            break

        else:
            print("Invalid Choice")


if __name__ == "__main__":
    main()