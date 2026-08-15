from auth import authenticate

username = input("Username: ")
password = input("Password: ")

if authenticate(username, password):
    print("Login Successful")
else:
    print("Invalid Credentials")