import json

def authenticate(username, password):
    with open("user.json", "r") as file:
        users = json.load(file)

    return username in users and users[username] == password