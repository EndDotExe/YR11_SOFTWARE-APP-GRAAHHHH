# Mr Jones Sample Code
# This code is a simple user authentication system that allows users to register and login.
# It uses a CSV file to store user credentials and bcrypt for password hashing.
import csv
import sys
import bcrypt


# Salt to add to password before Hashing
salt = b"$2b$12$ieYNkQp8QumgedUo30nuPO"


# Salt & Hash the password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), salt=salt).decode()


# Check if the password matches the hash
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


# Load accounts from the CSV file
def load_accounts():
    try:
        with open("source.csv", "r") as file:
            return list(csv.DictReader(file))
    except FileNotFoundError:
        return []


# Save a new account to the CSV file
def save_account(username, password):
    with open("source.csv", "a") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "password"])
        writer.writerow({"username": username, "password": hash_password(password)})


# Register a new user
def register():
    username = input("Enter Username: ").strip()
    password = input("Enter Password: ").strip()
    if len(password) < 4:
        print("Password must be at least 4 characters long.")
        return
    accounts = load_accounts()
    for account in accounts:
        if account["username"] == username:
            print("Username already exists.")
            return
    save_account(username, password)
    print("Registration successful!")


# Login a user
def login():
    username = input("Username? ").strip()
    password = input("Password? ").strip()
    accounts = load_accounts()
    for account in accounts:
        if account["username"] == username and check_password(password, account["password"]):
            print("Valid Confirmation!")
            return
    print("Invalid username or password.")


# Main function
def main():
    while True:
        user = input("1. Login, 2. Register, 3. Quit: ").strip().lower()
        if user == "1" or user == "login":
            login()
        elif user == "2" or user == "Register":
            register()
        elif user == "3" or user == "Quit":
            print("Goodbye!")
            sys.exit()
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
