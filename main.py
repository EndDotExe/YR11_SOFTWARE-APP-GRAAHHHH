import csv
import bcrypt

is_signedin = False

#Check if the user is signed in or not
def start_program():
    global is_signedin
    if is_signedin == True:
        signedin()
    else:
        notsignedin()
        

#the main menu if the user is signed in
def signedin():
    print("Choose: \n    Change Password\n    Logout\n")
    whichoption = input("|")
    match whichoption:
        case "Change password"|"Change Password"|"change password":
            change_password()
        case "Logout"|"logout"|"Log out"|"log out"|"Log Out":
            print("You have logged out.")
            is_signedin = False

#The main menu if the user is not signed in
def notsignedin():
    print("Choose: \n    Login \n    Register \n    Quit")
    whichone = input("|")
    match whichone:
        case "Login"|"login"|"Log in"|"log in"|"Log In":
            login()
        case "Register"|"register":
            register()
        case "Quit"|"quit":
            print("You have quit the program.")
            



#REGISTER
def register():
        create_account_username()

    #Create account - Username
def create_account_username():
    global username
    username = input("Register Username: ")
    doesusernamealreadyexist()

#doesusernamealreadyexist()
#Check if the registered username already exists
# IF the username already exists:
    # tell the user and kick them back to the menu
# ELSE:
    # Jump to password creation

def doesusernamealreadyexist():
    with open ("plain_text.txt", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == existingusername:
                print("Username is already taken, please enter another.")
                return
                notsignedin()
                
        else:
            file.write(f"{username},")
        create_account_password()


    #Create account - Password
#create_account_password()
    # ask user for a password
    # Write the password to plain_text.txt
    # tell the user they created a password
    # return to the menu
def create_account_password():
    password = input("Create Password: ")
    with open ("plain_text.txt", "a") as file:
        file.write(f"{password}\n")
    print("Password created.")
#    saltnhash()
    notsignedin()


#Salt & Hash password
#def saltnhash():
#    salt = b"k3yb0ardm4$h:]"
#Hashing the password
#    hashed_password = bcrypt.hashpw(password.encode(),salt=salt)

#Verfying password
#    if bcrypt.checkpw(input_password.encode(), hashed_password):
#        print("Login successful! :D")



#LOGIN
def login():
    global existingusername
    existingusername = input("Enter Username: ")
    loginusernamechecker()
#    saltnhash()


    #Does Username Exist?

#loginusernamechecker()
# IF existingusername does not match one in plain_text.txt:
    # PRINT username doesnt exist
    # Return to the main menu
# ELSE:
    # PRINT username accepted
    # RUN passwordchecker

def loginusernamechecker():
    usernamecheck = []

    with open ("source.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] != existingusername:
                print("Username does not exist, try again.")
                notsignedin()
            else: 
                print("Username accepted.")
                loginpasswordchecker()

    #Is Password Correct?
#loginpasswordchecker()
# Check plaintext.txt for the entered password
# IF entered password doesnt exist:
    # PRINT password not accepted
    # return to the main menu
# ELSE:
    # Welcome the user
    # SET is_signedin variable to TRUE
    # Return to the main menu's signed in version
def loginpasswordchecker():
    checkpassword = input("Enter Password: ")
    passwordcheck = []

    with open ("source.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["password"] != checkpassword:
                print("Incorrect password, try again.")
                notsignedin()
            else:
                print(f"Password accepted. Welcome, {existingusername}!")
                is_signedin = True
                signedin()

#CHANGE PASSWORD
#change_password()
    # Get the new password from the user
    # Edit plaintext.txt to have the new password
    # Return to the signed in menu
    
def change_password():
    new_password = input("Enter new password: ")
    updated = False
    with open("plain_text.txt", "r") as file:
        rows = list(csv.DictReader(file))
    with open("plaintext.txt", "w") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "password"])
        writer.writeheader()
        for row in rows:
            if row["username"] == existingusername:
                row["password"] = bcrypt.hashpw(new_password.encode, bcrypt.gensalt())
                updated = True
            writer.writerow(row)
        if updated:
            print("Password changed successfully :]")
            signedin()
        else:
            print("User not found :[")

    signedin()


#Run the program
start_program()