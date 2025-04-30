import csv

is_signedin = False

#Check if the user is signed in or not
def start_program():
    global is_signedin
    if is_signedin == True:
        signedin()
    if is_signedin == False:
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
    with open ("plain_text.txt", "a") as file:
        if username == row[0]:
            print("Username is already taken, please enter another.")
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
    notsignedin()

    #Salt & Hash password



#LOGIN
def login():
    global existingusername
    existingusername = input("Enter Username: ")
    loginusernamechecker()


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

    with open ("plain_text.txt") as file:
        reader = csv.reader(file)
        for row in reader:
            usernamecheck.append({"username": row[0]})
    if existingusername != row[0]:
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

    with open ("plain_text.txt") as file:
        reader = csv.reader(file)
        for row in reader:
            passwordcheck.append({"password": row[1]})
    if passwordcheck != row[1]:
        print("Incorrect password, try again.")
        notsignedin()
    else:
        print(f"Password accepted. Welcome, {existingusername}.")
        is_signedin = True
        signedin()

#CHANGE PASSWORD
#change_password()
    # Get the new password from the user
    # Edit plaintext.txt to have the new password
    # Return to the signed in menu
    
def change_password():
    newpassword = input("Enter new password: ")
    with open("plain_text.txt", "a") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "password"])
        writer.writerow({"username": previoususername, "password": newpassword})
    print("Password updated.")
    signedin()


#Run the program
start_program()