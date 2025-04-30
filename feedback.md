# Feedback

### **Strengths**
1. **Basic Structure**:
   - The code is modular, with functions handling specific tasks like `register`, `login`, and `change_password`.
   - It uses global variables (`is_signedin`) to manage the program's state effectively.

2. **User Interaction**:
   - The program provides clear prompts and feedback to the user, making it user-friendly.

3. **File Handling**:
   - The code uses file operations to store and retrieve user data, which is a good starting point for persistence.

4. **Use of `match` Statements**:
   - The use of `match` statements for handling user input is clean and readable.

---

### **Issues and Suggestions for Improvement**

#### 1. **Insecure Password Storage**
   - Passwords are stored in plaintext in `plain_text.txt`, which is a major security issue.
   - **Fix**: Use a library like `bcrypt` to hash passwords before storing them and verify the hash during login.

   Example:
   ```python
   import bcrypt

   salt = b"$2b$12$ieYNkQp8QumgedUo30nuPO"

   # Hashing a password
   hashed_password = bcrypt.hashpw(password.encode(), salt=salt)

   # Verifying a password
   if bcrypt.checkpw(input_password.encode(), hashed_password):
       print("Login successful!")
   ```

---

#### 2. **Global Variables**
   - The use of global variables like `is_signedin`, `username`, and `existingusername` can lead to bugs and make the code harder to maintain.
   - **Fix**: Pass these variables as arguments to functions or encapsulate them in a class.

---

#### 3. **File Handling Issues**
   - The code appends to `plain_text.txt` without properly checking for existing data, which can lead to duplicate or incorrect entries.
   - **Fix**: Use `csv.DictReader` and `csv.DictWriter` to handle the file as a structured CSV file.

   Example:
   ```python
   with open("plain_text.txt", "r") as file:
       reader = csv.DictReader(file)
       for row in reader:
           if row["username"] == username:
               print("Username already exists.")
               return
   ```

---

#### 4. **Logic Errors**
   - **`doesusernamealreadyexist` Function**:
     - The `row[0]` variable is undefined, leading to a potential runtime error.
     - **Fix**: Iterate through the file properly and check for existing usernames.

   - **`loginusernamechecker` Function**:
     - The `row[0]` variable is used outside the loop, which will cause an error.
     - **Fix**: Ensure the loop is properly structured and the variable is defined.

   - **`loginpasswordchecker` Function**:
     - The `passwordcheck` list is not used correctly, and the logic for checking passwords is flawed.
     - **Fix**: Compare the input password with the stored password directly.

---

#### 5. **Password Change Logic**
   - The `change_password` function appends a new row to the file instead of updating the existing password.
   - **Fix**: Read the file into memory, update the password, and rewrite the file.

   Example:
   ```python
   def change_password():
       new_password = input("Enter new password: ")
       updated = False
       with open("plain_text.txt", "r") as file:
           rows = list(csv.DictReader(file))
       with open("plain_text.txt", "w") as file:
           writer = csv.DictWriter(file, fieldnames=["username", "password"])
           writer.writeheader()
           for row in rows:
               if row["username"] == existingusername:
                   row["password"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                   updated = True
               writer.writerow(row)
       if updated:
           print("Password updated successfully.")
       else:
           print("User not found.")
   ```

---

#### 6. **Error Handling**
   - The program does not handle invalid inputs or file-related errors gracefully.
   - **Fix**: Add proper error handling using `try-except` blocks.

   Example:
   ```python
   try:
       with open("plain_text.txt", "r") as file:
           # File operations
   except FileNotFoundError:
       print("Error: File not found.")
   ```

---

#### 7. **Code Readability**
   - The code lacks comments and has inconsistent formatting, making it harder to understand.
   - **Fix**: Add comments explaining the purpose of each function and improve formatting.