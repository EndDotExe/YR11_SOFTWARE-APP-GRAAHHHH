# Task 1 Python Programming Practical Task
This is the source repository for your first practical programming task.

## Task Time
1.	00:10:00 setup (create blank Lucidchart/Visio studio, clone repository, close all non-essential apps)
2.	00:05:00 minutes reading time (no keyboard, mouse only)
3.	02:45:00 working time
4.  At task end students will final commit/push and then turn in repository URL to Microsoft Teams

## Before the task begins
1. Open a new Lucid chart or Visio document for your models in a new tab in your browser
2. Fork this repository as a private repository
3. Ensure all your work is saved in the folder 'my_work'; only work in this folder will be marked.

## Task Specifications
You are to take the role of a Python Software Engineer to develop a functioning command line login application with a menu and functionality as follows:
1. __Login__ – Not logged-in users can log in with a username and password stored in `plain_text.txt`. A correct login combination updates the menu to include 'Change password' and 'Logout' and excludes 'Login', 'Register' and ‘Quit’
2. __Register__ – Not logged-in users can create a new account with a username and password, the new username must be unique, and the password must be a minimum of 4 characters
3. __Quit__ – Not logged-in users can end the program
4. __Change password__ – A logged-in user can change their password, which is updated in `plain_text.txt` with a minimum password length of 4 characters
5. __Logout__ - A logged-in user can log out, a logged-in user can logout returning them to the main menu in a logged out state.

> [!Important]
> Students can use *.CSV, *.TXT or hardcoded Python variables interchangeably. However, marks will be deducted for hardcoded Python variables and the provided usernames and password MUST be included. Students can make changes to the filename, filetype or add lines as required by their implementation.

### Extension Specifications
1. Passwords are stored 'salted' and 'hashed', (salted and hashed passwords are provided in salted_and_hashed.csv);

### Task Documentation Requirements
You'll need to model the application you have delivered using the NESA Software Engineering Course Specification. You are required to produce the following projections:
1. IPO table
2. Flow chart
3. Structure chart

**Do not model the task specifications, model the application you have delivered**

## Allowed websites

Students can only visit webpages inside this repository or linked from with this repository.
1. Anything pages contained within the GitHub Repo as long as you don't leave this repo
2. https://docs.python.org/3/library
**Students who access websites other than those listed here during the task will be instantly awarded a zero mark.**

## Allowed Extensions, Installs & libraries

All allowed extensions, pip installs & libraries have already been included or used in [example.py](example.py).
**Students who install additional extensions, pip installs or libraries will be instantly awarded a zero mark.**

## Files

- [source.csv](my_work/source.csv) is to be used by your application
- [plain_text.txt](my_work/plain_text.txt) is to help you with testing or can be used if you don't want to use plain text passwords.
- [README.md](README.md) contains core information
- Notes files contain the notes from the CS50 course:
    1. [Functions & Variables](0-FunctionsVariables/0-FunctionsVariables.md)
    2. [Conditionals](1-Conditionals/1-Conditionals.md)
    3. [Loops](2-Loops/2-Loops.md)
    4. [Debugging](Debugging/Debugging.md)
    5. [Exceptions](3-Exceptions/3-Exceptions.md)
    6. [Libraries](4-Libraries/4-Libraries.md)
    7. [Unit Tests](5-UnitTests/5-UnitTests.md)
    8. [File IO](6-FileIO/6-FileIO.md)


## Encrypting & Decrypting Passwords for Safer Storage

__Encryption__: Encryption is the process of encoding plain text or any information so that only authorized people can read it with a corresponding key, protecting confidential data from unauthorized persons.
__Hashing__: Hashing converts any amount of data into a fixed-length hash that cannot be reversed. It is widely used in cryptography. The hash allows us to validate if the input has changed even slightly; if it has, the resulting hash will be different.
__Salting__: In cryptography, a salt is random data used as an additional input to a one-way function that hashes data, such as a password. Salts are used to keep passwords safe while they are being stored.

| Same password | + | Different salt | Same Hashing Function | = | Different output |
| --- | --- | --- | --- | --- | --- |
| "gwW$3zHw" | + | 12gT3 | SHA256 Hash | = | "12d6a36ff1ffba1d24fd3ac0d270315bef3c3de4f6765b8788301f9fd57c084e" |
| "gwW$3zHw" | + | 97xH7 | SHA256 Hash | = | "3820b409b311a3534dcc30bbaa11f0ff5ce064fb476647ede393c8d94937ae15" |

In this article, we will learn the Salted Password Hashing technique. This technique involves converting an algorithm to map data of any size to a fixed length.

### Byte String Explained

To store anything in a computer, you must first encode it, i.e. convert it to bytes. For example:

- If you want to store music, you must first encode it using MP3, WAV, etc.
- If you want to store a picture, you must first encode it using PNG, JPEG, etc.
- If you want to store text, you must first encode it using ASCII, UTF-8, etc.

In Python, a byte string is just that: a sequence of bytes. It isn't human-readable. Under the hood, everything must be converted to a byte string before it can be stored in a computer.

On the other hand, a character string, often just called a "string," is a sequence of characters that is human-readable. A character string can't be directly stored in a computer; it has to be encoded first (converted into a byte string). Multiple encodings, such as ASCII and UTF-8, allow a character string to be converted into a byte string.

Encoding and decoding are inverse operations. Everything must be encoded before it can be written to disk, and it must be decoded before it can be read by a human.

In Python, a byte string is represented by a b, followed by the byte string's ASCII representation.

A byte string can be decoded back into a character string if you know the encoding that was used to encode it.

__Example of a string:__

```python
my_string = "This string, will be stored as a string"
```

bytes = b'...' literals = a sequence of bytes. A “byte” is the smallest integer type addressable on a computer, which is nearly universally an octet or 8-bit unit, thus allowing numbers between 0 and 255.

__Example of a byte string:__

```python
my_byte_string = b"This is a byte string It will be stored as a sequence of bytes".
```

### Hashing Passwords

#### Why do we need to Hash a Password?

Hashing is used mainly to protect a password from hackers. Suppose a website is hacked, and cybercriminals don’t get access to your password. Instead, they get access to the encrypted “hash” created by the method of hashing.

#### Why do we use salt in hashing?

Historically, only the password’s cryptographic hash function was maintained on a system, but over time, additional precautions were developed to prevent the identification of duplicate or common passwords. One such prevention is salting.

#### What is BCrypt?

The BCrypt Algorithm is a Python library used to hash and salt passwords securely. It enables the creation of a password protection layer that can develop local hardware innovation to protect against long-term hazards or threats, such as attackers having the computational capacity to guess passwords twice as efficiently.

All the necessary code snippets for this task are found in [example.py](example.py).