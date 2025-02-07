# Hash Cracker

## Description

This is a simple hash cracker that can crack `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512` hashes. It uses a wordlist to crack the hashes. The wordlist is a list of common passwords that are used to crack the hashes. The program reads the wordlist and compares the hashes of the words in the wordlist to the hash that is to be cracked. If the hash of a word in the wordlist matches the hash that is to be cracked, the program will output the word that was used to generate the hash.

## Installation

To install the program, you will need to have Python installed on your computer. You can download Python from the official website: [https://www.python.org/downloads/](https://www.python.org/downloads/)

Once you have Python installed, you can download the `main.py` file from this repository. You can do this by clicking on the "Code" button and selecting "Download ZIP". Once you have downloaded the file, you can extract it to a folder on your computer.

## Usage

To use the program, open a terminal or command prompt and navigate to the folder where you extracted the `main.py` file. You can run the program by typing the following command:

```sh
python main.py
```

# Step by Step Implementation

1. The program will prompt you to enter the hash that you want to crack. You can enter the hash and press Enter.
    ```python
    hash_to_crack = input("Enter the hash to crack: ").strip()
    ```

2. The program will then prompt you to enter the path to the wordlist that you want to use to crack the hash. You can enter the path to the wordlist and press Enter.
    ```python
    wordlist_file = input("Enter the wordlist file: ").strip()
    ```

3. The program will identify possible algorithms based on the length of the hash and print them.
    ```python
    possible_algorithms = identify_algorithm(hash_to_crack)
    print(f"Possible algorithms: {possible_algorithms}")
    ```

4. The program will then read the wordlist and compare the hashes of the words in the wordlist to the hash that is to be cracked. If the hash of a word in the wordlist matches the hash that is to be cracked, the program will output the word that was used to generate the hash.
    ```python
    for algorithm in possible_algorithms:
        result = crack_hash(hash_to_crack, algorithm, wordlist_file)
        if result:
            print(f"Success! The cracked hash is {result}")
            break
        else:
            print("Failed to crack the hash")
    ```

5. If the hash is not cracked, the program will print a failure message.
    ```python
    print("Failed to crack the hash")
    ```