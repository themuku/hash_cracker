import hashlib


def identify_algorithm(hash_to_test):
    algorithms = {
        32: ['md5', hashlib.md5],
        40: ['sha1', hashlib.sha1],
        56: ['sha224', hashlib.sha224],
        64: ['sha256', hashlib.sha256],
        96: ['sha384', hashlib.sha384],
        128: ['sha512', hashlib.sha512]
    }

    return algorithms.get(len(hash_to_test), ['unknown'])


def crack_hash(hash_to_crack, algorithm, wordlist_file):
    try:
        hash_function = getattr(hashlib, algorithm)
    except AttributeError:
        print(f"Unsupported algorithm: {algorithm}")
        return None

    print(f"Cracking hash {hash_to_crack} using {algorithm} algorithm")

    try:
        with open(wordlist_file, "r") as f:
            for line in f:
                word = line.strip()
                hashed_word = hash_function(word.encode()).hexdigest()

                if hashed_word == hash_to_crack:
                    return word
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist_file}")
        return None

    return None


if __name__ == "__main__":
    hash_to_crack = input("Enter the hash to crack: ").strip()
    wordlist_file = input("Enter the wordlist file: ").strip()

    possible_algorithms = identify_algorithm(hash_to_crack)
    print(f"Possible algorithms: {possible_algorithms}")

    for algorithm in possible_algorithms:
        result = crack_hash(hash_to_crack, algorithm, wordlist_file)
        if result:
            print(f"Success! The cracked hash is {result}")
            break
        else:
            print("Failed to crack the hash")
