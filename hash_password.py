import hashlib


def get_password():
    password = input("Enter the password: ")
    return password


def hash_password(password):
    print("Supported algorithms: md5, sha1, sha224, sha256, sha384, sha512")
    algorithm = input("Select the algorithm: ").strip()

    try:
        hash_function = getattr(hashlib, algorithm)
        hashed_password = hash_function(password.encode()).hexdigest()
        print(f"Hashed password: {hashed_password}")
    except AttributeError:
        print(f"Algorithm {algorithm} is not supported")


if __name__ == "__main__":
    password = get_password()
    hash_password(password)