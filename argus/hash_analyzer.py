
def identify_hash_type(file_hash: str) -> str:
    file_hash = file_hash.strip().lower()

    if not all(char in "0123456789abcdef" for char in file_hash):
        return "Invalid"

    if len(file_hash) == 32:
        return "MD5"

    elif len(file_hash) == 40:
        return "SHA-1"

    elif len(file_hash) == 64:
        return "SHA-256"

    return "Invalid"
