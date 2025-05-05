from cryptography.fernet import Fernet

def generate_key():
    """Generate a new AES encryption key."""
    return Fernet.generate_key()

def encrypt(data, key):
    """Encrypt data using the provided key."""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt(data, key):
    """Decrypt data using the provided key."""
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()