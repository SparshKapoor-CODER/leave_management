import secrets

# Generate a 32-byte (256-bit) secret key
secret_key = secrets.token_hex(32)
print(f"Generated Secret Key: {secret_key}")

print("\nAdd this to your .env file:")
print(f"SECRET_KEY={secret_key}")