from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich import box
import os
import json
import base64
import hashlib

console = Console()

# Paths to files
SECRETS_FILE = "secrets.json"
USER_FILE = "user.json"
CONFIG_FILE = "config.json"
RSA_PRIVATE_KEY_FILE = "rsa_private_key.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public_key.pem"

# Load user data
def load_user_data():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save user data
def save_user_data(data):
    with open(USER_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Load config data
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save config data
def save_config(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate and store RSA keys
def generate_and_store_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys to files
    with open(RSA_PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_pem)
    with open(RSA_PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_pem)

    return private_pem, public_pem

# Load RSA private key
def load_rsa_private_key():
    with open(RSA_PRIVATE_KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

# Load RSA public key
def load_rsa_public_key():
    with open(RSA_PUBLIC_KEY_FILE, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

# Sign up a new user
def sign_up():
    console.print(Panel("Sign Up", title="Sign Up", style="bold green", border_style="green"))
    username = Prompt.ask("[bold cyan]Enter a username[/]")
    password = Prompt.ask("[bold cyan]Enter a password[/]", password=True)
    password_hash = hash_password(password)
    user_data = load_user_data()
    if username in user_data:
        console.print(Panel("Username already exists!", title="Error", style="bold red", border_style="red"))
        return False
    encryption_key = Fernet.generate_key()
    config = {
        'ENCRYPTION_KEY': encryption_key.decode('utf-8')
    }
    user_data[username] = {"password": password_hash}
    save_user_data(user_data)
    save_config(config)

    # Generate and store RSA keys
    generate_and_store_rsa_keys()

    console.print(Panel(f"Sign up successful! Your encryption key is: {encryption_key.decode('utf-8')}", title="Success", style="bold green", border_style="green"))
    return True

# Sign in an existing user
def sign_in():
    console.print(Panel("Sign In", title="Sign In", style="bold green", border_style="green"))
    username = Prompt.ask("[bold cyan]Enter your username[/]")
    password = Prompt.ask("[bold cyan]Enter your password[/]", password=True)
    password_hash = hash_password(password)
    user_data = load_user_data()
    if username not in user_data or user_data[username]["password"] != password_hash:
        console.print(Panel("Invalid username or password!", title="Error", style="bold red", border_style="red"))
        return None
    console.print(Panel("Sign in successful!", title="Success", style="bold green", border_style="green"))
    return username

# Main function with sign-in/sign-up
def main():
    while True:
        choice = Prompt.ask("[bold cyan]Choose an option[/]", choices=["sign in", "sign up", "exit"], default="exit")
        if choice == "sign up":
            if sign_up():
                continue
        elif choice == "sign in":
            username = sign_in()
            if username:
                # After sign-in, continue with the main functionality
                run_main_app()
                break
        elif choice == "exit":
            console.print(Panel("Exiting...", title="Goodbye", style="bold red", border_style="red"))
            break

# Main app functionality after sign-in
def run_main_app():
    config = load_config()
    ENCRYPTION_KEY = config['ENCRYPTION_KEY'].encode('utf-8')

    # Load RSA keys
    if not os.path.exists(RSA_PRIVATE_KEY_FILE) or not os.path.exists(RSA_PUBLIC_KEY_FILE):
        generate_and_store_rsa_keys()

    RSA_PRIVATE_KEY = load_rsa_private_key()
    RSA_PUBLIC_KEY = load_rsa_public_key()

    # Encrypt data using all methods
    def encrypt_data(data):
        fernet = Fernet(ENCRYPTION_KEY)
        encrypted_fernet = fernet.encrypt(data.encode())
        
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(ENCRYPTION_KEY)
        cipher = Cipher(algorithms.AES(key), modes.GCM(salt))
        encryptor = cipher.encryptor()
        encrypted_aes = encryptor.update(data.encode()) + encryptor.finalize()
        encrypted_aes = base64.urlsafe_b64encode(salt + encryptor.tag + encrypted_aes)
        
        encrypted_rsa = RSA_PUBLIC_KEY.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_rsa = base64.urlsafe_b64encode(encrypted_rsa)

        return {
            "fernet": encrypted_fernet.decode('utf-8'),
            "aes": encrypted_aes.decode('utf-8'),
            "rsa": encrypted_rsa.decode('utf-8')
        }

    # Decrypt data using all methods
    def decrypt_data(secret):
        fernet = Fernet(ENCRYPTION_KEY)
        decrypted_fernet = fernet.decrypt(secret["fernet"].encode()).decode()
        
        encrypted_aes = base64.urlsafe_b64decode(secret["aes"])
        salt = encrypted_aes[:16]
        tag = encrypted_aes[16:32]
        ciphertext = encrypted_aes[32:]
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(ENCRYPTION_KEY)
        cipher = Cipher(algorithms.AES(key), modes.GCM(salt, tag))
        decryptor = cipher.decryptor()
        decrypted_aes = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

        decrypted_rsa = RSA_PRIVATE_KEY.decrypt(
            base64.urlsafe_b64decode(secret["rsa"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        return decrypted_fernet, decrypted_aes, decrypted_rsa

    # Load secrets from file
    def load_secrets():
        if os.path.exists(SECRETS_FILE):
            with open(SECRETS_FILE, 'r') as f:
                return json.load(f)
        return {}

    # Save secrets to file
    def save_secrets(secrets):
        with open(SECRETS_FILE, 'w') as f:
            json.dump(secrets, f, indent=4)

    # Ensure the secrets file exists
    def ensure_secrets_file():
        if not os.path.exists(SECRETS_FILE):
            with open(SECRETS_FILE, 'w') as f:
                json.dump({}, f)
            console.print(Panel("Created new secrets file.", title="Info", style="bold green", border_style="green"))

    # Add Secret
    def add_secret():
        secrets = load_secrets()
        name = Prompt.ask("[bold cyan]Enter secret name[/]")
        value = Prompt.ask("[bold cyan]Enter secret value[/]")
        encrypted_values = encrypt_data(value)
        secrets[name] = encrypted_values
        save_secrets(secrets)
        console.print(Panel("Secret added successfully!", title="Success", style="bold green", border_style="green", padding=(1, 1)))

    # Edit Secret
    def edit_secret():
        secrets = load_secrets()
        name = Prompt.ask("[bold cyan]Enter the name of the secret to edit[/]")
        if name in secrets:
            new_value = Prompt.ask("[bold cyan]Enter new secret value[/]")
            encrypted_values = encrypt_data(new_value)
            secrets[name] = encrypted_values
            save_secrets(secrets)
            console.print(Panel("Secret edited successfully!", title="Success", style="bold green", border_style="green", padding=(1, 1)))
        else:
            console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red", padding=(1, 1)))

    # Get Secret (View)
    def get_secret():
        secrets = load_secrets()
        name = Prompt.ask("[bold cyan]Enter secret name[/]")
        if name in secrets:
            decrypted_values = decrypt_data(secrets[name])
            table = Table(title="Decrypted Secret", show_header=True, header_style="bold magenta")
            table.add_column("Method", style="dim", width=12)
            table.add_column("Decrypted Value")
            table.add_row("Fernet", decrypted_values[0])
            table.add_row("AES", decrypted_values[1])
            table.add_row("RSA", decrypted_values[2])
            console.print(table)
        else:
            console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red", padding=(1, 1)))

    # Delete Secret
    def delete_secret():
        secrets = load_secrets()
        name = Prompt.ask("[bold cyan]Enter the name of the secret to delete[/]")
        if name in secrets:
            del secrets[name]
            save_secrets(secrets)
            console.print(Panel("Secret deleted successfully!", title="Success", style="bold green", border_style="green", padding=(1, 1)))
        else:
            console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red", padding=(1, 1)))

    # List all secrets
    def list_secrets():
        secrets = load_secrets()
        table = Table(title="Stored Secrets", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="dim", width=12)
        table.add_column("Encrypted Value")
        for name, secret in secrets.items():
            table.add_row(name, secret["fernet"])
        console.print(table)

    # Ensure secrets file exists on startup
    ensure_secrets_file()

    # Main loop
    while True:
        choice = Prompt.ask(
            "[bold cyan]What do you want to do?[/]",
            choices=["add", "edit", "view", "delete", "list", "exit"],
            default="exit"
        )

        if choice == "add":
            add_secret()
        elif choice == "edit":
            edit_secret()
        elif choice == "view":
            get_secret()
        elif choice == "delete":
            delete_secret()
        elif choice == "list":
            list_secrets()
        elif choice == "exit":
            console.print(Panel("Exiting...", title="Goodbye", style="bold red", border_style="red"))
            break

if __name__ == "__main__":
    main()

