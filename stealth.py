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
from rich.text import Text
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

    # Generate RSA keys
    def generate_rsa_keys():
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
        return private_pem, public_pem

    RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa_keys()

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
        
        public_key = serialization.load_pem_public_key(RSA_PUBLIC_KEY)
        encrypted_rsa = public_key.encrypt(
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

        private_key = serialization.load_pem_private_key(RSA_PRIVATE_KEY, password=None)
        decrypted_rsa = private_key.decrypt(
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
            with open(SECRETS_FILE, 'w') as f):
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
        secret = secrets.get(name)
        if secret:
            try:
                decrypted_values = decrypt_data(secret)
                console.print(Panel(f"[bold blue]Decrypted Values:\nFernet: {decrypted_values[0]}\nAES: {decrypted_values[1]}\nRSA: {decrypted_values[2]}", title="Secret Retrieved", style="bold blue", border_style="blue", padding=(1, 1)))
            except Exception as e:
                console.print(Panel(f"Error: {e}", title="Decryption Error", style="bold red", border_style="red", padding=(1, 1)))
        else:
            console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red", padding=(1, 1)))

    # List Secrets
    def list_secrets():
        secrets = load_secrets()
        table = Table(title="Secrets", show_header=True, header_style="bold magenta", box=box.ROUNDED, padding=(1, 1))
        table.add_column("Name", style="cyan", no_wrap=True)
        for name in secrets:
            table.add_row(name)
        console.print(table)

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

    # Display menu with ASCII art and borders
    def display_menu():
        header = Text("Secret Manager CLI", justify="center", style="bold white on blue")
        header.append("\n[Version 1.0]", style="bold yellow")
        header.append("\n\nManage your secrets securely with encryption and time-based keys.", style="dim white")
        console.print(Panel(header, title="Welcome", border_style="blue", padding=(1, 1))
        console.print(Panel("""
[bold cyan]1.[/] [bold white]Add Secret[/]
[bold cyan]2.[/] [bold white]Edit Secret[/]
[bold cyan]3.[/] [bold white]View Secret[/]
[bold cyan]4.[/] [bold white]List All Secrets[/]
[bold cyan]5.[/] [bold white]Delete Secret[/]
[bold cyan]6.[/] [bold white]Exit[/]""", border_style="blue", padding=(1, 2)))

    # Ensure the secrets file exists
    ensure_secrets_file()

    # Main loop
    while True:
        display_menu()
        choice = Prompt.ask("[bold cyan]Choose an option[/]", choices=["1", "2", "3", "4", "5", "6"], default="6")
        if choice == "1":
            add_secret()
        elif choice == "2":
            edit_secret()
        elif choice == "3":
            get_secret()
        elif choice == "4":
            list_secrets()
        elif choice == "5":
            delete_secret()
        elif choice == "6":
            console.print(Panel("Exiting...", title="Goodbye", style="bold red", border_style="red", padding=(1, 1)))
            break

if __name__ == "__main__":
    main()
