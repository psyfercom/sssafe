from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import os
import json
import subprocess
import pyotp
import time

console = Console()

# Path to the secrets file
SECRETS_FILE = "secrets.json"
# TOTP Secret Key (For demonstration, should be securely stored/managed)
TOTP_SECRET = pyotp.random_base32()

# Remote GitHub repository URL
GITHUB_REPO_URL = "https://github.com/psyfercom/stealthstrings.git"

# Generate a key
def generate_key():
    key = Fernet.generate_key()
    console.print(Panel(Text(f"Generated Encryption Key: {key.decode()}", style="bold green"), title="New Key", border_style="green"))
    return key

# Generate TOTP based encryption key
def generate_totp_key():
    totp = pyotp.TOTP(TOTP_SECRET)
    otp = totp.now()  # Generate TOTP
    combined_key = f"{otp}".encode()
    fernet_key = Fernet.generate_key()  # Generate a random key for additional security
    console.print(Panel(f"TOTP-based Key: {otp}", title="TOTP Key", border_style="magenta"))
    return combined_key, fernet_key

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

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

# Add Secret
def add_secret():
    secrets = load_secrets()
    name = Prompt.ask("[bold yellow]Enter secret name[/]")
    value = Prompt.ask("[bold yellow]Enter secret value[/]")
    _, fernet_key = generate_totp_key()  # Generate TOTP key
    encrypted_value = encrypt_data(value, fernet_key)
    secrets[name] = encrypted_value.decode('utf-8')
    save_secrets(secrets)
    console.print(Panel("Secret added successfully!", title="Success", style="bold green", border_style="green"))
    git_commit_and_push("Added a new secret")

# Edit Secret
def edit_secret():
    secrets = load_secrets()
    name = Prompt.ask("[bold yellow]Enter the name of the secret to edit[/]")
    if name in secrets:
        new_value = Prompt.ask("[bold yellow]Enter new secret value[/]")
        _, fernet_key = generate_totp_key()  # Generate TOTP key
        encrypted_value = encrypt_data(new_value, fernet_key)
        secrets[name] = encrypted_value.decode('utf-8')
        save_secrets(secrets)
        console.print(Panel("Secret edited successfully!", title="Success", style="bold green", border_style="green"))
        git_commit_and_push("Edited a secret")
    else:
        console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red"))

# Get Secret (View)
def get_secret():
    secrets = load_secrets()
    name = Prompt.ask("[bold yellow]Enter secret name[/]")
    _, fernet_key = generate_totp_key()  # Generate TOTP key
    encrypted_value = secrets.get(name)
    if encrypted_value:
        try:
            value = decrypt_data(encrypted_value.encode(), fernet_key)
            console.print(Panel(f"[bold blue]Secret Value:[/bold blue] {value}", title="Secret Retrieved", style="bold blue", border_style="blue"))
        except Exception as e:
            console.print(Panel(f"Error: {e}", title="Decryption Error", style="bold red", border_style="red"))
    else:
        console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red"))

# List Secrets
def list_secrets():
    secrets = load_secrets()
    table = Table(title="Secrets", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Name", style="cyan", no_wrap=True)
    for name in secrets:
        table.add_row(name)
    console.print(table)

# Delete Secret
def delete_secret():
    secrets = load_secrets()
    name = Prompt.ask("[bold yellow]Enter the name of the secret to delete[/]")
    if name in secrets:
        del secrets[name]
        save_secrets(secrets)
        console.print(Panel("Secret deleted successfully!", title="Success", style="bold green", border_style="green"))
        git_commit_and_push("Deleted a secret")
    else:
        console.print(Panel("Secret not found!", title="Error", style="bold red", border_style="red"))

# Git Commit and Push
def git_commit_and_push(message):
    try:
        subprocess.run(["gh", "auth", "login", "--with-token"], input=f"{os.environ.get('GITHUB_TOKEN')}\n", text=True, check=True)
        subprocess.run(["git", "remote", "set-url", "origin", GITHUB_REPO_URL], check=True)
        subprocess.run(["git", "add", SECRETS_FILE], check=True)
        subprocess.run(["git", "commit", "-m", message], check=True)
        subprocess.run(["git", "push"], check=True)
        console.print(Panel("Changes pushed to GitHub!", title="GitHub", style="bold green", border_style="green"))
    except subprocess.CalledProcessError as e:
        console.print(Panel(f"Error: {e}", title="GitHub Error", style="bold red", border_style="red"))

# Display menu with ASCII art and borders
def display_menu():
    header = Text("Secret Manager CLI", justify="center", style="bold white on blue")
    header.append("\n[Version 1.0]", style="bold yellow")
    header.append("\n\nManage your secrets securely with encryption and time-based keys.", style="dim white")
    console.print(Panel(header, title="Welcome", border_style="blue"))
    console.print(Panel("""
[bold yellow]1.[/] [bold white]Add Secret[/]
[bold yellow]2.[/] [bold white]Edit Secret[/]
[bold yellow]3.[/] [bold white]View Secret[/]
[bold yellow]4.[/] [bold white]List All Secrets[/]
[bold yellow]5.[/] [bold white]Delete Secret[/]
[bold yellow]6.[/] [bold white]Exit[/]""", border_style="blue", padding=(1, 2)))

# Main loop
def main():
    while True:
        display_menu()
        choice = Prompt.ask("[bold yellow]Choose an option[/]", choices=["1", "2", "3", "4", "5", "6"], default="6")
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
            console.print(Panel("Exiting...", title="Goodbye", style="bold red", border_style="red"))
            break

if __name__ == "__main__":
    main()
