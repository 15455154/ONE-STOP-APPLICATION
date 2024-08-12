import tkinter as tk
from tkinter import messagebox
import hashlib
import sqlite3

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication Page")
        self.root.geometry("400x300")

        # Initialize SQLite database
        self.conn = sqlite3.connect('users.db')
        self.cursor = self.conn.cursor()
        self.create_table()

        # Show login screen first
        self.create_login_screen()

    def create_table(self):
        # Create users table if it doesn't exist
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                               (username TEXT PRIMARY KEY, password TEXT)''')
        self.conn.commit()

    def create_login_screen(self):
        # Clear existing widgets
        self.clear_widgets()

        # Create login page widgets
        self.title_label = tk.Label(self.root, text="Login", font=("Arial", 24))
        self.title_label.pack(pady=10)
        
        self.username_label = tk.Label(self.root, text="Username:")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=40)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show='*', width=40)
        self.password_entry.pack(pady=5)
        
        self.login_button = tk.Button(self.root, text="Login", command=self.login)
        self.login_button.pack(pady=10)
        
        self.switch_to_signup_button = tk.Button(self.root, text="Don't have an account? Sign Up", command=self.create_signup_screen)
        self.switch_to_signup_button.pack(pady=5)

    def create_signup_screen(self):
        # Clear existing widgets
        self.clear_widgets()

        # Create sign-up page widgets
        self.title_label = tk.Label(self.root, text="Sign Up", font=("Arial", 24))
        self.title_label.pack(pady=10)
        
        self.username_label = tk.Label(self.root, text="Username:")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=40)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show='*', width=40)
        self.password_entry.pack(pady=5)
        
        self.signup_button = tk.Button(self.root, text="Sign Up", command=self.sign_up)
        self.signup_button.pack(pady=10)
        
        self.switch_to_login_button = tk.Button(self.root, text="Already have an account? Login", command=self.create_login_screen)
        self.switch_to_login_button.pack(pady=5)

    def clear_widgets(self):
        # Destroy all widgets in the root window
        for widget in self.root.winfo_children():
            widget.destroy()

    def hash_password(self, password):
        # Hash the password using SHA-256
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Hash the entered password
        hashed_password = self.hash_password(password)

        # Retrieve hashed password from the database
        self.cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()

        if result and result[0] == hashed_password:
            messagebox.showinfo("Login Info", "Login Successful!")
        else:
            messagebox.showerror("Login Error", "Invalid Username or Password")

    def sign_up(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Basic sign-up validation
        if username and password:
            # Check if username exists
            self.cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            if self.cursor.fetchone():
                messagebox.showerror("Sign Up Error", "Username already exists")
            else:
                # Hash the password and store it in the database
                hashed_password = self.hash_password(password)
                self.cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                self.conn.commit()
                messagebox.showinfo("Sign Up Info", "Sign Up Successful!")
                self.create_login_screen()
        else:
            messagebox.showerror("Sign Up Error", "Username and Password cannot be empty")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
