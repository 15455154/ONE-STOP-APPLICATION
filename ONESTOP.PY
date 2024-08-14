import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog, ttk
from PIL import Image, ImageTk
import os
import pandas as pd
import bcrypt

# Ensure the path is correct
logo_path = os.path.join(os.path.dirname(__file__), 'Designer (1).ico')

# Create the main Tkinter window
root = tk.Tk()
root.title("ONE STOP")
root.geometry("400x400")

# Set the logo icon for the window
root.iconbitmap(logo_path)

# Dark mode variable
dark_mode = tk.BooleanVar()

# Function to toggle dark mode
def toggle_dark_mode():
    if dark_mode.get():
        root.configure(bg='#1E1E1E')
        style.configure("TButton", background='#39FF14', foreground='black')
    else:
        root.configure(bg='#FFFFFF')
        style.configure("TButton", background='#000000', foreground='white')

# Define custom styles
style = ttk.Style()
style.configure("TButton",
                font=('Roboto', 15),
                padding=10,
                background='#000000',
                foreground='white')

# Function for user registration
def open_registration_window():
    registration_window = tk.Toplevel(root)
    registration_window.title("Register")
    registration_window.geometry("300x200")

    tk.Label(registration_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(registration_window)
    username_entry.pack(pady=5)

    tk.Label(registration_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(registration_window, show="*")
    password_entry.pack(pady=5)

    def register():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        # Load existing credentials or create a new DataFrame
        file_exists = os.path.isfile('credentials.csv')
        if file_exists:
            df = pd.read_csv('credentials.csv')
        else:
            df = pd.DataFrame(columns=['Username', 'Password'])

        if username in df['Username'].values:
            messagebox.showwarning("Registration Error", "Username already exists.")
            return

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Add new user to DataFrame
        new_data = pd.DataFrame({'Username': [username], 'Password': [hashed_password.decode()]})
        df = pd.concat([df, new_data], ignore_index=True)
        df.to_csv('credentials.csv', index=False)
        messagebox.showinfo("Registration Success", "User registered successfully!")
        registration_window.destroy()

    tk.Button(registration_window, text="Register", command=register).pack(pady=10)

# Function for user login
def open_login_window():
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    def login():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        file_exists = os.path.isfile('credentials.csv')
        if not file_exists:
            messagebox.showwarning("Login Error", "No registered users found.")
            return

        df = pd.read_csv('credentials.csv')

        if username not in df['Username'].values:
            messagebox.showwarning("Login Error", "Username not found.")
            return

        stored_hashed_password = df.loc[df['Username'] == username, 'Password'].values[0]
        if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
            messagebox.showinfo("Login Success", "Login successful!")
        else:
            messagebox.showwarning("Login Error", "Incorrect password.")

    tk.Button(login_window, text="Login", command=login).pack(pady=10)

# Basic Python Functions Info
def learn_python_functions():
    basic_functions = {
        "print": "The print() function outputs text to the console.\nExample: print('Hello, World!')",
        "input": "The input() function takes user input.\nExample: name = input('Enter your name: ')",
        "if": "The if statement is used for conditional execution.\nExample: if x > 0: print('Positive')",
        "for": "The for loop is used for iterating over a sequence.\nExample: for i in range(5): print(i)",
        "while": "The while loop is used for repeated execution as long as a condition is true.\nExample: while x < 5: x += 1",
    }
    topic = simpledialog.askstring("Learn Python", "Ask me about basic Python functions (e.g., print, input, if, for, while):")
    if topic:
        response = basic_functions.get(topic.lower(), "Sorry, I don't have information on that topic.")
        messagebox.showinfo("Python Basics", response)

# BioData Collector function
def handle_button_2():
    user_name = simpledialog.askstring("Input", "Please enter your name:")
    if not user_name:
        return
    user_age = simpledialog.askstring("Input", "What is your age:")
    user_city = simpledialog.askstring("Input", "What is your city name:")

    data = {
        'Name': [user_name],
        'Age': [user_age],
        'City': [user_city]
    }

    df = pd.DataFrame(data)
    save_location = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
    if save_location:
        df.to_excel(save_location, index=False)
        messagebox.showinfo("Info", f"Data has been saved to {save_location}")

    # Close the biodata window after saving
    root.destroy()

# Adding buttons with centered layout
button_texts = ["Learn Python", "Biodata to Excel", "Toggle Dark Mode", "Register", "Login"]
button_commands = [learn_python_functions, handle_button_2, toggle_dark_mode, open_registration_window, open_login_window]

for text, command in zip(button_texts, button_commands):
    button = ttk.Button(root, text=text, style="TButton", command=command)
    button.pack(expand=True, pady=10)

# Dark mode toggle button
dark_mode_button = ttk.Checkbutton(root, text="Dark Mode", variable=dark_mode, command=toggle_dark_mode)
dark_mode_button.pack(expand=True, pady=10)

# Background customization
root.configure(bg='#FFFFFF')  # Light background as default

# Start the Tkinter event loop
root.mainloop()

