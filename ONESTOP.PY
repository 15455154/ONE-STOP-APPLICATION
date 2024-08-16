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
        style.configure("TButton", background='#000000', foreground='black')

# Define custom styles
style = ttk.Style()
style.configure("TButton",
                font=('Roboto', 15),
                padding=10,
                background='#000000',
                foreground='black')

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
        open_login_window()  # Automatically open login window after registration

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
            login_window.destroy()
            show_main_app()  # Show the main app after successful login
        else:
            messagebox.showwarning("Login Error", "Incorrect password.")

    tk.Button(login_window, text="Login", command=login).pack(pady=10)
    tk.Button(login_window, text="Register", command=open_registration_window).pack(pady=10)  # Option to register

# Basic Python Functions Info
def learn_python_functions():
    basic_functions = {
        "print": "The print() function outputs text to the console.\nExample: print('Hello, World!')",
        "input": "The input() function takes user input.\nExample: name = input('Enter your name: ')",
        "if": "The if statement is used for conditional execution.\nExample: if x > 0: print('Positive')",
        "for": "The for loop is used for iterating over a sequence.\nExample: for i in range(5): print(i)",
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

# Function to show the main app
def show_main_app():
    for widget in main_buttons:
        widget.pack(expand=True, pady=10)
    # Remove login window if still open
    for widget in root.winfo_children():
        if isinstance(widget, tk.Toplevel):
            widget.destroy()

# Adding a Sliding Full Bar with Animation
def slide_in_bar():
    bar_width = 200
    for x in range(-bar_width, 0, 20):
        side_bar.place(x=x, y=0, width=bar_width, height=root.winfo_height())
        root.update()
    side_bar.place(x=0, y=0, width=bar_width, height=root.winfo_height())

def slide_out_bar():
    bar_width = 200
    for x in range(0, -bar_width, -20):
        side_bar.place(x=x, y=0, width=bar_width, height=root.winfo_height())
        root.update()

# Side bar
side_bar = tk.Frame(root, bg='gray')

# Add buttons to the side bar
ttk.Button(side_bar, text="Learn Python", command=learn_python_functions).pack(fill='x', padx=10, pady=5)
ttk.Button(side_bar, text="Biodata to Excel", command=handle_button_2).pack(fill='x', padx=10, pady=5)
ttk.Button(side_bar, text="Dark Mode", command=toggle_dark_mode).pack(fill='x', padx=10, pady=5)

# Button with three slashes to open/closev the side bar
menu_button = tk.Button(root, text="≡", command=slide_in_bar, font=('Arial', 18), bg='black', fg='white', borderwidth=0)
menu_button.pack(anchor='nw', padx=10, pady=10)

# To close the side bar, click anywhere outside of it
root.bind("<Button-1>", lambda event: slide_out_bar() if event.x > 200 else None)

# Background customization
root.configure(bg='#FFFFFF')  # Light background as default

# Start the Tkinter event loop
open_login_window()  # Automatically open the login window when the app starts
root.mainloop()

