import customtkinter as ctk
from tkinter import simpledialog, messagebox, filedialog, ttk
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk
import os
import pandas as pd
import bcrypt

# Set the color theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("green")

# Create the main Tkinter window
root = ctk.CTk()
root.title("ONE STOP")
root.geometry("1000x1000")

# Ensure the path is correct
logo_path = os.path.join(os.path.dirname(__file__), 'Designer (1).ico')
root.iconbitmap(logo_path)

# Dark mode variable
dark_mode = ctk.BooleanVar()

# Function to toggle dark mode
def toggle_dark_mode():
    if dark_mode.get():
        root.configure(bg_color='#1E1E1E')
        side_bar.configure(bg_color='#000000')
    else:
        root.configure(bg_color='#FFFFFF')
        side_bar.configure(bg_color='#FFFFFF')

# Function for user registration
def open_registration_window():
    registration_window = ctk.CTkToplevel(root)
    registration_window.title("Register")
    registration_window.geometry("300x200")

    ctk.CTkLabel(registration_window, text="Username:").pack(pady=5)
    username_entry = ctk.CTkEntry(registration_window)
    username_entry.pack(pady=5)

    ctk.CTkLabel(registration_window, text="Password:").pack(pady=5)
    password_entry = ctk.CTkEntry(registration_window, show="*")
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

    ctk.CTkButton(registration_window, text="Register", command=register).pack(pady=10)

# Function for user login
def open_login_window():
    login_window = ctk.CTkToplevel(root)
    login_window.title("Login")
    login_window.geometry("500x500")

    ctk.CTkLabel(login_window, text="Username:").pack(pady=10)
    username_entry = ctk.CTkEntry(login_window)
    username_entry.pack(pady=20)

    ctk.CTkLabel(login_window, text="Password:").pack(pady=50)
    password_entry = ctk.CTkEntry(login_window, show="*")
    password_entry.pack(pady=0)

    def login():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        file_exists = os.path.isfile('credentials.csv')
        if not file_exists:
            messagebox.showwarning("Login Error", "No registered users found.")
            return 0

        df = pd.read_csv('credentials.csv')

        if username not in df['Username'].values:
            messagebox.showwarning("Login Error", "Username not found.")
            return 0

        stored_hashed_password = df.loc[df['Username'] == username, 'Password'].values[0]
        if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
            messagebox.showinfo("Login Success", "Login successful!")
            login_window.destroy()
            show_main_app()  # Show the main app after successful login
        else:
            messagebox.showwarning("Login Error", "Incorrect password.")

    ctk.CTkButton(login_window, text="Login", command=login).pack(pady=10)
    ctk.CTkButton(login_window, text="Register", command=open_registration_window).pack(pady=10)  # Option to register

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
    for widget in root.winfo_children():
        if isinstance(widget, ctk.CTkToplevel):
            widget.destroy()

# Image Converter Tool
def convert_image(filepath, output_format):
    # Load the image
    image = Image.open(filepath)
    
    # Save it in the selected format
    output_filename = os.path.splitext(filepath)[0] + '.' + output_format
    image.save(output_filename, output_format.upper())
    
    # Notify the user
    messagebox.showinfo("Success", f"Image saved as {output_filename}")

def on_drop(event):
    # Get the dropped file path
    filepath = event.data
    
    # Check if it is a valid image file
    if filepath.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff')):
        img = Image.open(filepath)
        img.thumbnail((300, 300))  # Resize image for display
        
        # Display the image
        img = ImageTk.PhotoImage(img)
        lbl_image.configure(image=img)
        lbl_image.image = img
        
        # Store the file path
        lbl_image.filepath = filepath
    else:
        messagebox.showerror("Invalid file", "Please drop a valid image file.")

def save_image():
    # Get the file path and selected format
    filepath = getattr(lbl_image, 'filepath', None)
    output_format = format_var.get()
    
    if filepath and output_format:
        convert_image(filepath, output_format)
    else:
        messagebox.showerror("Error", "No image loaded or format selected.")

# CodeQuest Game
class CodeQuest:
    def __init__(self, root):
        self.root = root
        self.root.title("CodeQuest")
        self.current_level = 0
        self.history = []
        self.create_widgets()
        self.show_level()

    def create_widgets(self):
        # Title label
        self.title_label = ctk.CTkLabel(self.root, text="CodeQuest", font=("Arial", 16))
        self.title_label.pack(pady=10)

        # Instruction label
        self.instruction_label = ctk.CTkLabel(self.root, text="", wraplength=400)
        self.instruction_label.pack(pady=10)

        # Code input area
        self.code_text = ctk.CTkTextbox(self.root, height=10, width=50)
        self.code_text.pack(pady=10)

        # Run button
        self.run_button = ctk.CTkButton(self.root, text="Run Code", command=self.run_code)
        self.run_button.pack(side=ctk.LEFT, padx=10)

        # History button
        self.history_button = ctk.CTkButton(self.root, text="View History", command=self.view_history)
        self.history_button.pack(side=ctk.LEFT, padx=10)

        # Next button
        self.next_button = ctk.CTkButton(self.root, text="Next", command=self.next_level)
        self.next_button.pack(side=ctk.RIGHT, padx=10)

    def show_level(self):
        if self.current_level == 0:
            self.show_intro()
        elif self.current_level == 1:
            self.show_print_level()
        elif self.current_level == 2:
            self.show_input_level()
        elif self.current_level == 3:
            self.show_variable_level()
        elif self.current_level == 4:
            self.show_if_level()
        else:
            messagebox.showinfo("Congratulations", "You've completed all levels!")

    def show_intro(self):
        self.instruction_label.configure(text="Welcome to CodeQuest! We'll start by learning basic Python concepts. Click 'Next' to begin.")
        self.code_text.delete("1.0", ctk.END)
        self.run_button.configure(state=ctk.DISABLED)

    def show_print_level(self):
        self.instruction_label.configure(text="Level 1: Use the print() function to display 'Hello, World!'.")
        self.code_text.delete("1.0", ctk.END)
        self.run_button.configure(state=ctk.NORMAL)

    def show_input_level(self):
        self.instruction_label.configure(text="Level 2: Use the input() function to ask the user for their name.")
        self.code_text.delete("1.0", ctk.END)

    def show_variable_level(self):
        self.instruction_label.configure(text="Level 3: Create a variable to store the user's age and print it.")
        self.code_text.delete("1.0", ctk.END)

    def show_if_level(self):
        self.instruction_label.configure(text="Level 4: Use an if statement to check if the user's age is over 18.")
        self.code_text.delete("1.0", ctk.END)

    def run_code(self):
        code = self.code_text.get("1.0", ctk.END)
        self.history.append(code)

        try:
            exec(code, {})
            messagebox.showinfo("Success", "Code ran successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{e}")

    def view_history(self):
        history_window = ctk.CTkToplevel(self.root)
        history_window.title("Code History")
        history_window.geometry("400x300")

        history_text = ctk.CTkTextbox(history_window, state=ctk.NORMAL)
        history_text.pack(expand=True, fill=ctk.BOTH)

        for entry in self.history:
            history_text.insert(ctk.END, entry + "\n")

    def next_level(self):
        self.current_level += 1
        self.show_level()

# Main sidebar for options
side_bar = ctk.CTkFrame(root)
side_bar.pack(side=ctk.LEFT, fill='y', padx=10, pady=10)

ctk.CTkButton(side_bar, text="Register", command=open_registration_window).pack(fill='x', padx=10, pady=5)
ctk.CTkButton(side_bar, text="Login", command=open_login_window).pack(fill='x', padx=10, pady=5)
ttk.Button(side_bar, text="Biodata to Excel", command=handle_button_2).pack(fill='x', padx=10, pady=5)

# Dark mode toggle
dark_mode_toggle = ctk.CTkCheckBox(side_bar, text="Dark Mode", variable=dark_mode, command=toggle_dark_mode)
dark_mode_toggle.pack(fill='x', padx=10, pady=5)

# Button to open Image Converter
def open_image_converter():
    converter_window = ctk.CTkToplevel(root)
    converter_window.title("Image Converter")
    converter_window.geometry("400x400")

    lbl_instruction = ctk.CTkLabel(converter_window, text="Drag and drop an image file below:")
    lbl_instruction.pack(pady=10)

    global lbl_image
    lbl_image = ctk.CTkLabel(converter_window)
    lbl_image.pack(pady=10)

    format_var = ctk.StringVar()
    format_var.set("png")  # Default format is PNG

    ctk.CTkOptionMenu(converter_window, variable=format_var, values=["png", "jpg", "bmp", "gif", "tiff"]).pack(pady=10)
    ctk.CTkButton(converter_window, text="Convert Image", command=save_image).pack(pady=10)

    converter_window.drop_target_register(DND_FILES)
    converter_window.dnd_bind('<<Drop>>', on_drop)

ttk.Button(side_bar, text="Image Converter", command=open_image_converter).pack(fill='x', padx=10, pady=5)

# Initialize CodeQuest game
codequest = CodeQuest(root)

# Run the main Tkinter loop
root.mainloop()

