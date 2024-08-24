import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog, ttk
from tkinterdnd2 import TkinterDnD, DND_FILES
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
        side_bar.configure(bg='#333333')
    else:
        root.configure(bg='#FFFFFF')
        style.configure("TButton", background='#000000', foreground='black')
        side_bar.configure(bg='black')

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
            return 0

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
side_bar = tk.Frame(root, bg='white')

# Add buttons to the side bar
ttk.Button(side_bar, text="Biodata to Excel", command=handle_button_2).pack(fill='x', padx=10, pady=5)
ttk.Button(side_bar, text="Dark Mode", command=toggle_dark_mode).pack(fill='x', padx=10, pady=5)

# Button with three slashes to open/close the side bar
menu_button = tk.Button(root, text="≡", command=slide_in_bar, font=('Arial', 18), bg='black', fg='white', borderwidth=0)
menu_button.pack(anchor='nw', padx=10, pady=10)

# To close the side bar, click anywhere outside of it
root.bind("<Button-1>", lambda event: slide_out_bar() if event.x > 200 else None)

# Background customization
root.configure(bg='#000000')  # Light background as default

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
        self.title_label = tk.Label(self.root, text="CodeQuest", font=("Arial", 16))
        self.title_label.pack(pady=10)

        # Instruction label
        self.instruction_label = tk.Label(self.root, text="", wraplength=400)
        self.instruction_label.pack(pady=10)

        # Code input area
        self.code_text = tk.Text(self.root, height=10, width=50)
        self.code_text.pack(pady=10)

        # Run button
        self.run_button = tk.Button(self.root, text="Run Code", command=self.run_code)
        self.run_button.pack(side=tk.LEFT, padx=10)

        # History button
        self.history_button = tk.Button(self.root, text="View History", command=self.view_history)
        self.history_button.pack(side=tk.LEFT, padx=10)

        # Next button
        self.next_button = tk.Button(self.root, text="Next", command=self.next_level)
        self.next_button.pack(side=tk.RIGHT, padx=10)

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
        self.instruction_label.config(text="Welcome to CodeQuest! We'll start by learning basic Python concepts. Click 'Next' to begin.")
        self.code_text.delete("1.0", tk.END)
        self.run_button.config(state=tk.DISABLED)

    def show_print_level(self):
        self.instruction_label.config(text="Level 1: Print Statements\n\nWrite a Python program that prints 'Hello, World!'.")
        self.run_button.config(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)

    def show_input_level(self):
        self.instruction_label.config(text="Level 2: Input\n\nWrite a Python program that asks for your name and prints a greeting message with your name.")
        self.run_button.config(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)

    def show_variable_level(self):
        self.instruction_label.config(text="Level 3: Variables\n\nCreate a variable 'x' and assign it the value 5. Print the value of 'x'.")
        self.run_button.config(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)

    def show_if_level(self):
        self.instruction_label.config(text="Level 4: If Statements\n\nWrite a Python program that asks for a number and prints 'Even' if the number is even and 'Odd' if it is odd.")
        self.run_button.config(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)

    def run_code(self):
        code = self.code_text.get("1.0", tk.END)
        self.history.append(code)
        try:
            exec_globals = {}
            exec(code, {}, exec_globals)
            if self.current_level == 1 and exec_globals.get('print_message') == "Hello, World!":
                self.complete_level()
            elif self.current_level == 2 and exec_globals.get('name') is not None:
                self.complete_level()
            elif self.current_level == 3 and 'x' in exec_globals and exec_globals['x'] == 5:
                self.complete_level()
            elif self.current_level == 4 and 'number' in exec_globals:
                number = exec_globals['number']
                if (number % 2 == 0 and exec_globals.get('result') == 'Even') or (number % 2 != 0 and exec_globals.get('result') == 'Odd'):
                    self.complete_level()
                else:
                    self.incorrect_feedback()
            else:
                self.incorrect_feedback()
        except Exception as e:
            messagebox.showerror("Error", f"Error in your code: {e}")

    def complete_level(self):
        messagebox.showinfo("Congratulations", "You've completed this level!")
        self.current_level += 1
        self.show_level()

    def incorrect_feedback(self):
        messagebox.showerror("Result", "Oops! Your code didn't meet the requirements. Try again.")

    def view_history(self):
        history_text = "\n".join(self.history)
        messagebox.showinfo("Code History", history_text)

    def next_level(self):
        self.current_level += 1
        self.show_level()

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
        lbl_image.config(image=img)
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

# Initialize the main window
image_converter_root = TkinterDnD.Tk()
image_converter_root.title("Image Format Converter")
image_converter_root.geometry("400x400")

# Label to show the dropped image
lbl_image = tk.Label(image_converter_root, text="Drag and drop an image here", bg="gray", width=40, height=10)
lbl_image.pack(pady=20)

# Bind the drag-and-drop event
lbl_image.drop_target_register(DND_FILES)
lbl_image.dnd_bind('<<Drop>>', on_drop)

# Dropdown to select the output format
format_var = tk.StringVar(value="png")
formats = ["png", "jpeg", "bmp", "gif", "tiff"]
tk.OptionMenu(image_converter_root, format_var, *formats).pack(pady=10)

# Button to save the converted image
btn_save = tk.Button(image_converter_root, text="Convert and Save Image", command=save_image)
btn_save.pack(pady=10)

# Function to start CodeQuest
def start_codequest():
    root.withdraw()  # Hide the main window
    codequest_root = tk.Tk()
    app = CodeQuest(codequest_root)
    codequest_root.mainloop()

# Add a button to start CodeQuest
ttk.Button(root, text="Start CodeQuest", command=start_codequest).pack(pady=10)

# Start the Tkinter event loop
open_login_window()  # Automatically open the login window when the app starts
root.mainloop()
