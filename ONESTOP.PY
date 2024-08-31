import customtkinter as ctk
from tkinter import simpledialog, messagebox, filedialog
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

# Color schemes
dark_mode_colors = {
    "background": "#1E1E1E",
    "sidebar": "#2E2E2E",
    "button": "#3E3E3E",
    "text": "#FFFFFF"  # White text for dark mode
}

light_mode_colors = {
    "background": "#FFFFFF",
    "sidebar": "#F0F0F0",
    "button": "#E0E0E0",
    "text": "#000000"  # Black text for light mode
}

# Function to toggle dark mode
def toggle_dark_mode():
    if dark_mode.get():
        root.configure(bg=dark_mode_colors["background"])
        side_bar.configure(fg_color=dark_mode_colors["sidebar"])
        for widget in root.winfo_children():
            if isinstance(widget, ctk.CTkLabel) or isinstance(widget, ctk.CTkButton) or isinstance(widget, ctk.CTkTextbox):
                widget.configure(fg_color=dark_mode_colors["button"], text_color=dark_mode_colors["text"])
            if isinstance(widget, ctk.CTkToplevel):
                for sub_widget in widget.winfo_children():
                    if isinstance(sub_widget, ctk.CTkLabel) or isinstance(sub_widget, ctk.CTkButton):
                        sub_widget.configure(text_color=dark_mode_colors["text"])
    else:
        root.configure(bg=light_mode_colors["background"])
        side_bar.configure(fg_color=light_mode_colors["sidebar"])
        for widget in root.winfo_children():
            if isinstance(widget, ctk.CTkLabel) or isinstance(widget, ctk.CTkButton) or isinstance(widget, ctk.CTkTextbox):
                widget.configure(fg_color=light_mode_colors["button"], text_color=light_mode_colors["text"])
            if isinstance(widget, ctk.CTkToplevel):
                for sub_widget in widget.winfo_children():
                    if isinstance(sub_widget, ctk.CTkLabel) or isinstance(sub_widget, ctk.CTkButton):
                        sub_widget.configure(text_color=light_mode_colors["text"])

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
    
    # Initialize the sidebar frame
    global side_bar
    side_bar = ctk.CTkFrame(root, width=200, height=root.winfo_height(), fg_color=light_mode_colors["sidebar"])
    side_bar.pack(side="left", fill="y")

    # Add widgets to sidebar
    btn1 = ctk.CTkButton(side_bar, text="Open BioData Collector", command=handle_button_2)
    btn1.pack(pady=20)

    btn2 = ctk.CTkButton(side_bar, text="Start CodeQuest", command=lambda: CodeQuest(root))
    btn2.pack(pady=20)

    btn3 = ctk.CTkButton(side_bar, text="Convert Image", command=open_image_converter)
    btn3.pack(pady=20)

    # Add dark mode toggle
    dark_mode_toggle = ctk.CTkSwitch(side_bar, text="Dark Mode", variable=dark_mode, command=toggle_dark_mode)
    dark_mode_toggle.pack(pady=20)

    # Add sidebar movement functionality
    def on_drag_start(event):
        side_bar._drag_start_x = event.x
        side_bar._drag_start_y = event.y

    def on_drag_motion(event):
        x = side_bar.winfo_x() - side_bar._drag_start_x + event.x
        y = side_bar.winfo_y() - side_bar._drag_start_y + event.y
        side_bar.place(x=x, y=y)

    side_bar.bind("<Button-1>", on_drag_start)
    side_bar.bind("<B1-Motion>", on_drag_motion)

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
    file_path = event.data
    file_path = file_path.strip('{}')  # Remove curly braces if present

    if os.path.isfile(file_path):
        convert_image(file_path, format_var.get())
    else:
        messagebox.showwarning("Invalid File", "The dropped file is not valid.")

def open_image_converter():
    image_converter_window = ctk.CTkToplevel(root)
    image_converter_window.title("Image Converter")
    image_converter_window.geometry("300x300")

    global format_var
    format_var = ctk.StringVar(value="png")

    ctk.CTkLabel(image_converter_window, text="Select output format:").pack(pady=5)
    formats = ["png", "jpg", "bmp", "gif", "tiff"]
    for format in formats:
        ctk.CTkRadioButton(image_converter_window, text=format.upper(), variable=format_var, value=format).pack(pady=2)

    ctk.CTkButton(image_converter_window, text="Save Image", command=lambda: convert_image(file_path, format_var.get())).pack(pady=10)

    # Drag and drop functionality
    image_converter_window.drop_target_register(DND_FILES)
    image_converter_window.dnd_bind('<<Drop>>', on_drop)

# Initialize the main window
open_login_window()  # Open the login window initially

# Run the application
root.mainloop()


