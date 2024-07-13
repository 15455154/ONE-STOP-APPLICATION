import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from PIL import Image, ImageTk
import csv
import pandas as pd
from openpyxl import load_workbook
from openpyxl.chart import BarChart3D, Reference
import os

# Ensure the path is correct
logo_path = os.path.join(os.path.dirname(__file__), 'Designer (1).ico')

def read_txt_and_convert_to_csv(input_file, output_file):
    with open(input_file, 'r') as txt_file, open(output_file, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        for line in txt_file:
            words = line.strip().split()
            csv_writer.writerow(words)

def create_excel_with_3d_clustered_chart(csv_file, excel_file):
    df = pd.read_csv(csv_file)
    df.to_excel(excel_file, index=False, engine='openpyxl')
    wb = load_workbook(excel_file)
    ws = wb.active
    chart = BarChart3D()
    chart.type = "col"
    chart.grouping = "clustered"
    data = Reference(ws, min_col=2, min_row=1, max_col=ws.max_column, max_row=ws.max_row)
    chart.add_data(data, titles_from_data=True)
    categories = Reference(ws, min_col=1, min_row=2, max_row=ws.max_row)
    chart.set_categories(categories)
    ws.add_chart(chart, "E5")
    wb.save(excel_file)

def open_new_window(button_text):
    new_window = tk.Toplevel()
    new_window.title(button_text)
    new_window.geometry("300x200")
    new_window.configure(bg='#14a3c7')
    try:
        new_window.iconbitmap(logo_path)
    except tk.TclError:
        messagebox.showerror("Error", "Icon file not found!")
    label = tk.Label(new_window, text=f"This is the {button_text} window", bg='#14a3c7', fg='#000000', font=('Arial', 12))
    label.pack(pady=20)

def handle_button_1():
    input_file = filedialog.askopenfilename(title="Select text file", filetypes=[("Text files", "*.txt")])
    if input_file:
        csv_output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save CSV file as")
        if csv_output_file:
            read_txt_and_convert_to_csv(input_file, csv_output_file)
            excel_output_file = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")], title="Save Excel file as")
            if excel_output_file:
                create_excel_with_3d_clustered_chart(csv_output_file, excel_output_file)
    open_new_window("TXT TO EXCEL")

def handle_button_2():
    messagebox.showinfo("Info", "Hi, Mister! This is the bio data collector.\nI will collect a few of your details. Let's start!")
    user_number = simpledialog.askstring("Input", "Please enter your phone number:")
    user_name = simpledialog.askstring("Input", "Please enter your name:")
    user_dob = simpledialog.askstring("Input", "What is your date of birth:")
    user_city = simpledialog.askstring("Input", "What is your city name:")
    user_age = simpledialog.askstring("Input", "What is your age:")
    user_quali = simpledialog.askstring("Input", "What is your qualification:")
    user_blood = simpledialog.askstring("Input", "What is your blood type:")
    user_height = float(simpledialog.askstring("Input", "What is your height (in meters):"))
    user_weight = int(simpledialog.askstring("Input", "What is your weight (in kilograms):"))
    user_nationality = simpledialog.askstring("Input", "What is your nationality:")
    user_sex = simpledialog.askstring("Input", "What is your gender:")
    user_password = simpledialog.askstring("Input", "Please create a password:")
    user_qus = simpledialog.askstring("Input", "What information do you need (e.g., name, birth date, etc.):")
    er_enter = simpledialog.askstring("Input", "Please enter your password:")
    
    if er_enter == user_password:
        response = {
            "name": user_name,
            "number": user_number,
            "birth date": user_dob,
            "age": user_age,
            "qualification": user_quali,
            "blood group": user_blood,
            "height": user_height,
            "weight": user_weight,
            "nationality": user_nationality,
            "gender": user_sex
        }.get(user_qus, "Thank you for using the bio data collector!")
        
        messagebox.showinfo("Info", response)
    else:
        messagebox.showerror("Error", "Incorrect password!")

    data = {
        'Name': [user_name],
        'Age': [user_age],
        'City': [user_city],
        'Date of Birth': [user_dob],
        'Phone Number': [user_number],
        'Qualification': [user_quali],
        'Blood Type': [user_blood],
        'Height': [user_height],
        'Weight': [user_weight],
        'Nationality': [user_nationality],
        'Gender': [user_sex]
    }

    df = pd.DataFrame(data)
    save_location = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")], title="Save Bio Data as")
    if save_location:
        df.to_excel(save_location, index=False)
        messagebox.showinfo("Info", f"Data has been saved to {save_location}")
    open_new_window("BIO DATA TO EXCEL")

def handle_button_3():
    def add(x, y): return x + y
    def subtract(x, y): return x - y
    def multiply(x, y): return x * y
    def divide(x, y): return x / y
    
    messagebox.showinfo("Calculator", "Select operation.\n1.Add\n2.Subtract\n3.Multiply\n4.Divide")

    while True:
        choice = simpledialog.askstring("Input", "Enter choice(1/2/3/4):")
        if choice in ('1', '2', '3', '4'):
            num1 = float(simpledialog.askstring("Input", "Enter first number:"))
            num2 = float(simpledialog.askstring("Input", "Enter second number:"))

            result = {
                '1': f"{num1} + {num2} = {add(num1, num2)}",
                '2': f"{num1} - {num2} = {subtract(num1, num2)}",
                '3': f"{num1} * {num2} = {multiply(num1, num2)}",
                '4': f"{num1} / {num2} = {divide(num1, num2)}"
            }[choice]

            messagebox.showinfo("Result", result)
            break
        else:
            messagebox.showerror("Error", "Invalid Input")
    open_new_window("CALCULATOR")

def handle_button_4():
    basics_info = {
        "print": "The print() function outputs text to the console. Example: print('Hello, World!')",
        "input": "The input() function takes user input. Example: name = input('Enter your name: ')",
        "if": "The if statement is used for conditional execution. Example: if x > 0: print('Positive')",
        "for": "The for loop is used for iterating over a sequence. Example: for i in range(5): print(i)",
        "while": "The while loop is used for repeated execution as long as a condition is true. Example: while x < 5: x += 1",
        "def": "The def keyword is used to define a function. Example: def greet(name): print('Hello, ' + name)",
        "return": "The return statement exits a function and returns a value. Example: def add(a, b): return a + b"
    }

    while True:
        topic = simpledialog.askstring("Python Basics AI", "Ask me about basic Python functions (e.g., print, input, if, for, while, def, return):")
        if topic:
            response = basics_info.get(topic.lower(), "Sorry, I don't have information on that topic.")
            messagebox.showinfo("Python Basics AI", response)
        else:
            break

    open_new_window("LEARN PYTHON")

def display_popup():
    root = tk.Tk()
    root.title("ONE STOP")
    root.geometry("400x400")
    root.configure(bg='#20948B')
    try:
        root.iconbitmap(logo_path)
    except tk.TclError:
        messagebox.showerror("Error", "Icon file not found!")
    image = Image.open(logo_path)
    image = image.resize((100, 100), Image.LANCZOS)
    logo = ImageTk.PhotoImage(image)
    label = tk.Label(root, image=logo, bg='#6AB187')
    label.pack(pady=10)
    button_texts = ["TXT TO EXCEL", "BIODATA TO EXCEL", "CALCULATOR", "LEARN PYTHON"]
    button_commands = [handle_button_1, handle_button_2, handle_button_3, handle_button_4]
    for text, command in zip(button_texts, button_commands):
        button = tk.Button(root, text=text, command=command, bg='#6AB187', fg='black', font=('Roboto', 15))
        button.pack(side=tk.TOP, padx=5, pady=5)
    root.mainloop()

display_popup()
