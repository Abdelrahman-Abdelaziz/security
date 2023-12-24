import tkinter as tk
from tkinter import scrolledtext, filedialog

class ClientWindow(tk.Toplevel):
    shared_messages = []  # Shared data structure for messages
    server_chat = None
    client_chat = None

    def __init__(self, master, title):
        super().__init__(master.root)
        self.title(title)


        # Create a text widget for the chat messages
        self.chat_box = scrolledtext.ScrolledText(self, width=40, height=30, state="disabled")
        self.chat_box.pack(padx=10, pady=10)

        # Create a frame for the message entry, label, and send button
        message_frame = tk.Frame(self)
        message_frame.pack(pady=10)

        # Create an entry widget for typing messages
        self.message_entry = tk.Entry(message_frame, width=30)
        self.message_entry.pack(side=tk.LEFT, padx=5)

        # Create a button to send messages
        send_button = tk.Button(message_frame, text="Send Text", command=self.send_message)
        send_button.pack(side=tk.LEFT, padx=5)

        # Create a button for uploading a file
        upload_button = tk.Button(self, text="Upload File", command=self.upload_file)
        upload_button.pack(pady=10)

        # Make the chat window unresizable
        self.resizable(width=False, height=False)

    def send_message(self):            
        message = self.message_entry.get()
        if message:  # Check if the message is not empty
            sender_name = self.title()  # The sender will have his Chat Window's Title as his name

            message_with_sender = f"{sender_name}: {message}\n" # This is where encryption will be done

            # Update the shared messages data structure
            ChatWindow.shared_messages.append(message_with_sender)

            # Update the local chat box
            self.update_chat_box()

            # Update the other chat window's chat box
            other_window = self.master.server_chat if sender_name == "Client" else self.master.client_chat
            other_window.update_chat_box()

            # Clear the message entry
            self.message_entry.delete(0, tk.END)

            # Add code here to send the message to the other chat window or server

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:  # Check if a file is selected
            sender_name = self.title()  # Get the window title (Server or Client)
            file_message = f"{sender_name} uploaded a file: {file_path}\n"

            # Update the shared messages data structure
            ChatWindow.shared_messages.append(file_message)

            # Update the local chat box
            self.update_chat_box()

            # Update the other chat window's chat box
            other_window = self.master.server_chat if sender_name == "Client" else self.master.client_chat
            other_window.update_chat_box()

            # Add code here to handle the uploaded file

    def update_chat_box(self):
        # Enable the text widget temporarily
        self.chat_box.config(state="normal")

        # Clear the current content
        self.chat_box.delete("1.0", tk.END)

        # Insert all messages in the shared data structure
        for message in ChatWindow.shared_messages:
            self.chat_box.insert(tk.END, message)

        # Disable the text widget again
        self.chat_box.config(state="disabled")