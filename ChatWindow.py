import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
import socket
import threading

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat App")
        self.root.geometry("500x500")
        self.custom_font = ("Arial", 14)

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack()

        label = tk.Label(self.current_frame, text="Welcome to Chat App", font=self.custom_font)
        label.pack(pady=20)

        chat_button = tk.Button(self.current_frame, text="Start Chat", font=self.custom_font, command=self.create_chat_frame)
        chat_button.pack(pady=10)

        quit_button = tk.Button(self.current_frame, text="Quit", font=self.custom_font, command=self.root.destroy)
        quit_button.pack(pady=10)

    def create_chat_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Chat Window", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.destroy_chat_windows)
        back_button.pack(pady=10)

        label = tk.Label(self.current_frame, text="You are now in chat mode\nIt is a kind of chat simulation to show\nthe secure chat functionality", font=self.custom_font)
        label.pack(pady=20)

        # Create two independent chat windows
        self.server_chat = ChatWindow(self, title="Server", port=1234)
        self.client_chat = ChatWindow(self, title="Client", port=5678)

        # Set the positions of the chat windows
        screen_width = self.root.winfo_screenwidth()
        window_width = 450  # Adjust the width as needed

        # Position chat_window1 on the left side
        self.server_chat.geometry(f"{window_width}x600+0+0")

        # Position chat_window2 on the right side
        self.client_chat.geometry(f"{window_width}x600+{screen_width - window_width}+0")

        # Connect the chat windows through sockets
        self.server_chat.connect_to(5678) # Connect to the client port
        self.client_chat.connect_to(1234) # Connect to the server port

        self.current_frame.pack()

    def destroy_chat_windows(self):
        self.server_chat.destroy()
        self.client_chat.destroy()
        self.current_frame.destroy()
        self.__init__(self.root)


class ChatWindow(tk.Toplevel):
    shared_messages = []  # Shared data structure for messages
    server_chat = None
    client_chat = None

    def __init__(self, master, title, port):
        super().__init__(master.root)
        self.title(title)
        self.port = port

        if title == "Server":
            ChatWindow.server_chat = self
        elif title == "Client":
            ChatWindow.client_chat = self

        # Create a socket object
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        self.socket.bind(("127.0.0.1", self.port))

        # Listen for incoming connections
        self.socket.listen(5)

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

    def connect_to(self, port):
        # Connect to the chat window on the same machine using port
        print(port)
        print(type(port))

        # Connect to the other chat window
        self.socket.connect(('127.0.0.1', int(port)))

        # Create a thread to listen for incoming messages
        self.listen_thread = threading.Thread(target=self.listen_for_messages)
        self.listen_thread.start()


    def listen_for_messages(self):
        # Listen for messages from the other chat window
        while True:
            try:
                # Accept a connection from the socket
                conn, addr = self.socket.accept()

                # Receive a message from the connection
                message = conn.recv(1024).decode()

                # If the message is empty, close the connection
                if not message:
                    conn.close()
                    break

                # Display the message on the chat box
                self.display_message(message, sender="Other")

            except Exception as e:
                # Handle any exceptions
                print(e)
                break

    def send_message(self):
        # Get the message from the entry widget
        message = self.message_entry.get()

        # If the message is not empty, send it to the other chat window
        if message:
            try:
                # Send the message to the socket
                self.socket.send(message.encode())

                # Display the message on the chat box
                self.display_message(message, sender="You")

                # Clear the entry widget
                self.message_entry.delete(0, tk.END)

            except Exception as e:
                # Handle any exceptions
                print(e)

    def display_message(self, message, sender):
        # Enable the chat box to insert text
        self.chat_box.config(state="normal")

        # Insert the message with the sender name
        self.chat_box.insert(tk.END, f"{sender}: {message}\n")

        # Disable the chat box to prevent editing
        self.chat_box.config(state="disabled")

        # Scroll to the end of the chat box
        self.chat_box.yview(tk.END)

    def upload_file(self):
        # Ask the user to choose a file to upload
        file_path = filedialog.askopenfilename()

        # If the file path is not empty, send the file name and content to the other chat window
        if file_path:
            try:
                # Get the file name and content
                file_name = file_path.split("/")[-1]
                file_content = open(file_path, "rb").read()

                # Send the file name and content to the socket
                self.socket.send(f"FILE:{file_name}".encode())
                self.socket.send(file_content)

                # Display the file name on the chat box
                self.display_message(f"Uploaded file: {file_name}", sender="You")

            except Exception as e:
                # Handle any exceptions
                print(e)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
