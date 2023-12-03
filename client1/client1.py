import logging
import signal
import socket
import sys
import threading
from tkinter import *
import tkinter as app
from tkinter import messagebox, Tk
import os
import ast


CLIENT_FOLDER = "client1_folder"

class appClient:
    def __init__(self, host, port, host_c, port_c):
        # Create client - client
        self.my_host = host_c
        self.my_port = port_c
        self.my_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.lock = threading.Lock()

        self.server_host = host
        self.server_port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upload_progress_callback = None

        signal.signal(signal.SIGINT, self.handle_sigint)

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.login_thread_flag = threading.Event()

    def start(self):
        try:
            self.my_client.bind((self.my_host, self.my_port))
            self.my_client.listen(10)
            logging.info(f"Client listening on {self.my_host}:{self.my_port}")

            self.client_socket.connect((self.server_host, self.server_port))
            print(f"Connected to the server at {self.server_host}:{self.server_port}.")

            login_thread = threading.Thread(target=self.login_form, args=(self.client_socket,), daemon=True)
            login_thread.start()

            # Start the command-shell interpreter
            while True:

                client_connect, client_address = self.my_client.accept()
                logging.info(f"New connection from {client_address}")
                # Create a new thread to handle the client
                connect_client_thread = threading.Thread(target=self.handle_client, args=(client_connect,))
                connect_client_thread.start()

        except ConnectionRefusedError:
            print(f"Error: Unable to connect to the server at {self.server_host}:{self.server_port}.")
        except Exception as e:
            self.logger.error(f"Error connecting to the server: {e}")
        finally:
            # Close the socket when the program exits (if it was successfully created)
            if self.client_socket:
                self.client_socket.close()

    def handle_client(self, client_connect):
        # Add the client to the list of connected clients
        client_address = client_connect.getpeername()
        with self.lock:
            self.clients[client_address] = client_connect

        try:
            while True:
                data = client_connect.recv(1024).decode()
                if not data:
                    break
                logging.info(f"Client from [{client_address}] wants to download the file [{data}]")
                files = os.listdir(CLIENT_FOLDER)
                filename: str = str(data)
                if data not in files:
                    client_connect.send("no_file".encode())
                else:
                    file_path = os.path.join(CLIENT_FOLDER, filename)
                    file_size = os.path.getsize(file_path)
                    client_connect.sendall(f"FILE {filename} {file_size}".encode())
                    with open(file_path, "rb") as file:
                        while True:
                            data = file.read(1024)
                            if not data:
                                break
                            client_connect.sendall(data)

        except ConnectionResetError:
            logging.info(f"Connection reset by {client_address}")
        except Exception as e:
            logging.info(f"Error handling client {client_address}: {e}")
        finally:
            # Remove the client from the list when the connection is closed
            with self.lock:
                del self.clients[client_address]
            client_connect.close()
            logging.info(f"Connection closed by {client_address}")

    @staticmethod
    def handle_sigint():
        print("\nClient closed.")
        sys.exit(0)

    def login_form(self, client_socket):
        def login_to_server():
            # Retrieve username and password from Entry widgets
            username: str = username_value.get()
            password = password_value.get()
            state: str = 'login'
            # Send data to the server (consider encrypting the password in a real-world scenario)
            client_socket.send(f"{state},{username},{password}".encode())
            print("[OK!]")
            server_responses: str = client_socket.recv(1024).decode()
            print(server_responses)
            client_receive = "Login successful to server"

            if server_responses == client_receive:
                login_root.destroy()
                self.menu_app(client_socket, username)
            else:
                messagebox.showerror(title="Error", message="Login failed!")

        def create_acc():
            login_root.destroy()
            self.create_account(client_socket)

        def ping():
            self.ping_hostname(client_socket)

        login_root = app.Tk()
        login_root.title("Sharing File App")
        login_root.geometry('600x450')
        login_root.configure(bg='#333333')

        frame = Frame(bg='#333333')

        header = Label(frame, text="Welcome to Sharing File App", bg='#333333', fg='#FFD700', font=("Arial", 20))
        header.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)

        username_s = Label(frame, text="Username:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 16))
        password_s = Label(frame, text="Password:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 16))
        username_s.grid(row=1, column=0)
        password_s.grid(row=2, column=0)

        username_value = app.StringVar()
        password_value = app.StringVar()

        username_entry = Entry(frame, textvariable=username_value, font=("Arial", 14))
        password_entry = Entry(frame, textvariable=password_value, show='*',
                               font=("Arial", 14))  # Show '*' for password

        username_entry.grid(row=1, column=1, pady=20, sticky=W)
        password_entry.grid(row=2, column=1, pady=20, sticky=W)

        button_submit = Button(frame, text="Login", command=login_to_server, bg='#FFD700', fg='#333333',
                               font=("Arial", 13), width=20)
        button_submit.grid(row=3, column=0, columnspan=1, pady=10, sticky=W)
        button_create_acc = Button(frame, text="Create a new account", command=create_acc, bg='#FFD700', fg='#333333',
                                   font=("Arial", 13), width=20)
        button_create_acc.grid(row=3, column=1, columnspan=1, pady=10, sticky=E)

        button_ping = Button(frame, text="Ping Hostname", command=ping, bg='#FFD700', fg='#333333',
                             font=("Arial", 13), width=45)
        button_ping.grid(row=4, column=0, columnspan=2, pady=20)

        frame.pack()

        login_root.mainloop()

    def create_account(self, client_socket):
        def login_server():
            signup_root.destroy()
            self.login_form(client_socket)

        def send_data_to_server():
            # Retrieve username and password from Entry widgets
            state: str = 'signup'
            username: str = username_value.get()
            password = password_value.get()
            pre_password = pre_password_value.get()

            # Send data to the server (consider encrypting the password in a real-world scenario)
            self.client_socket.send(f"{state},{username},{password},{pre_password}".encode())
            print("[OK!]")
            server_responses: str = client_socket.recv(1024).decode()
            print(server_responses)
            client_receive = "Successful"

            if server_responses == client_receive:
                messagebox.showinfo(title="Create account", message="Create a new account successful!")
            else:
                messagebox.showerror(title="Create account", message="Error!")

        signup_root: Tk = app.Tk()
        signup_root.title("Sharing File App")
        signup_root.geometry('600x600')
        signup_root.configure(bg='#333333')

        frame = Frame(bg='#333333')

        header = Label(frame, text="Create New Account", bg='#333333', fg='#FFD700', font=("Arial", 20))
        header.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)

        username_s = Label(frame, text="Username:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 16))
        password_s = Label(frame, text="Password:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 16))
        pre_password_s = Label(frame, text="Pre_Password:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 16))
        username_s.grid(row=1, column=0)
        password_s.grid(row=2, column=0)
        pre_password_s.grid(row=3, column=0)

        username_value = app.StringVar()
        password_value = app.StringVar()
        pre_password_value = app.StringVar()

        username_entry = Entry(frame, textvariable=username_value, font=("Arial", 14))
        password_entry = Entry(frame, textvariable=password_value, show='*',
                               font=("Arial", 14))
        pre_password_entry = Entry(frame, textvariable=pre_password_value, show='*', font=("Arial", 14))

        username_entry.grid(row=1, column=1, pady=20)
        password_entry.grid(row=2, column=1, pady=20)
        pre_password_entry.grid(row=3, column=1, pady=20)

        button_submit = Button(frame, text="Submit", command=send_data_to_server, bg='#FFD700', fg='#333333',
                               font=("Arial", 13))
        button_submit.grid(row=4, column=0, columnspan=1, pady=10)
        button_create_acc = Button(frame, text="Back to login", command=login_server, bg='#FFD700', fg='#333333',
                                   font=("Arial", 13))
        button_create_acc.grid(row=4, column=1, columnspan=1, pady=10)

        frame.pack()

        signup_root.mainloop()

    def menu_app(self, client_socket, username):
        menu_root = app.Tk()
        menu_root.title("Sharing File App")
        menu_root.geometry('600x400')
        menu_root.configure(bg='#333333')

        def ping():
            self.ping_hostname(client_socket)

        def discover():
            menu_root.destroy()
            self.discover_server(client_socket, username)

        def public():
            menu_root.destroy()
            self.public_server(client_socket, username)

        def fetch():
            menu_root.destroy()
            self.fetch_server(client_socket, username)

        def connect():
            menu_root.destroy()
            self.connect_client(client_socket, username)
            pass

        def logout():
            state: str = 'logout'
            text: str = 'not disconnect to server'
            client_socket.send(f"{state},{text}".encode())
            server_responses: str = client_socket.recv(1024).decode()
            print(server_responses)
            menu_root.destroy()
            self.login_form(client_socket)

        frame = Frame(bg='#333333', bd='40')

        header = Label(frame, text="Welcome to Sharing File App", bg='#333333', fg='#FFD700', font=("Arial", 20))
        header.grid(row=0, column=0, columnspan=2, sticky=N, ipady=30)

        button_ping = Button(frame, text="PING", command=ping, bg='#FFD700', fg='#333333',
                             font=("Arial", 13), width=18)
        button_ping.grid(row=1, column=0, pady=10, sticky=W)

        button_discover = Button(frame, text="DISCOVER", command=discover, bg='#FFD700', fg='#333333',
                                 font=("Arial", 13), width=18)
        button_discover.grid(row=1, column=1, columnspan=1, pady=10, sticky=E)

        button_public = Button(frame, text="PUBLIC", command=public, bg='#FFD700', fg='#333333',
                               font=("Arial", 13), width=18)
        button_public.grid(row=2, column=0, columnspan=1, pady=10, sticky=W)

        button_fetch = Button(frame, text="FETCH", command=fetch, bg='#FFD700', fg='#333333',
                              font=("Arial", 13), width=18)
        button_fetch.grid(row=2, column=1, columnspan=1, pady=10, sticky=E)

        button_connect = Button(frame, text="CONNECT", command=connect, bg='#FFD700', fg='#333333',
                                font=("Arial", 13), width=18)
        button_connect.grid(row=3, column=0, columnspan=1, pady=10, sticky=W)

        button_logout = Button(frame, text="LOGOUT", command=logout, bg='#FFD700', fg='#333333',
                               font=("Arial", 13), width=18)
        button_logout.grid(row=3, column=1, columnspan=1, pady=10, sticky=E)

        frame.pack()
        menu_root.mainloop()

    def ping_hostname(self, client_socket):
        state: str = 'ping'
        data: str = '!?!'
        counter = 0
        sent = 4
        received = 0
        report: str = f"Pinging 'localhost' with {sent} data:\n"
        data_check: str = 'OK!\n'
        while counter < 4:
            counter += 1
            client_socket.send(f"{state},{data}".encode())
            text: str = client_socket.recv(1024).decode()
            report = report + text
            if text == data_check:
                received += 1

        lost_data = sent - received
        loss = (lost_data / sent) * 100

        text = (f"Ping statistics for 'localhost':\n "
                f"Packets: Sent = {sent}, Received = {received}, Lost = {lost_data} ({loss}% loss)")
        messagebox.showinfo(title="Report", message=f"{report} {text}")

    def public_server(self, client_socket, username):
        hostname = self.my_host
        port = self.my_port

        def close():
            public_root.destroy()
            self.menu_app(client_socket, username)

        def public_all():

            state: str = 'send_name_file'
            files = os.listdir(CLIENT_FOLDER)
            check1_respond: str = 'already_exist'
            check2_respond: str = 'ok'
            files_error = 0
            files_ok = 0
            if not files:
                print("No files found in the directory.")
                messagebox.showinfo(title="Public all", message="No files found in the directory.")
            else:
                print("List of files:", files)

                for file in files:
                    client_socket.send(f"{state},{username},{file},{hostname},{port}".encode())
                    try:
                        server_respond: str = client_socket.recv(1024).decode()
                        if server_respond == check1_respond:
                            files_error += 1
                        elif server_respond == check2_respond:
                            files_ok += 1
                    except Exception as e:
                        # Handle socket errors
                        print(f"Error processing file {file}: {e}")

                print(f"Have {files_ok} public successful and {files_error} filename public failed!")
                messagebox.showinfo(
                    title="Public all",
                    message=f"Have {files_ok} public successful and {files_error} file name public failed!"
                )

        def send_name():
            state: str = 'send_name_file'
            filename: str = chose_file_value.get()
            file_path = os.path.join(CLIENT_FOLDER, filename)
            if os.path.exists(file_path):
                client_socket.send(f"{state},{username},{filename},{hostname},{port}".encode())
                check1_respond: str = 'already_exist'
                check2_respond: str = 'ok'
                server_respond: str = client_socket.recv(1024).decode()
                print(server_respond)
                if server_respond == check1_respond:
                    print("Public filename is failed!")
                    messagebox.showerror(title="Error", message="The file name already exists!")
                elif server_respond == check2_respond:
                    print("Public filename is successful!")
                    messagebox.showinfo(title="Successful", message="Public filename is successful!")
                else:
                    print("Public filename is failed!")
                    messagebox.showerror(title="Error", message="An unknown error ")
            else:
                print("Public filename is failed!")
                messagebox.showerror(title="Error", message="File not found!")

        public_root: Tk = app.Tk()
        public_root.title("Sharing File App")
        public_root.geometry('500x350')
        public_root.configure(bg='#333333')

        frame = Frame(bg='#333333', bd='40')

        header = Label(frame, text="Public File", bg='#333333', fg='#FFD700', font=("Arial", 30))
        header.grid(row=0, column=0, columnspan=2, sticky=N, pady=10)

        chose_file = Label(frame, text="File Name:", bg='#333333', fg='#FFFFFF', font=("Arial", 20))
        chose_file.grid(row=1, column=0, sticky=W)

        chose_file_value = app.StringVar()

        chose_file_entry = Entry(frame, textvariable=chose_file_value, font=("Arial", 14))
        chose_file_entry.grid(row=1, column=1, columnspan=1, pady=20)

        button_send_name = Button(frame, text="Public filename", command=send_name, bg='#FFD700', fg='#333333',
                                  font=("Arial", 13), width=18)
        button_send_name.grid(row=2, column=0, columnspan=1, pady=10, sticky=W)

        button_all = Button(frame, text="Public all", command=public_all, bg='#FFD700', fg='#333333',
                            font=("Arial", 13), width=20)
        button_all.grid(row=2, column=0, columnspan=2, pady=10, sticky=SE)

        button_back = Button(frame, text="Close", command=close, bg='#FFD700', fg='#333333',
                             font=("Arial", 13), width=20)
        button_back.grid(row=3, column=0, columnspan=2, pady=10, sticky=SE)

        frame.pack()

        public_root.mainloop()

    def discover_server(self, client_socket, username):
        state = 'discover'
        text = 'server'
        client_socket.send(f"{state},{text}".encode())
        filelist = client_socket.recv(1024).decode()

        def close():
            discover_root.destroy()
            self.menu_app(client_socket, username)

        def download():
            state_down: str = 'download'
            filename: str = chose_file_value.get()
            check_respond: str = 'no_file'
            if filename in files:
                client_socket.send(f"{state_down},{filename}".encode())
                print("OK")
                server_respond: str = client_socket.recv(1024).decode()
                if check_respond == server_respond:
                    print("File not found in server!")
                    messagebox.showerror(title="Error", message="File is not found in server!")
                else:
                    _, file_name_sent, file_size = server_respond.split()
                    file_size = int(file_size)

                    file_path = os.path.join(CLIENT_FOLDER, file_name_sent)

                    with open(file_path, "wb") as file_sent:
                        while file_size > 0:
                            data = client_socket.recv(1024)
                            file_sent.write(data)
                            file_size -= len(data)

                    print(f"File {filename} download successful!")
                    messagebox.showinfo(title="Successful", message=f"File {filename} download successful!")
            else:
                print("File not found!")
                messagebox.showerror(title="Error", message="File is not found!")

        files = filelist.split(",")
        discover_root: Tk = app.Tk()
        discover_root.title("Sharing File App")
        discover_root.geometry('600x600')
        discover_root.configure(bg='#333333')

        frame = Frame(bg='#333333', bd='40')

        header = Label(frame, text="List file form server", bg='#333333', fg='#FFD700', font=("Arial", 30))
        header.grid(row=0, column=0, columnspan=2, sticky=N, pady=10)

        chose_file = Label(frame, text="File Name:", bg='#333333', fg='#FFFFFF', font=("Arial", 20))
        chose_file.grid(row=1, column=0, sticky=W)

        chose_file_value = app.StringVar()

        chose_file_entry = Entry(frame, textvariable=chose_file_value, font=("Arial", 14))
        chose_file_entry.grid(row=1, column=1, columnspan=1, pady=20)

        button_send_name = Button(frame, text="Download", command=download, bg='#FFD700', fg='#333333',
                                  font=("Arial", 13), width=18)
        button_send_name.grid(row=2, column=0, columnspan=1, pady=10, sticky=W)

        button_send_name = Button(frame, text="Close", command=close, bg='#FFD700', fg='#333333',
                                  font=("Arial", 13), width=18)
        button_send_name.grid(row=2, column=1, columnspan=1, pady=10, sticky=E)

        table = Label(frame, text=f"STT", bg='#333333', fg='#FFD700', font=("Arial", 15))
        table.grid(row=3, column=0, columnspan=1, pady=10)

        table = Label(frame, text=f"File name", bg='#333333', fg='#FFD700', font=("Arial", 15))
        table.grid(row=3, column=1, columnspan=1, pady=10, sticky=W)

        print("List of files:")
        counter = 4
        stt = 0
        for file in files:
            counter += 1
            stt += 1
            print(f"{stt}. {file}")
            file_stt = Label(frame, text=f"{stt}", bg='#333333', fg='#FFFFFF', font=("Arial", 15))
            file_stt.grid(row=counter, column=0, columnspan=1)
            file_name = Label(frame, text=f"{file}", bg='#333333', fg='#FFFFFF', font=("Arial", 15))
            file_name.grid(row=counter, column=1, columnspan=1, sticky=W)

        frame.pack()
        discover_root.mainloop()

    def fetch_server(self, client_socket, username):
        def close():
            fetch_root.destroy()
            self.menu_app(client_socket, username)

        def select():
            data_select: str = lbx.get(ACTIVE)
            print(data_select)
            num, username_select, filename_select = data_select.split(",")
            state_select: str = 'select'
            client_socket.send(f"{state_select},{username_select},{filename_select}".encode())
            respond = client_socket.recv(1024).decode()
            if respond == 'not_found':
                print(f"Error! Not Found")
                messagebox.showerror(title="Error", message="Not found address!")
            else:
                print(f"Address: {respond}")
                messagebox.showinfo(title="Successful", message=f"{respond}")

        state: str = 'fetch'
        text: str = 'find'

        client_socket.send(f"{state},{text}".encode())
        data_str = client_socket.recv(1024).decode()
        data = ast.literal_eval(data_str)

        fetch_root: Tk = app.Tk()
        fetch_root.geometry("670x480")
        fetch_root.configure(bg='#333333')

        fr = Frame(fetch_root)
        fr.pack()

        sbr = Scrollbar(fr, )
        sbr.pack(side=RIGHT, fill="y")

        lbx = Listbox(fr, font=("Verdana", 16), bd=5, width=45, )

        lbx.pack(side=LEFT, fill="both", expand=True)

        stt = 1
        for username, filename in data:
            lbx.insert(END, f"{stt},{username},{filename}")
            stt += 1

        sbr.config(command=lbx.yview)
        lbx.config(yscrollcommand=sbr.set)

        button_select = Button(fetch_root, text="Fetch", command=select, bg='#FFD700', fg='#333333',
                               font=("Arial", 13), width=18)
        button_select.pack(side=LEFT)

        button_close = Button(fetch_root, text="Close", command=close, bg='#FFD700', fg='#333333',
                              font=("Arial", 13), width=18)
        button_close.pack(side=RIGHT)

        fetch_root.mainloop()

    def connect_client(self, client_socket, username):
        connect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def close():
            connect_root.destroy()
            self.menu_app(client_socket, username)

        def connect_to_client():
            host_connect: str = host_value.get()
            port_connect = int(port_value.get())

            try:
                connect_socket.connect((host_connect, port_connect))
                print(f"Connected to the server at {host_connect}:{port_connect}.")
                connect_root.destroy()
                connect_form()
            except ConnectionRefusedError:
                print(f"Error: Unable to connect to the server at {host_connect}:{port_connect}.")
            except Exception as e:
                print(f"Error connecting to the server: {e}")

        def connect_form():
            def close_socket():
                file_root.destroy()
                connect_socket.close()
                self.connect_client(client_socket, username)

            def download():
                data_send_client: str = file_value.get()
                connect_socket.send(f"{data_send_client}".encode())
                print("OK!")
                check_respond: str = 'no_file'
                client_respond = connect_socket.recv(1024).decode()
                if check_respond == client_respond:
                    print("File not found in server!")
                    messagebox.showerror(title="Error", message="File is not found in server!")
                else:
                    _, file_name_sent, file_size = client_respond.split()
                    file_size = int(file_size)

                    file_path = os.path.join(CLIENT_FOLDER, file_name_sent)

                    with open(file_path, "wb") as file_sent:
                        while file_size > 0:
                            data = connect_socket.recv(1024)
                            file_sent.write(data)
                            file_size -= len(data)

                    print(f"File {data_send_client} download successful!")
                    messagebox.showinfo(title="Successful", message=f"File {data_send_client} download successful!")

            file_root = app.Tk()
            file_root.title("Sharing File App")
            file_root.geometry('600x400')
            file_root.configure(bg='#333333')

            file_frame = Frame(bg='#333333')

            file_header = Label(file_frame, text="Download file form client",
                                bg='#333333', fg='#FFD700', font=("Arial", 30))
            file_header.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)

            file_text = Label(file_frame, text="File name:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 20))
            file_text.grid(row=1, column=0, sticky=W)

            file_value = app.StringVar()

            file_entry = Entry(file_frame, textvariable=file_value, font=("Arial", 14))
            file_entry.grid(row=1, column=1, pady=20, sticky=W)

            file_button_connect = Button(file_frame, text="Download", command=download, bg='#FFD700', fg='#333333',
                                    font=("Arial", 13), width=20)
            file_button_connect.grid(row=3, column=0, columnspan=1, pady=10, sticky=W)
            file_button_close = Button(file_frame, text="Close", command=close_socket, bg='#FFD700', fg='#333333',
                                       font=("Arial", 13), width=20)
            file_button_close.grid(row=3, column=1, columnspan=1, pady=10, sticky=E)

            file_frame.pack()
            file_root.mainloop()

        connect_root = app.Tk()
        connect_root.title("Sharing File App")
        connect_root.geometry('600x400')
        connect_root.configure(bg='#333333')

        frame = Frame(bg='#333333')

        header = Label(frame, text="Connect to client", bg='#333333', fg='#FFD700', font=("Arial", 30))
        header.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)

        host_text = Label(frame, text="Hostname:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 20))
        port_text = Label(frame, text="Port:  ", bg='#333333', fg='#FFFFFF', font=("Arial", 20))
        host_text.grid(row=1, column=0, sticky=W)
        port_text.grid(row=2, column=0, sticky=W)

        host_value = app.StringVar()
        port_value = app.StringVar()

        host_entry = Entry(frame, textvariable=host_value, font=("Arial", 14))
        port_entry = Entry(frame, textvariable=port_value,
                           font=("Arial", 14))  # Show '*' for password

        host_entry.grid(row=1, column=1, pady=20, sticky=W)
        port_entry.grid(row=2, column=1, pady=20, sticky=W)

        button_connect = Button(frame, text="Connect", command=connect_to_client, bg='#FFD700', fg='#333333',
                                font=("Arial", 13), width=20)
        button_connect.grid(row=3, column=0, columnspan=1, pady=10, sticky=W)
        button_close = Button(frame, text="Close", command=close, bg='#FFD700', fg='#333333',
                                   font=("Arial", 13), width=20)
        button_close.grid(row=3, column=1, columnspan=1, pady=10, sticky=E)

        frame.pack()
        connect_root.mainloop()


if __name__ == "__main__":
    try:
        server_host: str = input("Enter the server host: ")
        server_port = int(input("Enter the server port: "))

        client_host: str = '127.0.0.1'
        client_port = 12

        client = appClient(server_host, server_port, client_host, client_port)
        client.start()

    except ValueError as value_error:
        print(f"Error: {value_error}")


