import hashlib
import logging
import socket
import sqlite3
import threading
import os

SERVER_FOLDER = "server_folder"
class appServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.lock = threading.Lock()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        logging.info(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = self.server_socket.accept()
            logging.info(f"New connection from {client_address}")

            # Create a new thread to handle the client
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def handle_client(self, client_socket):
        # Add the client to the list of connected clients
        client_address = client_socket.getpeername()
        with self.lock:
            self.clients[client_address] = client_socket

        try:
            while True:
                data = client_socket.recv(1024).decode()
                state = data.split(",")[0]
                data_sent = data[data.find(',') + 1:]
                logging.info(state)
                if not data:
                    break  # Connection closed by client
                # Process the received data
                if state == 'login':
                    login_client(client_socket, client_address, data_sent)
                if state == 'signup':
                    signup_client(client_socket, client_address, data_sent)
                if state == 'logout':
                    logout_client(client_socket, client_address, data_sent)
                if state == 'ping':
                    ping_client(client_socket, client_address, data_sent)
                if state == 'send_name_file':
                    name_file_client(client_socket, client_address, data_sent)
                if state == 'discover':
                    discover(client_socket, client_address, data_sent)
                if state == 'download':
                    download_file_server(client_socket, client_address, data_sent)
                if state == 'fetch':
                    fetch(client_socket, client_address, data_sent)
                if state == 'select':
                    select(client_socket, client_address, data_sent)
        except ConnectionResetError:
            logging.info(f"Connection reset by {client_address}")
        except Exception as e:
            logging.info(f"Error handling client {client_address}: {e}")

        finally:
            # Remove the client from the list when the connection is closed
            with self.lock:
                del self.clients[client_address]
            client_socket.close()
            logging.info(f"Connection closed by {client_address}")


def login_client(client_socket, client_address, data_sent: object) -> None:
    username, password = data_sent.split(',')
    logging.info(f"Login from {client_address} with [Username: {username} - Password: {password}]")
    password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username, password))

    if cur.fetchall():
        logging.info(f"Login successful by {username}")
        client_socket.send("Login successful to server".encode())
    else:
        logging.info("Login failed!")
        client_socket.send("Login failed to server".encode())

    cur.close()
    conn.close()

def signup_client(client_socket, client_address, data_sent: object) -> None:

    username, password, pre_password = data_sent.split(',')
    logging.info(f"create new account from {client_address} with [Username: {username} - Password: {password}]")

    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()

    cur.execute('SELECT * FROM userdata WHERE username = ?', (username,))
    if cur.fetchone():
        client_socket.send("Failed".encode())
    elif not username or not password or not pre_password:
        client_socket.send("Failed".encode())
    elif password != pre_password:
        client_socket.send("Failed".encode())
    else:
        password = hashlib.sha256(password.encode()).hexdigest()

        new_client = (username, password)
        cur.execute('INSERT INTO "userdata" ("username", "password") VALUES (?, ?)', new_client)

        conn.commit()
        client_socket.send("Successful".encode())

    cur.close()
    conn.close()

def ping_client(client_socket, client_address, data_sent: object) -> None:
    logging.info(f"Form: {client_address}:{data_sent}")
    check_data: str = '!?!'
    if data_sent == check_data:
        client_socket.send("OK!\n".encode())
    else:
        client_socket.send("Miss!\n".encode())

def name_file_client(client_socket, client_address, data_sent: object) -> None:
    username, filename, hostname, port = data_sent.split(',')
    logging.info(f"Username:[{username}] sent filename:[{filename}] at [{client_address}]")

    conn = sqlite3.connect("filename_of_users.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM filename_of_users WHERE username = ? AND filename = ?", (username, filename))
    if cur.fetchone():
        client_socket.send("already_exist".encode())
        logging.info("Save data failed")
    else:
        new_filename = (username, filename, hostname, port)
        cur.execute('INSERT INTO "filename_of_users" ("username", "filename", "hostname", "port") VALUES (?, ?, ?, ?)',
                    new_filename)
        conn.commit()
        client_socket.send("ok".encode())
        logging.info("Save data successful")

    cur.close()
    conn.close()


def discover(client_socket, client_address, data_sent: object) -> None:
    logging.info(f"Client sent to {data_sent}: 'discover' request from: [{client_address}]")
    files = os.listdir(SERVER_FOLDER)

    if not files:
        logging.info("No files found in the directory.")
        client_socket.send("No files found in the directory.".encode())
    else:
        # Send the list of files as a comma-separated string
        file_list_str = ','.join(files)
        client_socket.sendall(file_list_str.encode())
        logging.info("List of files sent to the client.")


def download_file_server(client_socket, client_address, data_sent: object) -> None:
    logging.info(f"Client from [{client_address}] wants to download the file [{data_sent}]")
    files = os.listdir(SERVER_FOLDER)
    filename: str = str(data_sent)
    if data_sent not in files:
        client_socket.send("no_file".encode())
    else:
        file_path = os.path.join(SERVER_FOLDER, filename)
        file_size = os.path.getsize(file_path)
        client_socket.sendall(f"FILE {filename} {file_size}".encode())
        with open(file_path, "rb") as file:
            while True:
                data = file.read(1024)
                if not data:
                    break
                client_socket.sendall(data)


def fetch(client_socket, client_address, data_sent: object) -> None:
    logging.info(f"Client sent 'fetch' request from: [{client_address}]")
    if data_sent == 'find':
        conn = sqlite3.connect("filename_of_users.db")
        cur = conn.cursor()

        cur.execute("SELECT username, filename FROM filename_of_users")
        results = cur.fetchall()
        client_socket.send(f"{results}".encode())
        logging.info(f"Send data come to [{client_address}]: successful")
        conn.close()
    else:
        pass

def select(client_socket, client_address, data_send: object) -> None:
    def is_client_connected():
        try:
            socket_check.send("PING".encode())
            return True
        except (socket.error, BrokenPipeError):
            return False

    logging.info(f"Client request send address have:[{data_send}] from: {client_address}")
    username, filename = data_send.split(",")
    conn = sqlite3.connect("filename_of_users.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM filename_of_users WHERE username = ? AND filename = ?", (username, filename))
    if cur.fetchone():
        cur.execute("SELECT hostname, port FROM filename_of_users WHERE username = ? AND filename = ?",
                    (username, filename))
        result = cur.fetchone()

        if result:
            host_check, port_check = result
            socket_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                socket_check.connect((host_check, int(port_check)))
                if is_client_connected():
                    state_socket = "ON"
                else:
                    state_socket = "OFF"
                client_socket.send(f"Address {host_check},{port_check}, state : {state_socket}".encode())
                logging.info(f"Send data come to [{client_address}]: successful")
            except socket.error as e:
                logging.error(f"Error connecting to {host_check}:{port_check}: {e}")
                client_socket.send(f"Address {host_check}:{port_check}, state : OFF".encode())
            finally:
                socket_check.close()

        else:
            client_socket.send(f"not_found".encode())

        conn.close()
    else:
        client_socket.send(f"not_found".encode())

def logout_client(client_socket, client_address, data_sent: object) -> None:
    logging.info(f"Logout account form: {client_address} but {data_sent}")
    client_socket.send(f"Logout Successful!".encode())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = appServer('localhost', 24)
    server.start()
