"""
Trong file này sẽ là cách làm việc với thư viện socket cơ bản 
"""
# import module
import socket
"""
. Các khái niệm cơ bản

Socket: Một điểm cuối (endpoint) để gửi/nhận dữ liệu qua mạng.
Giao thức:

    TCP: Đáng tin cậy, đảm bảo dữ liệu đến đúng thứ tự (dùng cho chat, web).
    UDP: Nhanh, không đảm bảo thứ tự hoặc giao hàng (dùng cho streaming, game).


Các bước cơ bản:

    Server: Tạo socket → Bind địa chỉ → Listen → Accept kết nối → Gửi/nhận dữ liệu.
    Client: Tạo socket → Connect đến server → Gửi/nhận dữ liệu.



Các hàm chính:

    socket.socket(family=AF_INET, type=SOCK_STREAM): Tạo socket (AF_INET: IPv4, SOCK_STREAM: TCP).
    bind((host, port)): Gắn socket vào địa chỉ và cổng.
    listen(backlog): Lắng nghe kết nối (backlog: số kết nối chờ tối đa).
    accept(): Chấp nhận kết nối từ client, trả về socket mới và địa chỉ client.
    connect((host, port)): Kết nối client đến server.
    send(data) / sendall(data): Gửi dữ liệu (data là bytes).
    recv(bufsize): Nhận dữ liệu (trả về bytes).
    close(): Đóng socket.
"""
# Server TCP
import socket
from typing import Tuple

def start_server(host: str = "127.0.0.1", port: int = 12345) -> None:
    """Start a TCP server to accept and respond to client connections.

    Args:
        host (str): Server host address (default: localhost).
        port (int): Server port (default: 12345).
    """
    # Tạo socket TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Tái sử dụng cổng

    try:
        # Bind socket
        server_socket.bind((host, port))
        server_socket.listen(5)  # Chấp nhận tối đa 5 kết nối chờ
        print(f"Server listening on {host}:{port}")

        while True:
            # Chấp nhận kết nối
            client_socket, client_address = server_socket.accept()
            print(f"Connected to client: {client_address}")

            # Nhận và xử lý dữ liệu
            data = client_socket.recv(1024).decode("utf-8")
            if data:
                print(f"Received: {data}")
                response = f"Server received: {data}".encode("utf-8")
                client_socket.sendall(response)

            # Đóng kết nối client
            client_socket.close()

    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()

# Client TCP
import socket
from typing import Tuple

def start_client(host: str = "127.0.0.1", port: int = 12345, message: str = "Hello, Server!") -> None:
    """Connect to a TCP server and send a message.

    Args:
        host (str): Server host address (default: localhost).
        port (int): Server port (default: 12345).
        message (str): Message to send to the server.
    """
    # Tạo socket TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Kết nối đến server
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        # Gửi dữ liệu
        client_socket.sendall(message.encode("utf-8"))

        # Nhận phản hồi
        response = client_socket.recv(1024).decode("utf-8")
        print(f"Server response: {response}")

    except ConnectionError as e:
        print(f"Connection error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()

# Kết hợp Threading với Socket
import socket
import threading
from typing import Tuple

def handle_client(client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
    """Handle a single client connection.

    Args:
        client_socket (socket.socket): Socket for the client connection.
        client_address (Tuple[str, int]): Client's address (host, port).
    """
    try:
        print(f"Handling client {client_address}")
        while True:
            data = client_socket.recv(1024).decode("utf-8")
            if not data:  # Client ngắt kết nối
                print(f"Client {client_address} disconnected")
                break
            print(f"Received from {client_address}: {data}")
            response = f"Server received: {data}".encode("utf-8")
            client_socket.sendall(response)
    except ConnectionError:
        print(f"Client {client_address} connection error")
    finally:
        client_socket.close()

def start_server(host: str = "127.0.0.1", port: int = 12345) -> None:
    """Start a TCP server to handle multiple clients concurrently.

    Args:
        host (str): Server host address (default: localhost).
        port (int): Server port (default: 12345).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Server listening on {host}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            # Tạo thread để xử lý client
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True  # Thread dừng khi server tắt
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()

# Sử dụng UDP
## UDP không duy trì kết nối, gửi/nhận dữ liệu dạng datagram. Dưới đây là ví dụ server-client UDP.
## Server UDP
import socket
from typing import Tuple

def start_udp_server(host: str = "127.0.0.1", port: int = 12345) -> None:
    """Start a UDP server to receive and respond to messages.

    Args:
        host (str): Server host address (default: localhost).
        port (int): Server port (default: 12345).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"UDP server listening on {host}:{port}")

    try:
        while True:
            data, client_address = server_socket.recvfrom(1024)
            message = data.decode("utf-8")
            print(f"Received from {client_address}: {message}")
            response = f"Server received: {message}".encode("utf-8")
            server_socket.sendto(response, client_address)
    except KeyboardInterrupt:
        print("UDP server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_udp_server()


### Client UDP
import socket

def start_udp_client(host: str = "127.0.0.1", port: int = 12345, message: str = "Hello, UDP Server!") -> None:
    """Send a message to a UDP server and receive a response.

    Args:
        host (str): Server host address (default: localhost).
        port (int): Server port (default: 12345).
        message (str): Message to send.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client_socket.sendto(message.encode("utf-8"), (host, port))
        response, _ = client_socket.recvfrom(1024)
        print(f"Server response: {response.decode('utf-8')}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_udp_client()

"""
Không cần connect() hay accept() (UDP không duy trì kết nối).
Dùng sendto() và recvfrom() để gửi/nhận kèm địa chỉ.
Không đảm bảo dữ liệu đến đúng thứ tự hoặc đến được.
"""
