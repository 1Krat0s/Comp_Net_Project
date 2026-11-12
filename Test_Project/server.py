
import os
import socket
import threading
import time

# Import your Network Analysis module
from analysis import NetworkAnalyzer

IP = "10.200.102.109"
PORT = 4500
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_PATH = "server"

# Start network analysis with the server
analyzer = NetworkAnalyzer("network_stats.csv")


# Handles each connected client
def handle_client(conn, addr):

    client_id = f"{addr[0]}:{addr[1]}"

    print(f"[NEW CONNECTION] {addr} connected.")

    conn.sendall(
        "OK@Welcome to the server".encode(FORMAT)
    )

    try:
        while True:

            # Receive command from client
            message = conn.recv(SIZE)

            if not message:
                break

            try:
                data = message.decode(FORMAT).split("@")
            except UnicodeDecodeError:
                conn.sendall(
                    "ERROR@Invalid message encoding".encode(FORMAT)
                )
                continue

            cmd = data[0].strip().upper()
            send_data = "OK@"

            # Client disconnects
            if cmd == "LOGOUT":
                print(f"[DISCONNECT] {client_id}")
                break

            # Existing TASK command
            elif cmd == "TASK":

                start_time = time.perf_counter()

                send_data += "LOGOUT from the server.\n"

                conn.sendall(send_data.encode(FORMAT))

                elapsed = time.perf_counter() - start_time

                # Record server-side processing time
                analyzer.record_response(
                    source="server",
                    client_id=client_id,
                    operation="TASK",
                    duration_seconds=elapsed
                )

            # NEW: Receive statistics from the client
            elif cmd == "METRIC":

                try:
                    # Format for transfer:
                    # METRIC@TRANSFER@UPLOAD@filename@bytes@seconds

                    # Format for response:
                    # METRIC@RESPONSE@DIR@seconds

                    if len(data) < 4:
                        raise ValueError("Incomplete metric")

                    metric_type = data[1].strip().upper()
                    operation = data[2].strip().lower()

                    if metric_type == "TRANSFER":

                        if len(data) != 6:
                            raise ValueError("Invalid transfer metric")

                        filename = data[3]
                        bytes_transferred = int(data[4])
                        duration = float(data[5])

                        analyzer.record_transfer(
                            source="client",
                            client_id=client_id,
                            operation=operation,
                            filename=filename,
                            bytes_transferred=bytes_transferred,
                            duration_seconds=duration
                        )

                    elif metric_type == "RESPONSE":

                        if len(data) != 4:
                            raise ValueError("Invalid response metric")

                        duration = float(data[3])

                        analyzer.record_response(
                            source="client",
                            client_id=client_id,
                            operation=operation,
                            duration_seconds=duration
                        )

                    else:
                        raise ValueError("Unknown metric type")

                    conn.sendall(
                        "OK@Metric saved".encode(FORMAT)
                    )

                except (ValueError, OverflowError, KeyError) as error:

                    print(f"[ANALYSIS ERROR] {error}")

                    conn.sendall(
                        "ERROR@Invalid metric data".encode(FORMAT)
                    )

            # Unknown command
            else:
                conn.sendall(
                    "ERROR@Unknown command".encode(FORMAT)
                )

    except (ConnectionError, OSError) as error:
        print(f"[CLIENT ERROR] {client_id}: {error}")

    finally:
        print(f"[DISCONNECTED] {addr}")
        conn.close()


def main():

    print("[SERVER] Starting the server")

    os.makedirs(SERVER_PATH, exist_ok=True)

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(ADDR)
    server.listen()

    print(f"[SERVER] Listening on {IP}:{PORT}")
    print("[ANALYSIS] Monitoring enabled")

    try:
        while True:

            conn, addr = server.accept()

            # Start separate thread for each client
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr)
            )

            thread.start()

            print(
                f"[SERVER] Active clients: "
                f"{threading.active_count() - 1}"
            )

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")

    finally:
        server.close()


if __name__ == "__main__":
    main()
