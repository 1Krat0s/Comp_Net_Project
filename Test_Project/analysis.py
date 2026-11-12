
import csv
import os
import time
import threading
from datetime import datetime


class NetworkAnalyzer:
    """
    Collects and saves network performance statistics
    from the server and connected clients.
    """

    def __init__(self, filename="network_stats.csv"):
        self.filename = filename

        # Prevent multiple server threads from writing at once
        self.lock = threading.Lock()

        # Store statistics in memory
        self.statistics = []

        # Columns for the CSV file
        self.fields = [
            "timestamp",
            "source",
            "client_id",
            "operation",
            "filename",
            "file_size_mb",
            "transfer_time_sec",
            "transfer_rate_mbps",
            "response_time_ms",
            "status"
        ]

        # Create CSV file if it doesn't exist
        with self.lock:
            if not os.path.exists(self.filename) or \
                    os.path.getsize(self.filename) == 0:

                with open(self.filename, "w", newline="") as file:
                    writer = csv.DictWriter(
                        file,
                        fieldnames=self.fields
                    )
                    writer.writeheader()

        print("[ANALYSIS] Network monitoring started.")
        print("[ANALYSIS] Statistics file:", self.filename)

    def save_statistics(self, data):
        """
        Save one statistic to memory and the CSV file.
        """
        row = {
            field: data.get(field, "")
            for field in self.fields
        }

        row["timestamp"] = datetime.now().isoformat(
            timespec="seconds"
        )

        with self.lock:
            with open(self.filename, "a", newline="") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=self.fields
                )
                writer.writerow(row)

            self.statistics.append(row)

    def record_transfer(
        self,
        source,
        client_id,
        operation,
        filename,
        bytes_transferred,
        duration_seconds,
        status="success"
    ):
        """
        Calculate and record upload/download statistics.

        source: server or client
        operation: upload or download
        bytes_transferred: actual number of bytes transferred
        duration_seconds: elapsed transfer time
        """
        if source not in ("server", "client"):
            raise ValueError("Invalid metric source")

        if operation not in ("upload", "download"):
            raise ValueError("Invalid transfer operation")

        bytes_transferred = int(bytes_transferred)
        duration_seconds = float(duration_seconds)

        if bytes_transferred < 0 or duration_seconds < 0:
            raise ValueError("Transfer values cannot be negative")

        # Convert bytes to decimal MB
        file_size_mb = bytes_transferred / 1_000_000

        # Calculate transfer rate (MB/s)
        if duration_seconds > 0:
            transfer_rate = file_size_mb / duration_seconds
        else:
            transfer_rate = 0

        data = {
            "source": source,
            "client_id": client_id,
            "operation": operation,
            "filename": filename,
            "file_size_mb": round(file_size_mb, 3),
            "transfer_time_sec": round(duration_seconds, 4),
            "transfer_rate_mbps": round(transfer_rate, 3),
            "response_time_ms": "",
            "status": status
        }

        self.save_statistics(data)

        print(
            f"[ANALYSIS] {source.upper()} | "
            f"Client {client_id} | "
            f"{operation.upper()} | "
            f"{file_size_mb:.2f} MB | "
            f"{duration_seconds:.2f} sec | "
            f"{transfer_rate:.2f} MB/s"
        )

        return data

    def record_response(
        self,
        source,
        client_id,
        operation,
        duration_seconds,
        status="success"
    ):
        """
        Record how long a command takes to receive
        a response from the server.
        """
        if source not in ("server", "client"):
            raise ValueError("Invalid metric source")

        duration_seconds = float(duration_seconds)

        if duration_seconds < 0:
            raise ValueError("Response time cannot be negative")

        # Convert seconds to milliseconds
        response_time_ms = duration_seconds * 1000

        data = {
            "source": source,
            "client_id": client_id,
            "operation": operation,
            "filename": "",
            "file_size_mb": "",
            "transfer_time_sec": "",
            "transfer_rate_mbps": "",
            "response_time_ms": round(response_time_ms, 3),
            "status": status
        }

        self.save_statistics(data)

        print(
            f"[ANALYSIS] {source.upper()} | "
            f"Client {client_id} | "
            f"{operation.upper()} | "
            f"Response: {response_time_ms:.2f} ms"
        )

        return data

    def record_client_metric(self, message, client_id):
        """
        Process a statistics message received from
        an authenticated client.
        """
        if message.get("command") != "METRIC":
            raise ValueError("Invalid statistics message")

        metric_type = message.get("metric_type")
        operation = message.get("operation")
        status = message.get("status", "success")

        if status not in ("success", "error", "cancelled"):
            raise ValueError("Invalid metric status")

        if metric_type == "transfer":
            return self.record_transfer(
                source="client",
                client_id=client_id,
                operation=operation,
                filename=message.get("filename", ""),
                bytes_transferred=message["bytes_transferred"],
                duration_seconds=message["duration_seconds"],
                status=status
            )

        elif metric_type == "response":
            return self.record_response(
                source="client",
                client_id=client_id,
                operation=operation,
                duration_seconds=message["duration_seconds"],
                status=status
            )

        else:
            raise ValueError("Unknown metric type")

    def get_statistics(self):
        """
        Return the statistics collected during
        this server session.
        """
        with self.lock:
            return list(self.statistics)

    def display_summary(self):
        """
        Display the collected statistics.
        """
        records = self.get_statistics()

        print("\n========== NETWORK ANALYSIS ==========")

        if not records:
            print("No statistics collected yet.")
            return

        for record in records:
            print(
                f"{record['timestamp']} | "
                f"{record['source']} | "
                f"Client {record['client_id']} | "
                f"{record['operation']}"
            )

            if record["transfer_time_sec"] != "":
                print(
                    f"  File: {record['filename']} | "
                    f"Size: {record['file_size_mb']} MB | "
                    f"Time: {record['transfer_time_sec']} sec | "
                    f"Speed: {record['transfer_rate_mbps']} MB/s"
                )

            if record["response_time_ms"] != "":
                print(
                    f"  Response Time: "
                    f"{record['response_time_ms']} ms"
                )

        print("======================================\n")


def make_transfer_metric(
    operation,
    filename,
    bytes_transferred,
    duration_seconds,
    status="success"
):
    """
    Create a client-side transfer statistics message.
    """
    return {
        "command": "METRIC",
        "metric_type": "transfer",
        "operation": operation,
        "filename": filename,
        "bytes_transferred": bytes_transferred,
        "duration_seconds": duration_seconds,
        "status": status
    }


def make_response_metric(
    operation,
    duration_seconds,
    status="success"
):
    """
    Create a client-side response time message.
    """
    return {
        "command": "METRIC",
        "metric_type": "response",
        "operation": operation,
        "duration_seconds": duration_seconds,
        "status": status
    }
