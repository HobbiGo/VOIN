""" VOIN NETWORK TRANSPORT ENGINE V1.0 Bounded TCP transport adapter for the VOIN communication protocol. Security scope: - Loopback-only transport for initial local testing. - Newline-delimited JSON messages. - Strict message-size limits and socket timeouts. - Delegates message authorization and validation to VOINCommunicationEngine. - Does not provide TLS, cryptographic peer authentication, public-network exposure, or production P2P discovery. """

import ipaddress
import json
import socket
import socketserver
import threading


class VOINTransportEngine:

    VERSION = "1.0.0"
    MAX_MESSAGE_SIZE = 65536
    SOCKET_TIMEOUT = 3.0

    def __init__(self, communication_engine, local_peer_id):
        if communication_engine is None:
            raise ValueError("communication_engine is required")

        if not isinstance(local_peer_id, str) or not local_peer_id:
            raise ValueError("local_peer_id is required")

        self.communication_engine = communication_engine
        self.local_peer_id = local_peer_id
        self.server = None
        self.server_thread = None
        self._lock = threading.RLock()

@staticmethod
    def _is_loopback_host(host):
        if not isinstance(host, str) or not host:
            return False
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host.lower() == "localhost"

@staticmethod
    def _encode_message(message):
        try:
            encoded = json.dumps(
                message,
                separators=(",", ":"),
                allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            return None

        if len(encoded) > VOINTransportEngine.MAX_MESSAGE_SIZE:
            return None

        return encoded

    def start_server(self, host="127.0.0.1", port=0):
        if not self._is_loopback_host(host):
            return {
                "success": False,
                "error": "Only loopback hosts are permitted"
            }

        if isinstance(port, bool) or not isinstance(port, int):
            return {"success": False, "error": "Invalid port"}

        if not 0 <= port <= 65535:
            return {"success": False, "error": "Invalid port"}

        with self._lock:
            if self.server is not None:
                return {
                    "success": False,
                    "error": "Transport server already running"
                }

            engine = self

            class RequestHandler(socketserver.StreamRequestHandler):

                def handle(self):
                    self.connection.settimeout(engine.SOCKET_TIMEOUT)

                    try:
                        raw = self.rfile.readline(
                            engine.MAX_MESSAGE_SIZE + 2
                        )

                        if (
                            not raw
                            or len(raw) > engine.MAX_MESSAGE_SIZE + 1
                            or not raw.endswith(b"\n")
                        ):
                            response = {
                                "success": False,
                                "error": "Invalid or oversized frame"
                            }
                        else:
                            try:
                                message = json.loads(raw.decode("utf-8"))
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                message = None

                            if not isinstance(message, dict):
                                response = {
                                    "success": False,
                                    "error": "Invalid JSON message"
                                }
                            else:
                                response = engine.communication_engine.receive_message(
                                    message,
                                    engine.local_peer_id
                                )

                        try:
                            output = json.dumps(
                                response,
                                separators=(",", ":"),
                                allow_nan=False,
                                default=str
                            ).encode("utf-8") + b"\n"
                        except (TypeError, ValueError):
                            output = b'{"success":false,"error":"Response encoding failed"}\n'

                        self.wfile.write(output)

                    except (OSError, socket.timeout):
                        # A disconnected or timed-out client is isolated
                        # to this request handler.
                        return

            class LocalTCPServer(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads = True
                block_on_close = False

            try:
                server = LocalTCPServer((host, port), RequestHandler)
                server.timeout = self.SOCKET_TIMEOUT
            except (OSError, ValueError) as exc:
                return {
                    "success": False,
                    "error": "Unable to start transport server: " + str(exc)
                }

            thread = threading.Thread(
                target=server.serve_forever,
                name="VOINTransportServer",
                daemon=True
            )

            self.server = server
            self.server_thread = thread
            thread.start()

            return {
                "success": True,
                "host": server.server_address[0],
                "port": server.server_address[1],
                "status": "RUNNING"
            }

    def stop_server(self):
        with self._lock:
            server = self.server
            thread = self.server_thread
            self.server = None
            self.server_thread = None

        if server is None:
            return {
                "success": True,
                "status": "STOPPED"
            }

        server.shutdown()
        server.server_close()

        if thread is not None and thread.is_alive():
            thread.join(timeout=self.SOCKET_TIMEOUT + 1)

        return {
            "success": True,
            "status": "STOPPED"
        }

    def send_message(self, host, port, message):
        if not self._is_loopback_host(host):
            return {
                "success": False,
                "error": "Only loopback destinations are permitted"
            }

        if isinstance(port, bool) or not isinstance(port, int):
            return {"success": False, "error": "Invalid port"}

        if not 1 <= port <= 65535:
            return {"success": False, "error": "Invalid port"}

        if not self.communication_engine.validate_message(message):
            return {
                "success": False,
                "error": "Message validation failed"
            }

        encoded = self._encode_message(message)

        if encoded is None:
            return {
                "success": False,
                "error": "Invalid or oversized message"
            }

        try:
            with socket.create_connection(
                (host, port),
                timeout=self.SOCKET_TIMEOUT
            ) as connection:
                connection.settimeout(self.SOCKET_TIMEOUT)
                connection.sendall(encoded + b"\n")

                with connection.makefile("rb") as response_file:
                    raw_response = response_file.readline(
                        self.MAX_MESSAGE_SIZE + 2
                    )

            if (
                not raw_response
                or len(raw_response) > self.MAX_MESSAGE_SIZE + 1
                or not raw_response.endswith(b"\n")
            ):
                return {
                    "success": False,
                    "error": "Invalid transport response"
                }

            try:
                response = json.loads(raw_response.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {
                    "success": False,
                    "error": "Invalid transport response"
                }

            if not isinstance(response, dict):
                return {
                    "success": False,
                    "error": "Invalid transport response"
                }

            return response

        except (OSError, socket.timeout):
            return {
                "success": False,
                "error": "Transport connection failed"
            }

    def engine_info(self):
        with self._lock:
            running = self.server is not None

        return {
            "engine": "VOIN Network Transport Engine",
            "version": self.VERSION,
            "transport": "TCP",
            "message_framing": "NEWLINE_DELIMITED_JSON",
            "message_size_limit": self.MAX_MESSAGE_SIZE,
            "loopback_only": True,
            "communication_bridge": True,
            "server_running": running,
            "tls_enabled": False,
            "cryptographic_peer_authentication": False,
            "status": "RUNNING" if running else "READY_FOR_TESTING"
        }
