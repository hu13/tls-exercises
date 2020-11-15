import socket
import ssl
from pathlib import Path


LOCAL_HOST = 'localhost'
LOCAL_PORT = 8282
RESOURCE_DIRECTORY = Path(__file__).resolve().parent.parent / 'resources' / 'client'
CA_CERT = RESOURCE_DIRECTORY / 'ca.cert.pem'


def main():
    """
    Exercise 1 Client
    """

    # Part 1
    # Add code here to create and configure an SSLContext, wrap a socket and connect using TLS
    # For help check out:
    #      https://github.com/mikepound/tls-exercises/blob/master/python/README.md

    # Create a standard TCP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create SSL context which holds the parameters for any sessions
    context = ssl.create_default_context(cafile=CA_CERT)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3
    context.set_ciphers('ALL:!DSS:!DHE:!aNULL:!eNull')

    # We can wrap in an SSL context first, then connect
    conn = context.wrap_socket(sock, server_hostname="Expert TLS Server")
    try:
        # Connect using conn
        conn.connect((LOCAL_HOST, LOCAL_PORT))

        # The code below is complete, it will use a connection to send and receive from the server
        if conn is None:
            return

        # What parameters were established?
        print("Negotiated session using cipher suite: {0}\n".format(conn.cipher()[0]))

        # In python sockets send and receive bytes. Send some numbers:
        ints = [2, 3, 5, 7, 11, 13, 17, 19, 23]
        conn.send(bytes(ints))

        # Receive a number back from the server
        server_response = conn.recv(1024)

        # Server response is an int, convert it back
        server_int = int.from_bytes(server_response, 'big')
        from functools import reduce
        assert server_int == reduce(lambda x, y: x*y, ints)
        print(server_int)
    finally:
        if conn is not None:
            conn.close()


if __name__ == '__main__':
    main()
