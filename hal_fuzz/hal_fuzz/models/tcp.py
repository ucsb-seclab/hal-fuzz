from . import Model
from ..handlers.fuzz import get_fuzz
from collections import deque


class TCP(Model):
    """
    Models the scenario of a TCP socket-style interface.
    """

    packet_queue = deque()
    port = None

    # TODO: Support multiple ports
    # TODO: Support non-fuzzed input

    @classmethod
    def listen(cls, port):
        cls.port = port

    @classmethod
    def is_client_connected(cls):
        return True

    @classmethod
    def tx_packet(cls, payload):
        '''
            Creates the message that Peripheral.tx_msgs will send on this
            event
        '''
        print(payload)

    @classmethod
    def has_rx_packet(cls):
        if cls.packet_queue:
            return True
        else:
            return False

    @classmethod
    def enqueue_packet(cls, payload):
        cls.packet_queue.append(payload)

    @classmethod
    def get_rx_packet(cls):
        if cls.packet_queue:
            print("TCP: Returning frame")
            pkt = cls.packet_queue.popleft()
            return pkt
        else:
            print("TCP: No data to return")
            return None
