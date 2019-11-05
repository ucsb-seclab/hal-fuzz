from collections import deque, defaultdict
from ..handlers.fuzz import get_fuzz, fuzz_remaining
from ..globs import debug_enabled
from ..exit import do_exit
import sys

marker = b'\xbe\xef\xfa\xce'

class EthernetModel:

        frame_queues = defaultdict(deque)
        calc_crc = True
        rx_frame_isr = None
        rx_isr_enabled = False
        frame_times = defaultdict(deque)  # Used to record reception time
        MTU_SIZE = 1520

        @classmethod
        def configure(cls, uc, config):
            # TODO: Fuzzed and native ethernet support via a config
            pass

        @classmethod
        def tx_frame(cls, interface_id, frame):
            '''
                Creates the message that Peripheral.tx_msga will send on this
                event
            '''
            if True:
                try:
                    import dpkt
                    e = dpkt.ethernet.Ethernet(frame)
                    print("ETH OUT: " + repr(e))
                    #import ipdb; ipdb.set_trace()
                except:
                    input("Cannot decode ethernet packet...")
            pass

        @classmethod
        def get_rx_frame(cls, interface_id):
            frame = None
            if not cls.frame_queues[interface_id]:
                cls.get_fuzz_frames(interface_id)
            if cls.frame_queues[interface_id]:
                frame = cls.frame_queues[interface_id].popleft()
                if True:
                    try:
                        import dpkt
                        e = dpkt.ethernet.Ethernet(frame)
                        print("ETH IN: " + repr(e))
                    except:
                        input("Cannot decode ethernet packet...")
                # import ipdb;
                # ipdb.set_trace()
                return frame
            else:
                return frame

        @classmethod
        def get_fuzz_frames(cls, interface_id):
            if fuzz_remaining() == 0:
                # we're done
                do_exit(0)
            while fuzz_remaining() > 0:
                frame = b""
                while fuzz_remaining() > 0 and not frame.endswith(marker):
                    frame += get_fuzz(1)
                if frame.endswith(marker):
                    frame = frame[:-len(marker)]
                if len(frame) > 1514:
                    # AFL fucked up
                    do_exit(1)
                cls.frame_queues[interface_id].append(frame)

        @classmethod
        def get_frame_info(cls, interface_id):
            '''
                return number of frames and length of first frame
            '''
            queue = cls.frame_queues[interface_id]
            if not queue:
                cls.get_fuzz_frames(interface_id)
            queue = cls.frame_queues[interface_id]
            if not queue:
                return 0, 0
            return len(queue), len(queue[0])
