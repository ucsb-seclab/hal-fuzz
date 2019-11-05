from collections import deque, defaultdict
from ..handlers.fuzz import get_fuzz, fuzz_remaining
from ..globs import debug_enabled
from ..exit import do_exit
import sys
from . import register_model, Model

marker = b'\xbe\xef\xfa\xce'


class SerialModel(Model):

        frame_queues = defaultdict(deque)
        rx_frame_isr = None
        rx_isr_enabled = False
        packet_serial = False
        irq = None
        irq = None
        @classmethod
        def configure(cls, uc, config):

            if 'packet_serial' in config and config['packet_serial']:
                SerialModel.packet_serial = True
            if 'serial_irq' in config and config['serial_irq']:
                SerialModel.irq = config['serial_irq']
            # TODO: Fuzzed and native Serial support via a config
            pass

        @classmethod
        def tx(cls, interface_id, buf):
            '''
                Creates the message that Peripheral.tx_msga will send on this
                event
            '''
            if isinstance(buf, bytes):
                buf = buf.decode('latin1')
            sys.stdout.write(buf)

        cur_serial_frame = ""
        @classmethod
        def rx(cls, interface_id, count=1):
            if SerialModel.packet_serial:
                if not SerialModel.cur_serial_frame:
                    ret = SerialModel.cur_serial_frame
                    SerialModel.cur_serial_frame = SerialModel.get_next_frame(interface_id)
                    return ret
                out = SerialModel.cur_serial_frame[:count]
                SerialModel.cur_serial_frame = SerialModel.cur_serial_frame[count:]
                return out
            else:
                return get_fuzz(count)

        @classmethod
        def queue_frame(cls, interface_id):
            cls.cur_serial_frame = cls.get_next_frame(interface_id)

        @classmethod
        def get_next_frame(cls, interface_id, marker=b'<LF>'):
            print("Getting a new frame")
            if fuzz_remaining() == 0:
                # we're done
                do_exit(0)
            frame = b""
            while fuzz_remaining() > 0 and not frame.endswith(marker):
                print(repr(frame))
                frame += get_fuzz(1)
            if frame.endswith(marker):
                frame = frame[:-len(marker)]
            return frame

register_model(SerialModel)