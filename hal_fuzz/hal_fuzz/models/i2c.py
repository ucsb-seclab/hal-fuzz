from collections import deque, defaultdict
from ..handlers.fuzz import get_fuzz, fuzz_remaining
from ..globs import debug_enabled
from ..exit import do_exit
import sys
from . import register_model, Model


class I2CModel(Model):

        frame_queues = defaultdict(deque)
        packet_i2c = False

        @classmethod
        def configure(cls, uc, config):
            if 'packet_i2c' in config and config['packet_serial']:
                I2CModel.packet_i2c = True
            # TODO: Fuzzed and native i2c support via a config
            pass

        @classmethod
        def tx(cls, interface_id, addr, buf):
            '''
                Creates the message that Peripheral.tx_msga will send on this
                event
            '''
            if isinstance(buf, bytes):
                buf = buf.decode('latin1')
            sys.stdout.write(buf)

        cur_i2c_frame = ""
        @classmethod
        def rx(cls, interface_id, addr, count=1):
            if I2CModel.packet_i2c:
                if not I2CModel.cur_i2c_frame:
                    ret = I2CModel.cur_i2c_frame
                    I2CModel.cur_i2c_frame = I2CModel.get_next_frame(interface_id)
                    return ret
                out = I2CModel.cur_i2c_frame[:count]
                I2CModel.cur_i2c_frame = I2CModel.cur_i2c_frame[count:]
                return out
            else:
                return get_fuzz(count)

        @classmethod
        def queue_frame(cls, interface_id, addr):
            cls.cur_i2c_frame = cls.get_next_frame(interface_id, addr)

        @classmethod
        def get_next_frame(cls, interface_id, addr, marker=b'<LF>'):
            #print("Getting a new frame")
            if fuzz_remaining() == 0:
                # we're done
                print("I2C: out of input, exiting")
                do_exit(0)
            frame = b""
            while fuzz_remaining() > 0 and not frame.endswith(marker):
                frame += get_fuzz(1)
            if frame.endswith(marker):
                frame = frame[:-len(marker)]
            return frame


register_model(I2CModel)