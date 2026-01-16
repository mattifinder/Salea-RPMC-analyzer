# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'write_root_key': {
            'format': 'write root key, counter {{data.target_counter}}, 0x{{data.root_key}}',
        },
        'update_hmac_key': {
            'format': 'update hmac key, counter {{data.target_counter}}, key data 0x{{data.key_data}}'
        },
        'increment': {
            'format': 'increment counter {{data.target_counter}}, previous value {{data.previous_value}}'
        },
        'get': {
            'format': 'get counter {{data.target_counter}}, tag 0x{{data.tag}}'
        },
        'status_short': {
            'format': 'status {{data.result_bits}}'
        },
        'status_long': {
            'format': 'status {{data.result_bits}}, counter value {{data.counter_value}}, tag 0x{{data.tag}}'
        }
    }

    op1_opcode = 0x9b # NumberSetting(min_value=0, max_value=0xff)
    op2_opcode = 0x96 # NumberSetting(min_value=0, max_value=0xff)

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.miso = None
        self.mosi = None
        self.frames_read = None

    def _analyze(self) -> AnalyzerFrame:
        if len(self.mosi) < 3:
            return None

        if self.mosi[0] == 0x9b:
            if self.mosi[1] == 0:
                return AnalyzerFrame('write_root_key', self.start_time, self.end_time, {
                    'target_counter': self.mosi[2],
                    'root_key': self.mosi[4:36].hex()
                })
            elif self.mosi[1] == 1:
                return AnalyzerFrame('update_hmac_key', self.start_time, self.end_time, {
                    'target_counter': int(self.mosi[2]),
                    'key_data': self.mosi[4:8].hex()
                })
            elif self.mosi[1] == 2:
                return AnalyzerFrame('increment', self.start_time, self.end_time, {
                    'target_counter': self.mosi[2],
                    'previous_value': int.from_bytes(self.mosi[4:8], byteorder='big')
                })
            elif self.mosi[1] == 3:
                return AnalyzerFrame('get', self.start_time, self.end_time, {
                    'target_counter': self.mosi[2],
                    'tag': self.mosi[4:16].hex()
                })
        elif self.mosi[0] == 0x96:
            if len(self.miso) > 3:
                return AnalyzerFrame('status_long', self.start_time, self.end_time, {
                    'result_bits': bin(self.miso[2]),
                    'tag': self.miso[3:15].hex(),
                    'counter_value': int.from_bytes(self.miso[15:19], byteorder='big')
                })
            else:
                return AnalyzerFrame('status_short', self.start_time, self.end_time, {
                    'result_bits': bin(self.miso[2])
                })


    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'enable':
            self.start_time = frame.start_time
            self.miso = b''
            self.mosi = b''
            self.frames_read = 0
        elif frame.type == 'result':
            if self.frames_read < 64: # longest command is write root key with length 64
                self.miso += frame.data['miso']
                self.mosi += frame.data['mosi']
            self.frames_read += 1
        elif frame.type == 'disable':
            self.end_time = frame.end_time
            return self._analyze()
        elif frame.type == 'error':
            print(f'Unknown frame type: {frame.type} {frame.start_time}')
            self.start_time = None
            self.miso = None
            self.mosi = None
