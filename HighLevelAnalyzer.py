# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from binascii import hexlify


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('Show empty frames', 'Do not show empty frames'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'LINAK_frame_transaction': {
            'format': '{{data.parsed_command}} (Command: {{data.cmd}}, data: {{data.bytes}})'
        },
        'LINAK_frame_empty': {
            'format': '(Command: {{data.cmd}})'
        }
    }

    def PID_to_cmd(pid_byte):
        commands = {
            0: ["Ref1 Position and status", 0],
            1: ["Ref2 Position and status", 0],
            2: ["Ref3 Position and status", 0],
            3: ["Ref4 Position and status", 0],
            4: ["Ref5 Position and status", 0],
            5: ["Ref6 Position and status", 0],
            6: ["Ref7 Position and status", 0],
            7: ["Ref8 Position and status", 0],
            8: ["Master reference output", 0],
            9: ["Undefined", 0],
            10: ["Ref1 Input", 0],
            11: ["Ref2 Input", 0],
            12: ["Ref3 Input", 0],
            13: ["Ref4 Input", 0],
            14: ["Set compare serial #", 0],
            15: ["Get compare result", 0],
            16: ["Define slave #", 0],
            17: ["Enter boot load mode", 0],
            18: ["Slave 1 reference response", 0],
            19: ["Slave 2 reference response", 0],
            20: ["Slave 3 reference response", 0],
            21: ["Master bed reference outputs", 0],
            22: ["Slave 1 bed reference outputs", 0],
            23: ["Slave 2 bed reference outputs", 0],
            24: ["Slave 3 bed reference outputs", 0],
            25: ["Undefined", 0],
            26: ["Undefined", 0],
            27: ["Master serial", 0],
            28: ["Diagnostic message", 0],
            29: ["Twindrive slave 1 max speeds, status and positions", 0],
            30: ["Twindrive reference info", 0],
            31: ["Twindrive slave 0 max speeds", 0],
            32: ["Twindrave slave serial", 0],
            33: ["Undefined", 0],
            34: ["Undefined", 0],
            35: ["(backwards compatibilty)", 0],
            36: ["Request power", 0],
            37: ["Handset 1 command", 0],
            38: ["Handset 2 command", 0],
            39: ["Handset 1 safety sequence", 0],
            40: ["Handset 2 safety sequence", 0],
            41: ["Config request", 0],
            42: ["Config response", 0],
            43: ["Config take control", 0],
            44: ["--Unspecced--", 0],
        }

        return commands.get(pid_byte, ["invalid_command", 0])

    def translate_pid_data(pid_byte, data_bytes):
        if pid_byte <= 7:
            if len(data_bytes) != 6:
                return "Invalid length"
            ref_num = int(pid_byte) + 1
            current_position = int(data_bytes[1]) * 256 + int(data_bytes[0])
            return "Ref{} position: {}mm".format(ref_num, current_position / 10)
        elif pid_byte >= 10 and pid_byte <= 13:
            if len(data_bytes) != 3:
                return "Invalid length"
            ref_num = int(pid_byte) - 9
            command = int(data_bytes[1]) * 256 + int(data_bytes[0])
            if command == 0x7FFF:
                return "Ref{} move down".format(ref_num)
            elif command == 0x8000:
                return "Ref{} move up".format(ref_num)
            elif command == 0x8001:
                return "Ref{} do not move".format(ref_num)
            else:
                return "Ref{} move to position: {}mm".format(ref_num, command / 10)
        elif pid_byte == 36:
            if len(data_bytes) != 2:
                return "Invalid length"
            return "Power requested on"
        elif pid_byte == 37 or pid_byte == 38:
            handset_num = int(pid_byte) - 36
            return "Handset {} action {} flags 0x{}".format(handset_num, int(data_bytes[0]), hex(data_bytes[1]))
        elif pid_byte == 39 or pid_byte == 40:
            handset_num = int(pid_byte) - 38
            # Todo: say something if sequence is not expected?
            # 63 223 207 215 195 221 204 85 128
            return "Handset {} sequence {}".format(handset_num, int(data_bytes[0]))

        return ""

    def reset_state(self):
        # Static tracking variables
        self.current_starting_time = None
        self.last_end_time = None
        self.has_data = False
        self.has_checksum = False
        self.PID = None
        self.data = bytearray()


    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.reset_state()

        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)


    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        frames = []

        if frame.type == "header_break":
            if self.current_starting_time is not None and self.PID is not None:
                # Save last frame
                if len(self.data) > 0:
                    frames.append(AnalyzerFrame('LINAK_frame_transaction', self.current_starting_time, self.last_end_time,
                                    {
                                        'bytes': hexlify(self.data[:-1 if len(self.data) > 0 else 0]).decode('ascii'),
                                        'cmd': Hla.PID_to_cmd(self.PID)[0],
                                        'parsed_command': Hla.translate_pid_data(self.PID, self.data),
                                    }))
                else:
                    if self.my_choices_setting != "Do not show empty frames":
                        frames.append(AnalyzerFrame('LINAK_frame_empty', self.current_starting_time, self.last_end_time,
                                        {
                                            'cmd': Hla.PID_to_cmd(self.PID)[0],
                                        }))

            self.reset_state()
            self.current_starting_time = frame.start_time
        elif frame.type == "header_pid":
            self.PID = frame.data['protected_id']
        elif frame.type == "data" or frame.type == 'data_or_checksum':
            self.data += bytearray(frame.data['data'].to_bytes(1, 'big'))

        self.last_end_time = frame.end_time
        # Return the data frame itself
        return frames
