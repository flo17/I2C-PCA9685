# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
            'error': {
                'format': 'Error!'
            },
            "i2c-pca9685": {
                'format': 'address: {{data.address}}; data[{{data.count}}]: [ {{data.data}} ]'
            }
        }

    temp_frame = None
    data_bytes = None

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        pass

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # set our frame to an error frame, which will eventually get over-written as we get data.
        if self.temp_frame is None:
            self.temp_frame = AnalyzerFrame("error", frame.start_time, frame.end_time, {
                "address": "error",
                "count": 0,
                "register#_hex": "",
                "register#": "",
                "data": "",
                "LED" : "",
                "LEDX_ON_L" : "",
                "LEDX_ON_H" : "",
                "LEDX_OFF_L" : "",
                "LEDX_OFF_H" : ""
            }
            )

        if frame.type == "start" or (frame.type == "address" and self.temp_frame.type == "error"):
            self.data_bytes = []
            frame_to_flush = None
            if frame.type == "start" and self.temp_frame.type != "error":
                # the previous frame hasn't been flushed yet. Likely a repeated start event.
                frame_to_flush = self.temp_frame
            self.temp_frame = AnalyzerFrame("i2c-pca9685", frame.start_time, frame.end_time, {
                    "count": 0,
                    "register#_hex": "",
                    "register#": "",
                    "data": "",
                    "LED" : "",
                    "LEDX_ON_L" : "",
                    "LEDX_ON_H" : "",
                    "LEDX_OFF_L" : "",
                    "LEDX_OFF_H" : ""
                }
            )
            return frame_to_flush

        if frame.type == "address":
            self.temp_frame.end_time = frame.end_time
            address_byte = frame.data["address"][0]
            self.temp_frame.data["address"] = hex(address_byte)

        if frame.type == "data":
            self.temp_frame.end_time = frame.end_time
            self.temp_frame.data["count"] += 1
            self.data_bytes.append(frame.data["data"][0])


        if frame.type == "stop":
            self.temp_frame.end_time = frame.end_time
            new_frame = self.temp_frame
            self.temp_frame = None
            new_frame.data["count"] = str(int(hex(new_frame.data["count"]), 16))

            # Convert self.data_bytes to a string
            new_frame.data["data"] = ", ".join([hex(x) for x in self.data_bytes])

            # Process the data into sub-columns
            if len(self.data_bytes) > 0:
                new_frame.data["register#_hex"] = hex(self.data_bytes[0])
                new_frame.data["register#"] = str(int(hex(self.data_bytes[0]), 16))

                # If the data is a write to the LED register, process the data into sub-columns
                if len(self.data_bytes) == 5:
                    led_num = (self.data_bytes[0] - 6) // 4
                    new_frame.data["LED"] = str(led_num)
                    new_frame.data["LEDX_ON_L"] = hex(self.data_bytes[1])
                    new_frame.data["LEDX_ON_H"] = hex(self.data_bytes[2])
                    new_frame.data["LEDX_OFF_L"] = hex(self.data_bytes[3])
                    new_frame.data["LEDX_OFF_H"] = hex(self.data_bytes[4])


            return new_frame