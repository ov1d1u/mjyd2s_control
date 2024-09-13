class MJYD2SConfiguration:
    def __init__(self, configuration_bytes):
        if len(configuration_bytes) != 8:
            raise ValueError("Invalid configuration bytes")
        
        self.is_on = bool(configuration_bytes[3])
        self.brightness = configuration_bytes[4]
        self.is_enabled = bool(configuration_bytes[5])
        self.duration = configuration_bytes[6]
        self.ambient_limit = configuration_bytes[7]
        
    def bytes(self):
        byte_array = b"\x07\x03\x00"
        byte_array += "\x01" if self.is_on else "\x00"
        byte_array += bytes([self.brightness])
        byte_array += "\x01" if self.is_enabled else "\x00"
        byte_array += bytes([self.duration])
        byte_array += bytes([self.ambient_limit])
        return byte_array