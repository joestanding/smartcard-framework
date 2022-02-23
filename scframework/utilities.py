class StringUtils:

    @staticmethod
    def byte_to_hex(byte):
        return '{0:02x}'.format(byte)

    @staticmethod
    def bytes_to_hex(byte_string):
        return "".join(['{0:02x}'.format(x) for x in byte_string]).upper()

    @staticmethod
    def bytes_to_string(byte_string):
        return "".join([chr(x) for x in byte_string])

    @staticmethod
    def int_to_hex(integer):
        x = '%x' % (integer,)
        return (('0' * (len(x) % 2)) + x).upper()
