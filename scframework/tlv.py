import struct
from .constants import SmartCardConstants
from .utilities import StringUtils

# ------------------------------------------------------- #
# BER-TLV Parsing                                         #
# ------------------------------------------------------- #

class Tag:

    def __init__(self, tag=None, length=None, value=None, tlv_string=None, tlv_bytes=None):
        # Flags
        self.constructed = False
        self.multibyte_tag = False
        self.multibyte_length = False
        self.autocalc_length = False
        # Fields
        self.tag = None
        self.length = 0
        self.value = None
        # Miscellaneous
        self.name = "Unknown Tag"
        self.children = []
        self.tlv_string = None
        self.tlv_bytes = None
        self.remainder = None
        self.format = None

        # User wishes to create a new tag from scratch
        if tag is not None:
            self.tag = tag
            self.length = length
            self.value = value

        # If they don't provide a length, calculate it, if they do,
        # use that.
        if tag is not None and length is None:
            self.length = len(self.value)

        # If we've been provided with a hex string, convert it to bytes
        if tlv_string is not None:
            self.tlv_bytes = bytearray.fromhex(tlv_string)

        # If we've been provided with TLV bytes, just store it
        if tlv_bytes is not None:
            self.tlv_bytes = tlv_bytes

        # If we're given an existing TLV tag in either string or bytes, parse it
        if self.tlv_bytes is not None:
            self.parse_existing()


    # ------------------------------------------------------------- #

    def find(self, target_tag, depth=0):
        depth += 1
        if self.tag == target_tag:
            return self
        for child in self.children:
            if child.tag == target_tag:
                return child
            child_found = child.find(target_tag, depth)
            if child_found is not None:
                return child_found
        return None

    # ------------------------------------------------------------- #

    # Parse out the values from the existing TLV data we've been given
    def parse_existing(self):
        self.tag = struct.unpack('>B', self.tlv_bytes[0:1])[0]

        # Are we "constructed"? Are there child elements?
        if self.tag & 0x20 == 0x20:
            self.constructed = True

        # Check whether this is a multi-byte tag
        if self.tag & 0x1F == 0x1F:
            self.tag, rem_data = struct.unpack('>H', self.tlv_bytes[0:2])[0], self.tlv_bytes[2:]
        else:
            rem_data = self.tlv_bytes[1:]
        
        self.tag_str = format(self.tag, 'x').upper()
        if self.tag_str in SmartCardConstants.TLV_TAGS:
            if isinstance(SmartCardConstants.TLV_TAGS[self.tag_str], dict):
                self.name = SmartCardConstants.TLV_TAGS[self.tag_str]['name']
                self.format = SmartCardConstants.TLV_TAGS[self.tag_str]['format']
            else:
                self.name = SmartCardConstants.TLV_TAGS[self.tag_str]

        # Parse the length field
        try:
            self.length, rem_data = rem_data[0], rem_data[1:]
        except Exception as err:
            return

        # If the MSB of the length value is set, we have a multi-byte
        # length field. The least significant 7 bits will be how many
        # subsequent length fields we expect.
        if self.length & 0x80 == 0x80:
            len_byte_count = self.length & 0x7F
            self.length = 0
            # Iterate through each additional byte and construct an
            # integer from them.
            for i in range(len_byte_count):
                x = struct.unpack('B', rem_data[0:1])[0]
                self.length = self.length << 8
                self.length += x
            rem_data = rem_data[len_byte_count:]

        # TLV data beyond the scope of this tag which we have yet to parse
        remainder = rem_data[self.length:]
        # The data for this particular tag
        tag_data = rem_data[:self.length]
        self.value = tag_data

        # If our tag has children, iterate through and parse them
        if self.constructed:
            while tag_data:
                child_tag = Tag(tlv_bytes=tag_data)
                self.children.append(child_tag)
                tag_data = child_tag.remainder

        self.remainder = remainder
    
    # ------------------------------------------------------------- #
    # Output Options                                                #
    # ------------------------------------------------------------- #

    def to_bytes(self):
        tag = self.tag
        tlv_bytes = b''

        # Tag
        while tag > 0:
            tlv_bytes = struct.pack('B', (tag & 0xFF)) + tlv_bytes
            tag >>= 8

        # Length
        if self.length < 128:
            tlv_bytes += struct.pack('B', self.length)
        if self.length >= 128 and self.length < 256:
            tlv_bytes += struct.pack('BB', 0x81, self.length)

        # Value
        tlv_bytes += self.value
    
        return tlv_bytes

    # ------------------------------------------------------------- #
    
    def to_str(self):
        return StringUtils.bytes_to_hex(self.to_bytes())

    # ------------------------------------------------------------- #

    def print_structure(self, depth=0):
        print(("  " * depth) + self.__str__())
        depth += 1
        for child in self.children:
            child.print_structure(depth=depth)
            
    # ------------------------------------------------------------- #

    def __str__(self):
        ret_str = "Tag(name='" + self.name + "', hex=" + hex(self.tag) + \
                  ", len=" + str(self.length)
        if self.constructed:
            ret_str += ")"
            return ret_str
        else:
            ret_str += ", value=" + StringUtils.bytes_to_hex(self.value) + ")"
            return ret_str

    # ------------------------------------------------------------- #
