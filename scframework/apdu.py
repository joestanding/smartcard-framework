import binascii
from .tlv import Tag
from .utilities import StringUtils
from colorama import Fore, Back, Style
from tabulate import tabulate
import textwrap

def colour(string, colour):
    return colour + string + Style.RESET_ALL

# ------------------------------------------------------- #
# Base APDU Request                                       #
# ------------------------------------------------------- #

class Request:

    name = "Generic Request"
    cla  = 0x00
    ins  = 0x00

    def __init__(self):
        self.p1 = 0x00
        self.p2 = 0x00
        self.lc = 0x00
        self.le = 0x00
        self.data = b''

    def _byte_to_hex(self, byte):
        return '{0:02x}'.format(byte)

    def _bytes_to_string(self, byte_string):
        return "".join([chr(x) for x in byte_string])

    def _from_str(self, string):
        req_bytes = bytearray.fromhex(string)
        self.cla = req_bytes[0]
        self.ins = req_bytes[1]
        self.p1  = req_bytes[2]
        self.p2  = req_bytes[3]
        self.lc  = req_bytes[4]
        self.le  = req_bytes[len(req_bytes)-1]
        self.data = req_bytes[5:(5+self.lc)]

    @staticmethod
    def from_str(string):
        """
        Called statically by the user - used to return a specific subclass
        e.g. a ReadRecord instance will be returned instead of a generic
        Request if the APDU command is "READ RECORD".
        """
            
        try:
            req_bytes = bytearray.fromhex(string)
        except ValueError:
            return None
        if len(string) == 0:
            return None
        cla = req_bytes[0]
        ins = req_bytes[1]

        # Iterate through all registered requests
        for sc in Request.__subclasses__():
            sc_cla = sc.cla if isinstance(sc.cla, list) else [sc.cla]
            sc_ins = sc.ins if isinstance(sc.ins, list) else [sc.ins]

            if cla in sc_cla and ins in sc_ins:
                obj = sc()
                obj._from_str(string)
                return obj
        obj = Request()
        obj._from_str(string)
        return obj

    def to_bytes(self):
        self.lc = len(self.data)
        return bytes([self.cla]) + \
               bytes([self.ins]) + \
               bytes([self.p1]) + \
               bytes([self.p2]) + \
               bytes([self.lc]) + \
               self.data + \
               bytes([self.le])

    def to_str(self):
        self.lc = len(self.data)

        apdu =  self._byte_to_hex(self.cla)
        apdu += self._byte_to_hex(self.ins)
        apdu += self._byte_to_hex(self.p1)
        apdu += self._byte_to_hex(self.p2)
        apdu += self._byte_to_hex(self.lc)
        apdu += binascii.hexlify(self.data).decode('ascii')
        apdu += self._byte_to_hex(self.le)
        return apdu

    # Explanations!
    # These are overriden by subclasses of Request which
    # provide custom explanations of each field for a given
    # type of request

    def explain_p1(self):
        return ""

    def explain_p2(self):
        return ""

    def explain_data(self):
        return ""

    def get_name(self):
        return self.name

    def __str__(self):
        return "Request(name=" + self.get_name() + \
                ", cla=" + self._byte_to_hex(self.cla) + \
                ", ins=" + self._byte_to_hex(self.ins) + \
                ", p1=" + self._byte_to_hex(self.p1) + \
                ", p2=" + self._byte_to_hex(self.p2) + \
                ", lc=" + self._byte_to_hex(self.lc) + \
                ", le=" + self._byte_to_hex(self.le) + ")"

    def pretty_print(self):
        
        data_ascii = self.data.decode('ascii', 'ignore')
        table = [
                    [ colour("Class", Fore.MAGENTA), hex(self.cla), ""],
                    [ colour("Instruction  ", Fore.MAGENTA), hex(self.ins), colour(self.get_name(), Style.DIM) ],
                    [ colour("P1", Fore.MAGENTA), hex(self.p1), colour(self.explain_p1(), Style.DIM) ],
                    [ colour("P2", Fore.MAGENTA), hex(self.p2), colour(self.explain_p2(), Style.DIM) ],
                    [ colour("Le", Fore.MAGENTA), hex(self.le), colour(str(self.le) + " bytes expected in response", Style.DIM) ],
                    [ colour("Lc", Fore.MAGENTA), hex(self.lc), colour(str(self.lc) + " bytes of data in this message", Style.DIM) ],
                    [ colour("Data", Fore.MAGENTA), textwrap.fill(StringUtils.bytes_to_hex(self.data), width=50), colour(data_ascii, Style.DIM) ]
                ]

        print("")
        print(colour("============> REQUEST TO CARD ============>", Fore.YELLOW))
        print(tabulate(table, headers=[colour('Field', Fore.CYAN),
                                       colour('Hex', Fore.CYAN),
                                       colour('Meaning', Fore.CYAN)]))
        print("")

# ------------------------------------------------------- #
# Base APDU Response                                      #
# ------------------------------------------------------- #

class Response:

    RESPONSES = { 
            ( 0x90, 0x00 ) : "Command Successfully Executed (OK)",
            ( 0x67, 0x00 ) : "Invalid Length",
            ( 0x69, 0x83 ) : "Command Not Allowed - Authentication Method Blocked",
            ( 0x69, 0x84 ) : "Command Not Allowed - Referenced Data Invalidated",
            ( 0x69, 0x85 ) : "Command Not Allowed - Conditions of Use Not Satisifed",
            ( 0x6A, 0x81 ) : "Wrong Parameter(s) - Function Not Supported",
            ( 0x6A, 0x82 ) : "Wrong Parameter(s) - File Not Found",
            ( 0x6A, 0x83 ) : "Wrong Parameter(s) - Record Not Found",
            ( 0x6A, 0x88 ) : "Referenced Data Not Found",
            ( 0x62, 0x83 ) : "State of NVRAM Not Changed; Selected File Invalidated",
            ( 0x63, 0x00 ) : "State of NVRAM Change; Authentication Failed",
    }
    
    def __init__(self, sw1=0x00, sw2=0x00, data=b'', apdu_str=None):
        self.tlv = None

        if apdu_str is not None:
            try:
                apdu_bytes = bytearray.fromhex(apdu_str)
            except Exception as err:
                return None
            self.sw1 = apdu_bytes[len(apdu_bytes)-2]
            self.sw2 = apdu_bytes[len(apdu_bytes)-1]
            self.data = apdu_bytes[0:-2]
        else:
            self.sw1 = sw1
            self.sw2 = sw2
            self.data = data
        if len(self.data) > 0:
            self.tlv = Tag(tlv_bytes=self.data)

    def from_str(apdu_str):
        if len(apdu_str) == 0:
            return None
        try:
            bytearray.fromhex(apdu_str)
        except Exception as err:
            return None
        instance = Response(apdu_str=apdu_str)
        return instance

    def to_str(self):
        apdu_str = StringUtils.byte_to_hex(self.sw1) + \
                   StringUtils.byte_to_hex(self.sw2) + \
                   StringUtils.bytes_to_hex(self.data)
        return apdu_str

    def get_name(self):
        if self.sw1 == 0x61:
            return "Command Executed, " + str(self.sw2) + " Bytes Available"
        try:
            return self.RESPONSES[(self.sw1, self.sw2)]
        except Exception as e:
            return "Unknown"

    def get_mutations(self):
        muts = []
        if self.tlv is not None:
            for mut in self.tlv.get_mutations():
                mut['data'] = mut['data'] + bytes([self.sw1]) + \
                            bytes([self.sw2])
                muts.append(mut)
        return muts


    def __str__(self):
        return "Response(status='" + self.get_name() + \
                "', sw1=" + hex(self.sw1) + \
                ", sw2=" + hex(self.sw2) + ")"

    def pretty_print(self):
        if self.sw1 == 0x90 and self.sw2 == 0x00:
            msg_colour = Fore.GREEN
        else:
            msg_colour = Fore.RED
        table = [
            [ colour("SW1", Fore.MAGENTA), "0x" + StringUtils.byte_to_hex(self.sw1), colour(self.get_name(), msg_colour) ],
            [ colour("SW2", Fore.MAGENTA), "0x" + StringUtils.byte_to_hex(self.sw2) ],
        ]
        print("")
        print(colour("<============ RESPONSE FROM CARD <============", Fore.BLUE))
        print(tabulate(table, headers=[colour('Field', Fore.CYAN),
                                       colour('Hex', Fore.CYAN),
                                       colour('Meaning', Fore.CYAN)]))
        print("")
        if hasattr(self, 'tlv'):
            if self.tlv is not None:
                Response.pretty_print_tlv(self.tlv)

    def pretty_print_tlv(tlv, depth=0):
        print((" " * depth) + colour(tlv.name, Fore.MAGENTA) + " " + \
          colour("(" + hex(tlv.tag) + ")", Style.DIM))
        if not tlv.constructed:
            if tlv.format == 'alphanumeric' or tlv.format == 'alphanumeric_special':
                print((" " * depth) + colour(tlv.value.decode('ascii', 'ignore'), Fore.CYAN))
            else:
                print((" " * depth) + colour(StringUtils.bytes_to_hex(tlv.value), Fore.CYAN))
        depth += 1
        for child in tlv.children:
            Response.pretty_print_tlv(child, depth=depth)

# ------------------------------------------------------- #
# ISO/7816 Implementations                                #
# ------------------------------------------------------- #

class ActivateFile(Request):
    name = "Activate File"
    cla  = 0x00
    ins  = 0x44

# ------------------------------------------------------- #

class AppendRecord(Request):
    name = "AppendRecord"
    cla  = 0x00
    ins  = 0xE2 

# ------------------------------------------------------- #

class ChangeReferenceData(Request):
    name = "Change Reference Data"
    cla  = 0x00
    ins  = 0x24

# ------------------------------------------------------- #

class CreateFile(Request):
    name = "Create File"
    cla  = 0x00
    ins  = 0xE0

# ------------------------------------------------------- #

class DeactivateFile(Request):
    name = "Deactivate File"
    cla  = 0x00
    ins  = 0x04

# ------------------------------------------------------- #

class DeleteFile(Request):
    name = "Delete File"
    cla  = 0x00
    ins  = 0xE4

# ------------------------------------------------------- #

class DisableVerificationRequirement(Request):
    name = "Disable Verification Requirement"
    cla  = 0x00
    ins  = 0x26

# ------------------------------------------------------- #

class EnableVerificationRequirement(Request):
    name = "Enable Verification Requirement"
    cla  = 0x00
    ins  = 0x28

# ------------------------------------------------------- #

class Envelope(Request):
    name = "Envelope"
    cla  = 0x00
    ins  = [0xC2, 0xC3]

# ------------------------------------------------------- #

class EraseBinary(Request):
    name = "Erase Binary"
    cla  = 0x00
    ins  = [0x0E, 0x0F]

# ------------------------------------------------------- #

class EraseRecord(Request):
    name = "Erase Record"
    cla  = 0x00
    ins  = 0x0C

# ------------------------------------------------------- #

class ExternalAuthenticate(Request):
    name = "External Authenticate"
    cla  = 0x00
    ins  = 0x82

# ------------------------------------------------------- #

class GeneralAuthenticate(Request):
    name = "General Authenticate"
    cla  = 0x00
    ins  = [0x86, 0x87]

# ------------------------------------------------------- #

class GenerateAsymKeyPair(Request):
    name = "Generate Asymmetric Key Pair"
    cla  = 0x00
    ins  = 0x46

# ------------------------------------------------------- #

class GetChallenge(Request):
    name = "Get Challenge"
    cla  = 0x00
    ins  = 0x84

# ------------------------------------------------------- #

class GetData(Request):
    name = "Get Data"
    cla  = 0x00
    ins  = [0xCA, 0xCB]

# ------------------------------------------------------- #

class GetResponse(Request):
    name = "Get Response"
    cla  = 0x00
    ins  = 0xC0

# ------------------------------------------------------- #

class InternalAuthenticate(Request):
    name = "Internal Authenticate"
    cla  = 0x00
    ins  = 0x88

# ------------------------------------------------------- #

class ManageChannel(Request):
    name = "Manage Channel"
    cla  = 0x00
    ins  = 0x70

# ------------------------------------------------------- #

class ManageSecurityEnvironment(Request):
    name = "Manage Security Environment"
    cla  = 0x00
    ins  = 0x22

# ------------------------------------------------------- #

class PerformSCQLOperation(Request):
    name = "Perform SCQL Operation"
    cla  = 0x00
    ins  = 0x10

# ------------------------------------------------------- #

class PerformSecurityOperation(Request):
    name = "Perform Security Operation"
    cla  = 0x00
    ins  = 0x2A

# ------------------------------------------------------- #

class PerformTransactionOperation(Request):
    name = "Perform Transaction Operation"
    cla  = 0x00
    ins  = 0x12

# ------------------------------------------------------- #

class PerformUserOperation(Request):
    name = "Perform User Operation"
    cla  = 0x00
    ins  = 0x12

# ------------------------------------------------------- #

class PutData(Request):
    name = "Perform User Operation"
    cla  = 0x00
    ins  = [0xDA, 0xDB]

# ------------------------------------------------------- #

class ReadBinary(Request):
    name = "Read Binary"
    cla  = 0x00
    ins  = [0xB0, 0xB1]

# ------------------------------------------------------- #

class ReadRecord(Request):
    name = "Read Record"
    cla  = 0x00
    ins  = [0xB2, 0xB3]

    def __init__(self):
        pass

    def explain_p1(self):
        record_no = int(self.p1)
        return "Record Number " + str(record_no) + \
                " (" + hex(record_no) + ")"

    def explain_p2(self):
        #return str(self.p1 & 0b00000111)
        if self.p1 & 0b00000111 == 0b000:
            return "Read First Occurence"
        if self.p1 & 0b00000111 == 0b001:
            return "Read Last Occurence"
        if self.p1 & 0b00000111 == 0b010:
            return "Read Next Occurence"
        if self.p1 & 0b00000111 == 0b011:
            return "Read Previous Occurence"
        if self.p1 & 0b00000111 == 0b100:
            return "Read Record P1"
        if self.p1 & 0b00000111 == 0b100:
            return "Read All Records From P1 Up To Last"
        if self.p1 & 0b00000111 == 0b100:
            return "Read All Records From Last Up To P1"
        if self.p1 & 0b00000111 == 0b111:
            return "Reserved"
        return "Unknown"

# ------------------------------------------------------- #

class ResetRetryCounter(Request):
    name = "Reset Retry Counter"
    cla  = 0x00
    ins  = 0x2C

# ------------------------------------------------------- #

class SearchBinary(Request):
    name = "Search Binary"
    cla  = 0x00
    ins  = [0xA0, 0xA1]

# ------------------------------------------------------- #

class SearchRecord(Request):
    name = "Search Record"
    cla  = 0x00
    ins  = 0xA2

# ------------------------------------------------------- #

class Select(Request):
    
    SELECT_MF_DF_OR_EF             = 0b0000
    SELECT_CHILD_DF                = 0b0001
    SELECT_EF_UNDER_CURRENT_DF     = 0b0010
    SELECT_PARENT_DF_OF_CURRENT_DF = 0b0011
    SELECT_BY_DF_NAME              = 0b0100
    SELECT_FROM_MF                 = 0b1000
    SELECT_FROM_CURRENT_DF         = 0b1001

    name = "Select"
    cla  = 0x00
    ins  = 0xA4

    def __init__(self, name=None, select_type=4):
        super(Select, self).__init__()
        if name is not None:
            self.data = bytearray.fromhex(name)
        self.p1 = select_type

    def explain_p1(self):
        p1 = self.p1
        if p1 == 0b00000000:
            return "Select MF, DF or EF"
        if p1 == 0b00000001:
            return "Select Child DF"
        if p1 == 0b00000010:
            return "Select EF Under Current DF"
        if p1 == 0b00000011:
            return "Select Parent DF of the Current DF"
        if p1 == 0b00000100:
            return "Direct Selection by DF Name"
        if p1 == 0b00001000:
            return "Select From MF"
        if p1 == 0b00001001:
            return "Select From Current DF"
        return "Unknown"

    def explain_p2(self):
        p2 = self.p2
        file_occurence = "Unknown"
        fci = "Unknown"
        ls4b = self.p2 & 0b00001111

        if ls4b & 0b0011 == 0b00:
            pass
        #TODO
        return ""


    def explain_data(self):
        return self._bytes_to_string(self.data)

# ------------------------------------------------------- #


class TerminateCardUsage(Request):
    name = "Terminate Card Usage"
    cla  = 0x00
    ins  = 0xFE

# ------------------------------------------------------- #

class TerminateDF(Request):
    name = "Terminate DF"
    cla  = 0x00
    ins  = 0xE6

# ------------------------------------------------------- #

class TerminateEF(Request):
    name = "Terminate EF"
    cla  = 0x00
    ins  = 0xE8

# ------------------------------------------------------- #

class UpdateBinary(Request):
    name = "Update Binary"
    cla  = 0x00
    ins  = [0xD6, 0xD7]

# ------------------------------------------------------- #

class UpdateRecord(Request):
    name = "Update Record"
    cla  = 0x00
    ins  = [0xDC, 0xDD]

# ------------------------------------------------------- #

class Verify(Request):
    name = "Verify"
    cla  = 0x00
    ins  = [0x20, 0x21]

# ------------------------------------------------------- #

class WriteBinary(Request):
    name = "Write Binary"
    cla  = 0x00
    ins  = [0xD0, 0xD1]

# ------------------------------------------------------- #

class WriteRecord(Request):
    name = "Write Record"
    cla  = 0x00
    ins  = 0xD2
    
# ------------------------------------------------------- #
# EMV Request Implementations                             #
# ------------------------------------------------------- #

class ApplicationBlock(Request):
    name = "Application Block"
    cla  = [0x8C, 0x84]
    ins  = 0x18

# ------------------------------------------------------- #

class ApplicationUnblock(Request):
    name = "Application Unblock"
    cla  = [0x8C, 0x84]
    ins  = 0x16

# ------------------------------------------------------- #

class CardBlock(Request):
    name = "Card Block"
    cla  = [0x8C, 0x84]
    ins  = 0x16

# ------------------------------------------------------- #

class GenerateApplicationCryptogram(Request):
    name = "Generate Application Cryptogram"
    cla  = 0x80
    ins  = 0xAE

    def explain_p1(self):
        if self.p1 & 0b11000000 == 0b00000000:
            return "AAC"
        if self.p1 & 0b11000000 == 0b01000000:
            return "TC"
        if self.p1 & 0b11000000 == 0b10000000:
            return "ARQC"
        if self.p1 & 0b11000000 == 0b11000000:
            return "RFU"
        return ""

# ------------------------------------------------------- #

class GetProcessingOptions(Request):
    name = "Get Processing Options"
    cla  = 0x80
    ins  = 0xA8

    # TODO
    """
    def __init__(self, name=None, select_type=4):
        super(Select, self).__init__()
        if name is not None:
            self.data = bytearray.fromhex(name)
        self.p1 = select_type
    """

# ------------------------------------------------------- #

class PINChange(Request):
    name = "PIN Change/Unblock"
    cla  = 0x00
    ins  = 0x44

# ------------------------------------------------------- #
