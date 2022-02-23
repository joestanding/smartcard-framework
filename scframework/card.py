from colorama import Fore, Style
from smartcard.CardType import AnyCardType                                                                                                          
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.Exceptions import CardRequestTimeoutException
from .utilities import StringUtils

def coloured(message, colour):
    return colour + message + Style.RESET_ALL

class Card:
    def connect(self):
        card_request = CardRequest(timeout=10, cardType=AnyCardType())
        self.service = card_request.waitforcard()
        self.service.connection.connect()

    def send_apdu(self, apdu, auto_send_get_response=True):
        try:
            byte_string = bytes.fromhex(apdu.strip())
        except ValueError as err:
            return (None, None, None)
        byte_array = []
        for b in byte_string:
            byte_array.append(b)
        response, sw1, sw2 = self.service.connection.transmit(byte_array)

        if sw1 == 0x61 and auto_send_get_response:
            byte_string = bytes.fromhex("00c00000" + StringUtils.byte_to_hex(sw2))
            byte_array = []
            for b in byte_string:
                byte_array.append(b)
            response, sw1, sw2 = self.service.connection.transmit(byte_array)

        data = ""
        for b in response:
            #data += format(b, ':02x')
            data += f"{b:02x}"
        
        if data is '':
            data = "-"

        return (data, sw1, sw2)


