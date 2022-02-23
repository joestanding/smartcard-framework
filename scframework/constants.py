# --------------------------------------------------------------------------------------------------- #
# Constants                                                                                           #
# --------------------------------------------------------------------------------------------------- #

class SmartCardConstants:

    APPLICATION_IDS = {
        '315041592E5359532E4444463031': 'VISA Payment System Environment (1PAY.SYS.DDF01)',
        '325041592E5359532E4444463031': 'VISA Proximity Payment System Environment (2PAY.SYS.DDF01)',
        'A00000000305076010': 'VISA ELO Credit',
        'A0000000031010': 'VISA Debit/Credit (Classic)',
        'A000000003101001': 'VISA Credit',
        'A000000003101002': 'VISA Debit',
        'A0000000032010': 'VISA Electron',
        'A0000000032020': 'VISA V PAY',
        'A0000000033010': 'VISA Interlink',
        'A0000000034010': 'VISA Specific',
        'A0000000035010': 'VISA Specific',
        'A0000000040000': 'MasterCard Card Manager/Security Domain',
        'A00000000401': 'MasterCard PayPass',
        'A0000000041010': 'MasterCard Credit/Debit',
        'A00000000410101213': 'MasterCard Credit',
        'A00000000410101215': 'MasterCard Credit',
        'A0000000043060': 'Maestro Debit',
        'A000000004306001': 'Maestro Debit',
        'A0000001523010': 'Discover Card',
        'F1234567890123': 'JCB Test',
        'A000000333010101': 'China UnionPay Debit',
        'A000000333010102': 'China UnionPay Credit',
        'A000000333010103': 'China UnionPay Quasi Credit',
        'A000000003000000': 'GlobalPlatform Card Manager/Card Issuer Security Domain',
        'A000000151000000': 'GlobalPlatform Card Manager/Security Domain',
        '44464D46412E44466172653234313031': 'DeviceFidelity In2Pay DFare Applet',
        'A00000000300037561': 'VISA Bonus Card',
        'A00000000305076010': 'VISA ELO Credit',
        'A0000000036010': 'VISA Domestic Visa Cash Stored Value',
        'A0000000036020': 'VISA International Visa Cash Stored Value',
        'A0000000038002': 'VISA Auth Dynamic Passcode Authentication',
        'A0000000038010': 'VISA Plus',
        'A0000000039010': 'VISA Loyalty',
        'A000000003999910': 'VISA Proprietary ATM',
        'A0000000042010': 'MasterCard Specific',
        'A0000000042203': 'MasterCard U.S. Maestro',
        'A0000000043010': 'MasterCard Specific',
        'A0000000044010': 'MasterCard Specific',
        'A0000000045010': 'MasterCard Specific',
        'A0000000045555': 'MasterCard Cirrus Test Card APDU Logger',
        'A0000000046000': 'MasterCard Cirrus ATM Card',
        'A0000000048002': 'MasterCard Chip Authentication Protocol (CAP)',
        'A0000000050001': 'Maestro UK Domestic Debit',
        'A0000000050002': 'Maestro UK Domestic Debit (Solo)',
        'A0000000090001FF44FF1289': 'Orange UK (SIM Card?)',
        'A0000000101030': 'Maestro CH',
        'A000000018434D': 'GemPlus Card Manager',
        'A000000018434D00': 'GemPlus Security Domain',
        'A00000002401': 'Midland Bank Self Service',
        'A000000025': 'American Express',
        'A0000000250000': 'American Express (Credit/Debit)',
        'A00000002501': 'American Express AEIPS-compliant Payment Application',
        'A000000025010104': 'American Express',
        'A000000025010402': 'American Express',
        'A000000025010701': 'American Express ExpressPay',
        'A000000025010801': 'American Express',
        'A0000000291010': 'LINK Interchange American Express',
        'A00000002945087510100000': 'LINK Interchange Co-Op Bank',
        'A00000002949034010100001': 'LINK Interchange HSBC',
        'A00000002949282010100000': 'LINK Interchange Barclays',
        'A000000029564182': 'LINK Interchange HAFX',
        'A00000003029057000AD13100101FF': 'Belgian Personal Identity Card',
        'A0000000308000000000280101': 'Gemalto .NET Card',
        'A00000005945430100': 'Girocard Electrnic Cash',
        'A000000063504B43532D3135': 'RSA PKCS-15 PKI Application / ID Card in Finland',
        'A0000000635741502D57494D': 'WAP-WIM (Wireless Application Protocol / Wireless Identification Module)',
        'A00000006510': 'Japan Credit Bureau (JCB)',
        'A0000000651010': 'Japan Credit Bureau (JCB) Smart Credit',
        'A0000000790100': 'DoD CACv2 PKI ID',
        'A0000000790101': 'DoD CACv2 PKI Sign',
        'A0000000790102': 'DoD CACv2 PKI Encrypt',
        'A00000007901F0': 'DoD CACv1 PKI Identity Key',
        'A00000007901F1': 'DoD CACv1 PKI Digital Signature Key',
        'A00000007901F2': 'DoD CACv1 PKI Key Management Key',
        'A0000000790200': 'DoD CACv2 DoD Person',
        'A0000000790201': 'DoD CACv2 DoD Personnel'
    }

    TLV_TAGS = {
        '9F0A': {
            'name': 'Application Selection Registered Proprietary Data',
            'format': 'binary',
            'length': [0, 255]
        },
        '9F01': {
            'name': 'Acquirer Identifier',
            'format': 'binary',
            'length': [6, 6]
        },
        '9F02': {
            'name': 'Amount, Authorised (Numeric)',
            'format': 'binary',
            'length': [6, 6]
        },
        '9F03': {
            'name': 'Amount, Other (Numeric)',
            'format': 'binary',
            'length': [6, 6]
        },
        '9F04': {
            'name': 'Amount, Other (Binary)',
            'format': 'binary',
            'length': [4, 4]
        },
        '9F05': {
            'name': 'Application Discretionary Data',
            'format': 'binary',
            'length': [1, 32]
        },
        '9F06': {
            'name': 'Application Identifier (AID) - terminal',
            'format': 'binary',
            'length': [5, 16]
        },
        '9F07': {
            'name': 'Application Usage Control',
            'format': 'binary',
            'length': [2, 2]
        },
        '9F08': {
            'name': 'Application Version Number',
            'format': 'binary',
            'length': [2, 2]
        },
        '9F09': {
            'name': 'Application Version Number',
            'format': 'binary',
            'length': [2, 2]
        },
        '9F0B': {
            'name': 'Cardholder Name Extended',
            'format': 'alphanumeric_special',
            'length': [27, 45]
        },
        'BF0C': {
            'name': 'FCI Issuer Discretionary Data',
            'format': 'variable',
            'length': [0, 222]
        },
        '9F0D': {
            'name': 'Issuer Action Code - Default',
            'format': 'binary',
            'length': [5, 5]
        },
        '9F0E': {
            'name': 'Issuer Action Code - Denial',
            'format': 'binary',
            'length': [5, 5]
        },
        '9F0F': {
            'name': 'Issuer Action Code - Online',
            'format': 'binary',
            'length': [5, 5]
        },
        '9F10': {
            'name': 'Issuer Application Data',
            'format': 'binary',
            'length': [0, 32]
        },
        '9F11': {
            'name': 'Issuer Code Table Index',
            'format': 'numeric',
            'length': [1, 1]
        },
        '9F12': { 
            'name': 'Application Preferred Name',
            'format': 'alphanumeric_special',
            'length': [1, 16]
        },
        '9F13': 'Last Online Application Transaction Counter (ATC) Register',
        '9F14': 'Lower Consecutive Offline Limit',
        '9F15': 'Merchant Category Code',
        '9F16': 'Merchant Identifier',
        '9F17': 'Personal Identification Number (PIN) Try Counter',
        '9F18': 'Issuer Script Identifier',
        '9F1A': 'Terminal Country Code',
        '9F1B': 'Terminal Floor Limit',
        '9F1C': 'Terminal Identification',
        '9F1D': 'Terminal Risk Management Data',
        '9F1E': 'Interface Device (IFD) Serial Number',
        '9F1F': 'Track 1 Discretionary Data',
        '5F20': {
            'name': 'Cardholder Name',
            'format': 'alphanumeric_special',
            'sizes': [2, 26]
        },
        '9F21': 'Transaction Time',
        '9F22': 'Certification Authority Public Key Index',
        '9F23': 'Upper Consecutive Offline Limit',
        '5F24': 'Application Expiration Date',
        '5F25': 'Application Effective Date',
        '9F26': 'Application Cryptogram',
        '9F27': 'Cryptogram Information Data',
        '5F28': 'Issuer Country Code',
        '5F2A': 'Transaction Currency Code',
        '5F2D': {
                'name': 'Language Preference',
                'format': 'alphanumeric'
        },
        '9F2E': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent',
        '9F2F': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder',
        '5F30': 'Service Code',
        '9F32': 'Issuer Public Key Exponent',
        '9F33': 'Terminal Capabilities',
        '5F34': 'Application Primary Account Number (PAN)',
        '9F35': 'Terminal Type',
        '5F36': 'Transaction Currency Exponent',
        '9F37': 'Unpredictable Number',
        '9F38': 'Processing Options Data Object List (PDOL)',
        '9F34': 'Cardholder Verification Method (CVM) Results',
        '9F3A': 'Amount, Reference Currency',
        '9F3B': 'Application Reference Currency',
        '9F3C': 'Transaction Reference Currency Code',
        '9F3D': 'Transaction Reference Currency Exponent',
        '9F40': 'Additional Terminal Capabilities',
        '9F41': 'Transaction Sequence Counter',
        '42': 'Issuer Identification Number (IIN)',
        '9F43': 'Application Reference Currency Exponent',
        '9F44': 'Application Currency Exponent',
        '9F2D': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate',
        '9F46': 'Integrated Circuit Card (ICC) Public Key Certificate',
        '9F47': 'Integrated Circuit Card (ICC) Public Key Exponent',
        '9F48': 'Integrated Circuit Card (ICC) Public Key Remainder',
        '9F49': 'Dynamic Data Authentication Data Object List (DDOL)',
        '9F4A': 'Static Data Authentication Tag List',
        '9F4B': 'Signed Dynamic Application Data',
        '9F4C': 'ICC Dynamic Number',
        '9F4D': 'Log Entry',
        '9F4E': {
            'name': 'Merchant Name and Location',
            'format': 'alphanumeric_special'
        },
        '4F': {
            'name': 'Application Identifier (AID)',
            'format': 'binary'
        },
        '50': {
                'name': 'Application Label',
                'format': 'alphanumeric_special',
                'length': [1, 16]
        },
        '9F51': 'Application Currency Code',
        '9F52': 'Card Verification Results (CVR)',
        '5F53': 'International Bank Account Number (IBAN)',
        '5F54': 'Bank Identifier Code (BIC)',
        '5F55': 'Issuer Country Code (alpha2 format)',
        '5F56': 'Issuer Country Code (alpha3 format)',
        '57': 'Track 2 Equivalent Data',
        '9F58': 'Lower Consecutive Offline Limit (Card Check)',
        '9F59': 'Upper Consecutive Offline Limit (Card Check)',
        '5A': 'Application Primary Account Number (PAN)',
        '9F5C': 'Cumulative Total Transaction Amount Upper Limit',
        '9F72': 'Consecutive Transaction Limit (International - Country)',
        '61': 'Application Template',
        '9F62': 'Track 1 Bit Map for CVC3',
        '9F63': 'Track 1 Bit Map for UN and ATC',
        '9F64': 'Track 1 Number of ATC Digits',
        '9F65': 'Track 2 Bit Map for CVC3',
        '9F66': 'Track 2 Bit Map for UN and ATC',
        '9F68': 'Mag Stripe CVM List',
        '9F69': 'Unpredictable Number Data Object List (UDOL)',
        '9F6B': 'Track 2 Data',
        '9F6C': 'Mag Stripe Application Version Number (Card)',
        '9F6E': 'Unknown Tag',
        '6F': 'File Control Information (FCI) Template',
        '70': 'EMV Proprietary Template',
        '71': 'Issuer Script Template 1',
        '72': 'Issuer Script Template 2',
        '73': 'Directory Discretionary Template',
        '9F74': 'VLP Issuer Authorization Code',
        '9F75': 'Cumulative Total Transaction Amount Limit - Dual Currency',
        '9F76': 'Secondary Application Currency Code',
        '77': 'Response Message Template Format 2',
        '9F7D': 'Unknown Tag',
        '9F7F': 'Card Production Life Cycle (CPLC) History File Identifiers',
        '80': 'Response Message Template Format 1',
        '81': 'Amount, Authorised (Binary)',
        '82': 'Application Interchange Profile',
        '83': 'Command Template',
        '84': {
            'name': 'Dedicated File (DF) Name',
            'format': 'binary',
            'length': [5, 16]
        },
        '86': 'Issuer Script Command',
        '87': 'Application Priority Indicator',
        '88': 'Short File Identifier (SFI)',
        '89': 'Authorisation Code',
        '8A': 'Authorisation Response Code',
        '8C': 'Card Risk Management Data Object List 1 (CDOL1)',
        '8D': 'Card Risk Management Data Object List 2 (CDOL2)',
        '8E': 'Cardholder Verification Method (CVM) List',
        '8F': 'Certification Authority Public Key Index',
        '90': 'Issuer Public Key Certificate',
        '91': 'Issuer Authentication Data',
        '92': 'Issuer Public Key Remainder',
        '93': 'Signed Static Application Data',
        '94': 'Application File Locator (AFL)',
        '95': 'Terminal Verification Results',
        '97': 'Transaction Certificate Data Object List (TDOL)',
        '98': 'Transaction Certificate (TC) Hash Value',
        '99': 'Transaction Personal Identification Number (PIN) Data',
        '9A': 'Transaction Date',
        '9B': 'Transaction Status Information',
        '9C': 'Transaction Type',
        '9D': 'Directory Definition File (DDF) Name',
        '9F45': 'Data Authentication Code',
        'A5': 'File Control Information (FCI) Proprietary Template',
        '9F57': 'Issuer Country Code',
        '9F39': 'Point-of-Service (POS) Entry Mode',
        '9F73': 'Currency Conversion Factor',
        '9F42': 'Application Currency Code',
        '9F56': 'Issuer Authentication Indicator',
        '9F20': 'Track 2 Discretionary Data',
        'DF01': 'Reference PIN',
        '9F36': 'Application Transaction Counter (ATC)',
        '9F4F': 'Log Format',
        '5F50': {
            'name': 'Issuer URL',
            'format': 'string'
        },
        '9F5A': 'Issuer URL2',
        '9F53': 'Consecutive Transaction Limit (International)',
        '9F54': 'Cumulative Total Transaction Amount Limit',
        '9F55': 'Geographic Indicator',
        'ED': 'Miura - Configuration Information',
        'E1': 'Miura - Generic Template',
        'DF0D': {
            'name': 'Miura - Identifier',
            'format': 'alphanumeric'
        },
        'DF7F': {
            'name': 'Miura - Data',
            'format': 'alphanumeric'
        }
    }
