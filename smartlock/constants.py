
DEVICE_NAME = "Smart Lock [Group 10]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE


STATE_CODES = {
    "Locked": 0,
    "Authenticating": 1,
    "Authenticated": 2,
    "Opening": 3,
    "Unlocked": 4,
    "Closing": 5
}

COMMAND_CODES = {
    0x00: "Authenticate",
    0x01: "Open",
    0x02: "Close"
}

VALID_COMMANDS = [AUTH, OPEN, CLOSE, PASSCODE]

# Generate a list of all 256 possible 1-byte values: [0x00, 0x01, ..., 0xFF]
UNKNOWN_COMMANDS = [[i] for i in range(256) if i not in VALID_COMMANDS]
