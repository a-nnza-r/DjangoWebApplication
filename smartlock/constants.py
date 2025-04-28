
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

STATE_LABEL_CODES = {
    "[State] Device state: Locked": 0,
    "[State] Device state: Authenticating": 1,
    "[State] Device state: Authenticated": 2,
    "[State] Opening the lock mechanism": 3,
    "[State] Lock mechanism open": 4,
    "[State] Closing the lock mechanism": 5,
    "[State] Lock mechanism closed": 6,
}

LEGAL_STATE_TRANSITIONS = { # referring to the state diagram in README.pdf and [State] log patterns
    0: [1],    # Locked → Authenticating
    1: [2, 6], # Authenticating → Authenticated, or → Locked
    2: [5, 3], # Authenticated → Opening, or → Closing
    3: [4],    # Opening → Unlocked
    4: [5, 4], # Unlocked → Closing, or → Unlocked
    5: [6],    # Closing → Closed
    6: [0],    # Closed → Locked
}

COMMAND_CODES = {
    0x00: "Authenticate",
    0x01: "Open",
    0x02: "Close"
}

VALID_COMMANDS = [AUTH, OPEN, CLOSE, PASSCODE]

# Generate a list of all 256 possible 1-byte values: [0x00, 0x01, ..., 0xFF]
UNKNOWN_COMMANDS = [[i] for i in range(256) if i not in VALID_COMMANDS]

WEIGHTED_UNKNOWN_COMMANDS = [
    0x03, 0x04, 0x05,  # near known commands
    0x10, 0x20, 0x30,  # arbitrary intervals
    0x41, 0x44, 0x54,  # ASCII letters like A, D, T
    0x7F, 0x80, 0xF0,  # suspicious values
    0xFE, 0xFF          # boundary bytes
]
