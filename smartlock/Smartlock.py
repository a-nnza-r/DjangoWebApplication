#!/usr/bin/env python3
import sys
import asyncio
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

DEVICE_NAME = "Smart Lock [Group 4]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE

async def example_control_smartlock():
    # Use this code as template to create your fuzzer
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    print("\n[2] Authenticating...")
    res = await ble.write_command(AUTH + PASSCODE)
    if res[0] != 0:
        print(f"[X] Failure: Wrong Passcode.")
        await ble.disconnect()
        return

    print("[!] Authenticated!!!")
    await asyncio.sleep(2)

    print("\n[3] Opening")
    res = await ble.write_command(OPEN)
    await asyncio.sleep(2)

    print("\n[4] Closing")
    res = await ble.write_command(CLOSE)
    await asyncio.sleep(2)

    print("\n[5] Disconnecting...")
    await ble.disconnect()

    print(f"\n[6] Logs from Smart Lock (Serial Port):\n{'-'*50}")
    lines = ble.read_logs()  # Return a list of all log lines.
    for line in lines:
        print(line)
    # TIP: Use lines[-1] to get the most recent line

    sys.exit(0)


# Show User interface if command line contains --gui
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    # Ortherwise, run this example
    try:
        asyncio.run(example_control_smartlock())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
