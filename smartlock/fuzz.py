from collections import deque
import random
import sys
from BLEClient import BLEClient
from fuzzer.greybox import GreyboxFuzzer, IsInteresting, PowerSchedule, Seed
from fuzzer.mutator import ByteArrayMutator
import asyncio  # Ensure async operations work

print("What's happening")

DEVICE_NAME = "Smart Lock [Group 4]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE

async def run_fuzzer():
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    print("\n[2] Authenticating...")
    await asyncio.sleep(0.5)
    res = await ble.write_command(AUTH+PASSCODE)
    if res[0] != 0:
        print(f"[X] Failure: Wrong Passcode.")
        await ble.disconnect()
        return
    print("[!] Authenticated!!!")
    await asyncio.sleep(2)

    async def program(x: list[int]):  # Make program asyncs
        print("\n[3] Running random command")
        # await ble.write_command([1, 2, 3])
        await ble.write_command(x)  # Ensure byte array
        await asyncio.sleep(0.5)
        
        print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")
        lines = ble.read_logs()  # Return a list of all log lines.
        lines_with_error = [line for line in lines if line.startswith('[Error]')]
        print("Error codes:", lines_with_error)
        sys.stdout.flush()

    seed = Seed(queue=[[6,5,4,3,2,1]])
    power_schedule = PowerSchedule()
    mutator = ByteArrayMutator()
    is_interesting = IsInteresting()

    fuzzer = GreyboxFuzzer(seed, power_schedule, mutator, is_interesting, program)
    await fuzzer.run()
    
    lines = ble.read_logs()  # Return a list of all log lines.
    lines_with_error = [line for line in lines if line.startswith('[Error]')]
    print("All error codes:", lines_with_error)

if __name__ == "__main__":
    while True:
        try:
            asyncio.run(run_fuzzer()) 
        except KeyboardInterrupt:
            break