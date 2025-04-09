

import asyncio
import logging
import re
import sys
from smartlock.BLEClient import BLEClient
from smartlock.constants import AUTH, COMMAND_CODES, DEVICE_NAME, PASSCODE, STATE_CODES


def extract_transitions(log_lines, initial_state=0):
    current_state = initial_state
    transitions = []

    command_code = None
    for line in log_lines:
        cmd_match = re.search(r"Received command: 0x(\d+)", line)
        if cmd_match:
            cmd = int(cmd_match.group(1))
            command_code = COMMAND_CODES.get(cmd, None)

        state_match = re.search(r"\[State\].*Device state: (\w+)", line)
        if state_match:
            state_str = state_match.group(1)
            next_state = STATE_CODES.get(state_str, None)
            if command_code is not None and next_state is not None:
                transitions.append({
                    "from": current_state,
                    "command": command_code,
                    "to": next_state
                })
                current_state = next_state
                command_code = None  # reset command

    return transitions

async def connect_client_to_smartlock(ble) -> None:
    logging.info(f'[1] Connecting to "{DEVICE_NAME}"...')
    print(f'\n[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    logging.info("[2] Authenticating...")
    print("\n[2] Authenticating...")
    await asyncio.sleep(0.5)

    res = await ble.write_command(AUTH+PASSCODE)
    logging.info(f"Sent AUTH+PASSCODE: {AUTH+PASSCODE}")
    logging.info(f"Received response: {res}")

    if res[0] != 0:
        logging.error("[X] Failure: Wrong Passcode.")
        print(f"[X] Failure: Wrong Passcode.")
        await ble.disconnect()
        return False

    logging.info("[!] Authenticated!!!")
    print("[!] Authenticated!!!")
    await asyncio.sleep(4)

async def ble_program(x: list[int], ble: BLEClient) -> tuple:
    logging.info("-" * 60)
    logging.info(f"\n[>] Sending command: {x}")
    print("\n[3] Running random command")

    res = await ble.write_command(x)
    logging.info(f"[<] Received response: {res}")
    await asyncio.sleep(1)

    # print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")
    lines = ble.read_logs()

    current_state = []
    if lines:
        for line in lines:
            if line.startswith("[State]"):
                logging.info(line)
                current_state.append(line)

        transitions = extract_transitions(lines)
        logging.info(transitions)
    else:
        logging.info("No logs received from device.")

    sys.stdout.flush()
    return tuple(current_state)
