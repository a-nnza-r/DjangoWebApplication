from collections import deque
import random
import sys
from fuzzer.abstract import AbstractGreyboxFuzzer, AbstractIsInteresting, AbstractMutator, AbstractPowerSchedule, AbstractSeed
from smartlock.BLEClient import BLEClient
from fuzzer.mutation.common_mutator import ByteArrayMutator
import asyncio  # Ensure async operations work
import logging
import re

logging.basicConfig(
    filename='smartlock.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w',  # overwrites on every run
)

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

class Input():
    def __init__(self, value: list[int], path_id: int = -1):
        self.value: list[int] = value
        self.path_id: int = path_id

class Path:
    def __init__(self, id):
        self.id = id
        self.f: int = 1
        self.s: int = 0
        self.e: int = PowerSchedule.e0

    def update(self):
        self.s = self.s + 1
        self.f = self.f + self.e

class Paths: # sort of like a graph
    def __init__(self):
        self.paths = {}

    def append_if_not_exist(self, id: int):
        if id not in self.paths:
            self.paths[id] = Path(id)

    def get_path(self, id: int) -> Path:
        return self.paths[id]

    def get_mean_f(self) -> int:
        return int(sum([path.f for path in self.paths.values()]) / len(self.paths))
    
    def __str__(self):
        s = f'\n[Paths] {len(self.paths)} discovered.'
        s += ''.join([f" (Path={id}) s={path.s}, f={path.f}." for (id, path) in sorted(self.paths.items())])
        return s


class Seed(AbstractSeed):
    def __init__(self, queue: list):
        self.queue = deque(queue)

    def chooseNext(self) -> Input:
        return self.queue.popleft()

class PowerSchedule(AbstractPowerSchedule):
    e0 = 1
    M = 34000

    def __init__(self):
        self.paths = Paths() # 1 response code = 1 path

    def assignEnergy(self, t: Input = None):
        path = self.paths.get_path(t.path_id)
        path.update()
        if path.f <= self.paths.get_mean_f():
            path.e = min(int(PowerSchedule.e0 * (2 ** path.s)), PowerSchedule.M)
        else:
            path.e = 0
        return path.e

class IsInteresting(AbstractIsInteresting):
    def __call__(self, *args, **kwds) -> bool:
        return True

class GreyboxFuzzer(AbstractGreyboxFuzzer):
    def __init__(self, seed: AbstractSeed, power_schedule: AbstractPowerSchedule, mutator: AbstractMutator, is_interesting: IsInteresting, program):
        self.seed = seed
        self.power_schedule = power_schedule
        self.mutator = mutator
        self.is_interesting = is_interesting
        self.program = program
        self.bugs = []  # failure queue

    async def check_program_for_bugs(self, input) -> tuple[bool, int]:
        try:
            path_id = await self.program(input)  # Ensure the program function is awaited
            return (False, path_id)
        except Exception as error:
            self.bugs.append((input, error))
            print(self.bugs)
            return (True, -1)

        return random.choices([True, False], weights=[0.5, 0.5], k=1)[0]

    async def run(self):
        while len(self.seed.queue) > 0:
            t: Input = self.seed.chooseNext()
            
            self.power_schedule.paths.append_if_not_exist(t.path_id)
            sys.stdout.flush()
            print(self.power_schedule.paths)
            sys.stdout.flush()

            e = self.power_schedule.assignEnergy(t)

            for i in range(1, e + 1):
                mutated_value = self.mutator.mutateInput(t.value)

                is_buggy, path_id = await self.check_program_for_bugs(mutated_value)
                if is_buggy:
                    continue
                sys.stdout.flush()

                t_prime = Input(value=mutated_value, path_id=path_id)

                if self.is_interesting(t_prime):
                    self.seed.queue.append(t_prime)


DEVICE_NAME = "Smart Lock [Group 10]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE

async def run_fuzzer():
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    logging.info(f'[1] Connecting to "{DEVICE_NAME}"...')
    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    logging.info("[2] Authenticating...")
    print("\n[2] Authenticating...")
    await asyncio.sleep(0.5)

    res = await ble.write_command(AUTH+PASSCODE)
    logging.info(f"Sent AUTH+PASSCODE: {AUTH + PASSCODE}")
    logging.info(f"Received response: {res}")

    if res[0] != 0:
        logging.error("[X] Failure: Wrong Passcode.")
        print(f"[X] Failure: Wrong Passcode.")
        await ble.disconnect()
        return
    
    logging.info("[!] Authenticated!!!")
    print("[!] Authenticated!!!")
    await asyncio.sleep(4)

    lines = ble.read_logs()
    if lines:
        logging.info("[Initial BLE Logs]")
        for line in lines:
            logging.info(f"  {line}")

    async def program(x: list[int]) -> int:  # Make program asyncs
        logging.info("-" * 60)
        logging.info(f"\n[>] Sending command: {x}")
        print("\n[3] Running random command")
        # await ble.write_command([1, 2, 3])

        res = await ble.write_command(x)  # Ensure byte array
        logging.info(f"[<] Received response: {res}")
        await asyncio.sleep(2)
        
        print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")
        lines = ble.read_logs()  # Return a list of all log lines.

        if lines:
            for line in lines:
                # logging.info("[Device Logs]")
                if line.startswith("[State]"):
                    logging.info(line)
                
            transitions = extract_transitions(lines)
            logging.info(transitions)

            # for line in lines:
            #     if line.startswith("[Error]"):
            #         logging.warning(f"  {line}")
            #     elif line.startswith("[State]"):
            #         logging.info(f"  {line}")
            #     else:
            #         logging.debug(f"  {line}")  # general logs
        else:
            logging.info("No logs received from device.")

        # Print to console for user feedback
        print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")
        for line in lines:
            print(line)

        sys.stdout.flush()

        response_code = int(res[0])
        return response_code

    initial_inputs = [Input(OPEN), Input(CLOSE), Input(AUTH), Input(PASSCODE)]
    seed = Seed(queue=initial_inputs)
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