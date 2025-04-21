from collections import deque
import random
import sys
import traceback
from fuzzer.abstract import AbstractGreyboxFuzzer, AbstractIsInteresting, AbstractMutator, AbstractPowerSchedule, AbstractSeed
from fuzzer.utilities.smartlock import ble_program, connect_client_to_smartlock, extract_transitions_as_integers
from smartlock.BLEClient import BLEClient
from smartlock.constants import LEGAL_STATE_TRANSITIONS
from fuzzer.mutation.common_mutator import ByteArrayMutator
import asyncio  # Ensure async operations work
import logging

from smartlock.constants import AUTH, CLOSE, DEVICE_NAME, OPEN, PASSCODE

logging.basicConfig(
    filename='smartlock.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w',  # overwrites on every run
)


class Input():
    def __init__(self, value: list[int], path_state: tuple = ()):
        self.value: list[int] = value
        self.path_state: int = path_state

class Path:
    def __init__(self, state):
        self.state: tuple = state
        self.f: int = 1
        self.s: int = 0
        self.e: int = PowerSchedule.e0

    def update(self):
        self.s = self.s + 1
        self.f = self.f + self.e

class Paths: # sort of like a graph
    def __init__(self):
        self.paths = {}

    def append_if_not_exist(self, state: tuple):
        if state not in self.paths:
            self.paths[state] = Path(state)

    def get_path(self, state: tuple) -> Path:
        return self.paths[state]

    def get_mean_f(self) -> int:
        return int(sum([path.f for path in self.paths.values()]) / len(self.paths))
    
    def __str__(self):
        s = f'\n[Paths] {len(self.paths)} discovered.'
        s += ''.join([f" (Path={state}) s={path.s}, f={path.f}." for (state, path) in sorted(self.paths.items())])
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
        path = self.paths.get_path(t.path_state)
        path.update()
        if path.f <= self.paths.get_mean_f():
            path.e = min(int(PowerSchedule.e0 * (2 ** path.s)), PowerSchedule.M)
        else:
            path.e = 0
        return path.e

class IsInteresting(AbstractIsInteresting):
    def __init__(self):
        self.seen_path_states = set()
        self.seen_errors = set()
        self.illegal_transitions = set()

    def __call__(self, input: Input) -> bool:
        # Check for new path discovery
        is_new_path = input.path_state not in self.seen_path_states
        if is_new_path:
            self.seen_path_states.add(input.path_state)
            logging.info(f"Is interesting: New path discovered: {input.path_state}")
            return True

        # Check for error discovery (from logs)
        logs = input.path_state
        for log in logs:
            if "[Error]" in log:
                if log not in self.seen_errors:
                    self.seen_errors.add(log)
                    logging.info(f"Is interesting: New error discovered: {log}")
                    return False  # might not want to keep exploring the same error
                
        # Check for illegal state transitions
        transitions = extract_transitions_as_integers(input.path_state)
        for (src, dst) in transitions:
            allowed = LEGAL_STATE_TRANSITIONS.get(src, [])
            if dst not in allowed:
                print(f"Illegal state transition: {src} -> {dst} not allowed. Allowed: {src} -> {allowed}")
                logging.info(f"Illegal state transition: {src} -> {dst} not allowed. Allowed: {src} -> {allowed}")
                return True

        return False

class GreyboxFuzzer(AbstractGreyboxFuzzer):
    def __init__(self, seed: AbstractSeed, power_schedule: AbstractPowerSchedule, mutator: AbstractMutator, is_interesting: IsInteresting, program):
        self.seed = seed
        self.power_schedule = power_schedule
        self.mutator = mutator
        self.is_interesting = is_interesting
        self.program = program
        self.bugs = []  # failure queue
        self.paths = set()

    async def check_program_for_bugs(self, input) -> tuple[bool, int]:
        try:
            path_state = await self.program(input)  # Ensure the program function is awaited
            return (False, path_state)
        except Exception as error:
            self.bugs.append((input, error))
            print(self.bugs)
            return (True, -1)

    async def run(self):
        while len(self.seed.queue) > 0:
            t: Input = self.seed.chooseNext()
            
            self.power_schedule.paths.append_if_not_exist(t.path_state)
            sys.stdout.flush()
            print(self.power_schedule.paths)
            logging.info(self.power_schedule.paths)
            sys.stdout.flush()

            e = self.power_schedule.assignEnergy(t)

            for i in range(1, e + 1):
                mutated_value = self.mutator.mutateInput(t.value)

                is_buggy, path_state = await self.check_program_for_bugs(mutated_value)
                if is_buggy:
                    continue
                sys.stdout.flush()

                t_prime = Input(value=mutated_value, path_state=path_state)

                if self.is_interesting(t_prime):
                    self.seed.queue.append(t_prime)

async def run_fuzzer():
    try:
        initial_inputs = [Input(OPEN), Input(CLOSE)]
        seed = Seed(queue=initial_inputs)
        power_schedule = PowerSchedule()
        mutator = ByteArrayMutator()
        is_interesting = IsInteresting()

        fuzzer = GreyboxFuzzer(seed, power_schedule, mutator, is_interesting, None)

        while True:
            try:
                ble = BLEClient()
                ble.init_logs()
                await connect_client_to_smartlock(ble)

                async def ble_program(x: list[int]) -> tuple:
                    logging.info("-" * 60)
                    logging.info(f"\n[>] Sending command: {x}")
                    print("\n[3] Running random command")

                    res = await ble.write_command(x)
                    logging.info(f"[<] Received response: {res}")
                    await asyncio.sleep(2)

                    # print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")
                    lines = ble.read_logs()

                    current_state = []
                    if lines:
                        for line in lines:
                            if line.startswith("[State]"):
                                logging.info(line)
                                current_state.append(line)

                        transitions = extract_transitions_as_integers(lines)
                        logging.info(f"State transitions: {transitions}")
                    else:
                        logging.info("No logs received from device.")

                    sys.stdout.flush()
                    return tuple(current_state)


                try:
                    initial_inputs = [Input(OPEN), Input(CLOSE)]
                    seed = Seed(queue=initial_inputs)
                    power_schedule = PowerSchedule()
                    mutator = ByteArrayMutator()
                    is_interesting = IsInteresting()
                    fuzzer = GreyboxFuzzer(seed, power_schedule, mutator, is_interesting, ble_program)
                    await fuzzer.run()
                except Exception as ex:
                    print("\nProgram cannot be run. Exception:", ex)
                    print(traceback.format_exc())
                finally:
                    await ble.disconnect()

                error_codes = list(set(
                    line for line in ble.read_logs() if line.startswith("[Error]")
                ))
                print(error_codes)
                logging.info(error_codes)

            except Exception as ex:
                print("\nClient cannot be connected. Exception:", ex)
                await ble.disconnect()
                print(traceback.format_exc())
                print("Re-running program in a few seconds.")
            finally:
                await ble.disconnect()

    except KeyboardInterrupt:
        print("Stopping fuzzer.")

if __name__ == "__main__":
    asyncio.run(run_fuzzer()) 