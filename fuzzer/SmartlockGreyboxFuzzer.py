from collections import deque
import random
import sys
from fuzzer.abstract import AbstractGreyboxFuzzer, AbstractIsInteresting, AbstractMutator, AbstractPowerSchedule, AbstractSeed
from smartlock.BLEClient import BLEClient
from fuzzer.mutation.common_mutator import ByteArrayMutator
import asyncio  # Ensure async operations work


class Seed(AbstractSeed):
    def __init__(self, queue: list):
        self.queue = deque(queue)

    def chooseNext(self):
        return self.queue.popleft()

class PowerSchedule(AbstractPowerSchedule):
    def assignEnergy(self):
        return 5

class IsInteresting(AbstractIsInteresting):
    def __call__(self, *args, **kwds) -> bool:
        return random.choices([True, False], weights=[0.5, 0.5], k=1)[0]

class GreyboxFuzzer(AbstractGreyboxFuzzer):
    def __init__(self, seed: AbstractSeed, power_schedule: AbstractPowerSchedule, mutator: AbstractMutator, is_interesting: IsInteresting, program):
        self.seed = seed
        self.power_schedule = power_schedule
        self.mutator = mutator
        self.is_interesting = is_interesting
        self.program = program
        self.bugs = []  # failure queue

    async def check_program_for_bugs(self, input) -> bool:
        try:
            await self.program(input)  # Ensure the program function is awaited
        except Exception as error:
            self.bugs.append((input, error))
            print(self.bugs)
            return True

        return random.choices([True, False], weights=[0.5, 0.5], k=1)[0]

    async def run(self):
        while len(self.seed.queue) > 0:
            t = self.seed.chooseNext()
            e = self.power_schedule.assignEnergy()

            for i in range(1, e + 1):
                t_prime = self.mutator.mutateInput(t)
                sys.stdout.flush()  # Ensure immediate output

                if await self.check_program_for_bugs(t_prime):
                    continue

                if self.is_interesting(t_prime):
                    self.seed.queue.append(t_prime)


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