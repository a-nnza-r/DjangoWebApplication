from collections import deque
import random
import sys

class Seed:
    def __init__(self, queue: list):
        self.queue = deque(queue)

    def chooseNext(self):
        return self.queue.popleft()

class PowerSchedule:
    def assignEnergy(self):
        return 5

class Mutator:
    def mutateInput(self, input_str: str) -> str:
        input_list = list(input_str)
        index = random.randint(0, len(input_list) - 1)
        input_list[index] = chr(random.randint(32, 126))  # Replace with a random printable ASCII character
        return ''.join(input_list)

class IsInteresting():
    def __call__(self, *args, **kwds) -> bool:
        return random.choices([True, False], weights=[0.5, 0.5], k=1)[0]

class GreyboxFuzzer:
    def __init__(self, seed: Seed, power_schedule: PowerSchedule, mutator: Mutator, is_interesting: IsInteresting, program):
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


# def main():
#     def program(x):
#         if x[0] == "b":
#             if x[1] == "a":
#                 if x[2] == "d":
#                     if x[3] == "!":
#                         raise Exception("bug found")
                        
                        
                    
#     seed = Seed(queue=["aaaa", "bbbb", "cccc"])
#     power_schedule = PowerSchedule()
#     mutator = Mutator()
#     is_interesting = IsInteresting()

#     fuzzer = GreyboxFuzzer(seed, power_schedule, mutator, is_interesting, program)
#     fuzzer.run()

# if __name__ == "__main__":
#     main()
