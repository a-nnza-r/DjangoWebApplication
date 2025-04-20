





import copy
import random
import logging
from bitstring import BitArray
from fuzzer.abstract import AbstractMutator
from smartlock.constants import AUTH, OPEN, CLOSE, PASSCODE, VALID_COMMANDS, UNKNOWN_COMMANDS, WEIGHTED_UNKNOWN_COMMANDS

class ByteMutator():
    @staticmethod
    def _convert_input_to_bitarray(input: int) -> BitArray:
        """Convert integer input to a BitArray."""
        bit_length = input.bit_length()
        return BitArray(uint=input, length=8 if bit_length < 8 else bit_length)

    @staticmethod
    def _convert_bitarray_to_input(arr: BitArray) -> int:
        """Convert BitArray back to an integer."""
        return arr.uint

    @staticmethod
    def _mutate(f: callable, input: int, *args) -> int:
        """Apply a mutation function `f` to the bit array representation of `input`."""
        arr = ByteMutator._convert_input_to_bitarray(input)
        arr = f(arr, *args)
        return ByteMutator._convert_bitarray_to_input(arr)

    @staticmethod
    def _bitflip(arr: BitArray, n: int, stepover: int) -> None:
        """Flip bits at intervals of `stepover` in the first `n` bits of `arr`."""
        idxs_to_invert = range(0, min(n, len(arr)), stepover)
        arr.invert(idxs_to_invert)
        return arr
    
    @staticmethod
    def _setToRandomByte(input: int) -> int:
        return random.randint(0, 255)
    
    @staticmethod
    def _setToInterestingByte(input: int) -> int:
        return random.choice([0, 1, 2, 255])

    @staticmethod
    def mutate(input: int) -> int:
        """Randomly apply a mutation function to `input`."""
        fs = [
            # lambda inp: ByteMutator._mutate(lambda arr: ByteMutator._bitflip(arr, 1, 1), inp),
            # lambda inp: ByteMutator._mutate(lambda arr: ByteMutator._bitflip(arr, 2, 1), inp),
            lambda inp: ByteMutator._mutate(lambda arr: ByteMutator._bitflip(arr, 4, 1), inp),
            ByteMutator._setToRandomByte,
            ByteMutator._setToInterestingByte
        ]
        return random.choice(fs)(input)
    
class ByteArrayMutator(AbstractMutator):
    def __init__(self):
        self.explorer = StateExplorationStrategies()
        self.state_strategies = self.explorer.get_all_strategies()
        self.current_strategy_index = 0  # Track where you are in the list

    def mutateRandomBytes(self, input: list[int]) -> list[int]:
        num_bytes_to_mutate = random.randint(1, len(input))
        idxs_to_mutate = random.choices(list(range(len(input))), k=num_bytes_to_mutate)
        for i in idxs_to_mutate:
            input[i] = ByteMutator.mutate(input[i])
        return input
    
    def deleteRandomBytes(self, input: list[int]) -> list[int]:
        if len(input) == 1:
            return input
        num_to_delete = random.randint(0, len(input) // 2 + 1)
        idxs_to_delete = random.sample(range(len(input)), num_to_delete)  # Select random indices
        return [b for i, b in enumerate(input) if i not in idxs_to_delete]
    
    def insertRandomBytes(self, input: list[int]) -> list[int]:
        num_to_insert = random.randint(1, len(input) * 1)
        for _ in range(num_to_insert):
            random_byte = random.randint(0, 255)  # Generate a random byte (0x00 to 0xFF)
            insert_position = random.randint(0, len(input))  # Choose a random insertion index
            input.insert(insert_position, random_byte)  # Insert the byte at the random position
        return input
    
    def mutateInput(self, input: list[int]) -> list[int]:
        copy_of_input = copy.deepcopy(input)
        fs = [
            # self.mutateRandomBytes,
            # self.deleteRandomBytes,
            # self.insertRandomBytes,
            # self.repeat_valid_command,
            # self.valid_command_out_of_order,
            # self.inject_unknown_command,
            # self.weighted_unknown_command,
            # self.sequence_valid_commands,
            # self.rapid_toggle_open_close,
            self.explore_state_jump,
        ]
        mutation_operator = random.choice(fs)
        mutated = mutation_operator(copy_of_input)

        # Log the mutation strategy
        logging.info(f"[MUTATION] Mutation strategy for next input: {mutation_operator.__name__} | Original: {copy_of_input} | Mutated: {mutated}")
        
        return mutated    
      
    def repeat_valid_command(self, input: list[int]) -> list[int]:
        return random.choice(VALID_COMMANDS) * random.randint(1, 10)

    def valid_command_out_of_order(self, input: list[int]) -> list[int]:
        valid_commands = copy.deepcopy(VALID_COMMANDS)
        random.shuffle(valid_commands)
        return [byte for command in valid_commands for byte in command] # concatenate the arrays
    
    def weighted_unknown_command(self, input: list[int]) -> list[int]:
        weighted_byte = random.choice(WEIGHTED_UNKNOWN_COMMANDS)
        return [weighted_byte] + input

    def inject_unknown_command(self, input: list[int]) -> list[int]:
        return random.choice(UNKNOWN_COMMANDS) + input
    
    def sequence_valid_commands(self, input: list[int]) -> list[int]:
        sequence = [AUTH + PASSCODE, OPEN, AUTH + PASSCODE, CLOSE] * random.randint(1, 10)
        flat = [b for cmd in sequence for b in cmd]
        return flat

    def rapid_toggle_open_close(self, input: list[int]) -> list[int]:
        return [b for _ in range(random.randint(10, 50)) for b in random.choice([OPEN, CLOSE])]
    
    def explore_state_jump(self, input: list[int]) -> list[int]:
        # Get the current strategy
        strategy = self.state_strategies[self.current_strategy_index]
        
        # Increment index, wrap around when reaching the end
        self.current_strategy_index = (self.current_strategy_index + 1) % len(self.state_strategies)
        
        return strategy()
        
class StateExplorationStrategies:
    def __init__(self):
        self.auth = AUTH + PASSCODE
        self.open = OPEN
        self.close = CLOSE
        self.unknown = random.choice(UNKNOWN_COMMANDS)

    def open_without_auth(self):
        """Open without authentication – should trigger 0x03 (Command Not Allowed)"""
        return self._log("open_without_auth", self.open)

    def close_without_auth(self):
        """Close without authentication – should trigger 0x03"""
        return self._log("close_without_auth", self.close)

    def partial_auth(self):
        """Send incomplete AUTH payloads (1-6 bytes instead of 7)"""
        partial = [0x00] + [random.randint(0, 255) for _ in range(random.randint(1, 6))]
        return self._log("partial_auth", partial)

    def spam_auth(self):
        """Send multiple valid AUTHs to check for memory issues or FSM inconsistency"""
        sequence = self.auth * random.randint(5, 10)
        return self._log("spam_auth", sequence)

    def spam_open_without_close(self):
        """Open multiple times without closing – possible edge case or undefined state"""
        sequence = self.auth + self.open * random.randint(3, 10)
        return self._log("spam_open_without_close", sequence)

    def auth_open_unknown_close(self):
        """Inject unknown command between OPEN and CLOSE – may disrupt state"""
        sequence = self.auth + self.open + self.unknown + self.close
        return self._log("auth_open_unknown_close", sequence)

    def repeated_toggle(self):
        """Repeat OPEN and CLOSE to cause race conditions or state inconsistencies"""
        reps = random.randint(5, 20)
        sequence = self.auth + [cmd for _ in range(reps) for cmd in random.choice([self.open, self.close])]
        return self._log("repeated_toggle", sequence)

    def unknown_before_auth(self):
        """Try unknown command before AUTH to test early crash conditions"""
        return self._log("unknown_before_auth", self.unknown + self.auth)

    def garbage_payload(self):
        """Send a long garbage payload (junk bytes) to test buffer handling"""
        garbage = [random.randint(0, 255) for _ in range(1000)]
        return self._log("garbage_payload", garbage)

    def empty_payload(self):
        """Send an empty command – tests whether zero-length input is handled"""
        return self._log("empty_payload", [])

    def invalid_ordering(self):
        """Do OPEN → AUTH → CLOSE → AUTH again to test FSM recovery"""
        sequence = self.open + self.auth + self.close + self.auth
        return self._log("invalid_ordering", sequence)

    def unknown_spam(self):
        """Spam unknown commands – might crash weak command handlers"""
        sequence = self.unknown * random.randint(5, 15)
        return self._log("unknown_spam", sequence)

    def unknown_inside_valid_flow(self):
        """Inject unknown command into a valid AUTH → OPEN → CLOSE flow"""
        sequence = self.auth + self.unknown + self.open + self.unknown + self.close
        return self._log("unknown_inside_valid_flow", sequence)

    def get_all_strategies(self):
        return [
            self.open_without_auth,
            self.close_without_auth,
            self.partial_auth,
            self.spam_auth,
            self.spam_open_without_close,
            self.auth_open_unknown_close,
            self.repeated_toggle,
            self.unknown_before_auth,
            self.garbage_payload,
            self.empty_payload,
            self.invalid_ordering,
            self.unknown_spam,
            self.unknown_inside_valid_flow,
        ]

    def _log(self, strategy_name, sequence):
        logging.info(f"[STATE-EXPLORATION] Strategy: {strategy_name} | Sequence: {sequence}")
        return sequence

if __name__ == '__main__':
    input = [1, 2, 3, 4, 5, 6]
    for i in range(10):
        print(ByteArrayMutator().mutateInput(input))