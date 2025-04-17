





import copy
import random
from bitstring import BitArray
from fuzzer.abstract import AbstractMutator


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
            self.mutateRandomBytes,
            self.deleteRandomBytes,
            self.insertRandomBytes
        ]
        mutation_operator = random.choice(fs)
        return mutation_operator(copy_of_input)
        

if __name__ == '__main__':
    input = [1, 2, 3, 4, 5, 6]
    for i in range(10):
        print(ByteArrayMutator().mutateInput(input))