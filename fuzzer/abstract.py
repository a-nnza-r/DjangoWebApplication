from abc import ABC, abstractmethod
from typing import Any


class AbstractSeed(ABC):
    @abstractmethod
    def __init__(self, queue: list):
        pass

    @abstractmethod
    def chooseNext(self):
        pass


class AbstractPowerSchedule(ABC):
    @abstractmethod
    def assignEnergy(self) -> int:
        pass


class AbstractMutator(ABC):
    @abstractmethod
    def mutateInput(self, input):
        pass


class AbstractIsInteresting(ABC):
    @abstractmethod
    def __call__(self, *args, **kwds) -> bool:
        pass


class AbstractGreyboxFuzzer(ABC):
    @abstractmethod
    def __init__(
        self,
        seed: AbstractSeed,
        power_schedule: AbstractPowerSchedule,
        mutator: AbstractMutator,
        is_interesting: AbstractIsInteresting,
        program: Any,
    ):
        pass

    @abstractmethod
    def run(self):
        pass
