from abc import ABC, abstractmethod
from typing import Any, List, Dict


class AbstractTarget(ABC):
    @abstractmethod
    def setup(self):
        pass

    @abstractmethod
    def execute(self, input: Dict) -> Any:
        pass

    @abstractmethod
    def teardown(self):
        pass


class AbstractSeed(ABC):
    @abstractmethod
    def __init__(self, queue: List[Dict]):
        pass

    @abstractmethod
    def chooseNext(self) -> Dict:
        pass


class AbstractPowerSchedule(ABC):
    @abstractmethod
    def assignEnergy(self) -> int:
        pass


class AbstractMutator(ABC):
    @abstractmethod
    def mutateInput(self, input: Dict) -> Dict:
        pass


class AbstractIsInteresting(ABC):
    @abstractmethod
    def __call__(self, input: Dict, output: Any) -> bool:
        pass


class AbstractGreyboxFuzzer(ABC):
    @abstractmethod
    def __init__(
        self,
        seed: AbstractSeed,
        power_schedule: AbstractPowerSchedule,
        mutator: AbstractMutator,
        is_interesting: AbstractIsInteresting,
        target: AbstractTarget,
    ):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def log_results(self, input: Dict, output: Any, is_interesting: bool):
        pass

    @abstractmethod
    def visualize_results(self):
        pass


class AbstractGrammarParser(ABC):
    @abstractmethod
    def parse(self, definition: str) -> Any:
        """Parses a grammar definition file (JSON/YAML) and returns a structured format."""
        pass

    @abstractmethod
    def generate_input(self) -> Any:
        """Generates a valid input sample from the grammar."""
        pass

    @abstractmethod
    def mutate_input(self, input_data: Any) -> Any:
        """Applies fuzzing mutations while maintaining constraints."""
        pass
