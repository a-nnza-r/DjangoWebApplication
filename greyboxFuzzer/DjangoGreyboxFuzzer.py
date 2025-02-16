import coverage
import random
import subprocess
import time
import requests
import logging
from collections import deque

from abstract import (
    AbstractIsInteresting,
    AbstractGreyboxFuzzer,
    AbstractMutator,
    AbstractPowerSchedule,
    AbstractSeed,
)

# Setup logging
logging.basicConfig(
    filename="./fuzz_report.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class DjSeed(AbstractSeed):
    def __init__(self, queue):
        self.queue = deque(queue)

    def chooseNext(self):
        if not self.queue:
            logging.info("[INFO] Refilling seed queue with mutated data.")
            self.queue.append(
                {
                    "name": "".join(random.choices("abcdef0123456789", k=10)),
                    "info": "seed info",
                    "price": random.uniform(0, 100),
                }
            )
        return self.queue.popleft()


class DjIsInteresting(AbstractIsInteresting):
    def __init__(self):
        self.prev_coverage = set()
        self.coverage_file = ".coverage"
        self.server_process = None

    def start_server(self):
        """Start Django server only once."""
        if not self.server_process:
            logging.info("[INFO] Starting Django server with coverage.")
            self.server_process = subprocess.Popen(
                ["coverage", "run", "manage.py", "runserver", "8000"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(5)  # Allow server to start

    def stop_server(self):
        """Gracefully stop the Django test server."""
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait()
            self.server_process = None
            logging.info("[INFO] Django server stopped.")

    def send_request(self, input: dict):
        """Send a request to Django and return the response."""
        print(".", end="")
        base_url = "http://127.0.0.1:8000/datatb/product/add/"
        headers = {"Content-Type": "application/json"}

        start_time = time.time()
        try:
            response = requests.post(base_url, headers=headers, json=input, timeout=5)
            elapsed_time = time.time() - start_time

            if elapsed_time > 5:
                logging.warning(
                    f"[WARNING] Request took too long ({elapsed_time:.2f}s)\nInput: {input}"
                )

            if response.status_code not in [200, 201]:
                logging.error(
                    f"[ERROR] Unexpected response: {response.status_code} - {response.text}\nInput: {input}"
                )

            return response

        except requests.exceptions.Timeout:
            elapsed_time = time.time() - start_time
            logging.error(
                f"[ERROR] Request timed out after {elapsed_time:.2f}s\nInput: {input}"
            )
            return None
        except ValueError as ve:
            # JSON serialization issue (e.g., NaN, Infinity)
            if "Out of range float values are not JSON compliant" in str(ve):
                logging.error(f"[ERROR] JSON encoding failed: {ve}\nInput: {input}")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"[ERROR] Request failed: {e}\nInput: {input}")
            return None

    def __call__(self, input: dict) -> bool:
        response = self.send_request(input)

        if not response or response.status_code not in [200, 201]:
            return False  # Ignore failed requests

        # Save and load coverage
        subprocess.run(["coverage", "combine"], stdout=subprocess.DEVNULL)
        cov = coverage.Coverage(data_file=self.coverage_file)
        cov.load()

        new_coverage = set()
        for file in cov.get_data().measured_files():
            new_coverage.update(cov.get_data().lines(file))

        if new_coverage - self.prev_coverage:
            logging.info(
                f"[INFO] New execution path found! {len(new_coverage - self.prev_coverage)} new lines covered."
            )
            self.prev_coverage.update(new_coverage)
            return True  # Found new execution path

        return False


class DjPowerSchedule(AbstractPowerSchedule):
    def __init__(self):
        self.discovered_paths = 1

    def assignEnergy(self):
        """Adaptive energy assignment based on new paths found."""
        base_energy = 1000
        return base_energy + (100 * self.discovered_paths)


class DjMutator(AbstractMutator):
    def mutateInput(self, input: dict) -> dict:
        """Mutate input fields aggressively."""
        mutated_data = input.copy()
        mutation_type = random.choice(["name", "info", "price", "all"])

        if mutation_type in ["name", "all"]:
            mutated_data["name"] = "".join(
                random.choices(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    k=random.randint(1, 30),
                )
            )

        if mutation_type in ["info", "all"]:
            mutated_data["info"] = "".join(
                random.choices(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    k=random.randint(1, 20),
                )
            )

        if mutation_type in ["price", "all"]:
            mutated_data["price"] = random.choice(
                [0, -1, 1, float("inf"), -float("inf"), random.uniform(-1000, 10000)]
            )

        return mutated_data


class DjGreyboxFuzzer(AbstractGreyboxFuzzer):
    def __init__(
        self,
        seed: DjSeed,
        power_schedule: DjPowerSchedule,
        mutator: DjMutator,
        is_interesting: DjIsInteresting,
    ):
        self.seed = seed
        self.power_schedule = power_schedule
        self.mutator = mutator
        self.is_interesting = is_interesting
        self.bugs = []
        self.max_iterations = 99999

    def run(self):
        """Main fuzzing loop."""
        self.is_interesting.start_server()
        logging.info("[INFO] Fuzzer started.")
        for _ in range(self.max_iterations):
            test_case = self.seed.chooseNext()
            energy = self.power_schedule.assignEnergy()

            for _ in range(energy):
                mutated_test = self.mutator.mutateInput(test_case)
                if self.is_interesting(mutated_test):
                    logging.info(
                        f"[INFO] Found new execution path with input: {mutated_test}"
                    )

        logging.info("[INFO] Fuzzer completed.")
        self.is_interesting.stop_server()


def main():
    seed = DjSeed(queue=[{"name": "seed name", "info": "abcd", "price": 12.21}])
    power_schedule = DjPowerSchedule()
    mutator = DjMutator()
    is_interesting = DjIsInteresting()

    fuzzer = DjGreyboxFuzzer(seed, power_schedule, mutator, is_interesting)
    fuzzer.run()


if __name__ == "__main__":
    main()
