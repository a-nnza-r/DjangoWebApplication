from coverage import Coverage, CoverageData
import random
import subprocess
import hashlib
import time
import requests
import logging
from typing import (
    Dict,
    List,
    Set,
    Any,
    Callable,
    Optional,
    Union,
    Tuple,
)

from abstractUpdated import (
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
    """
    each seed input: {
        data: {
            name: str,
            info: str,
            price: float,
        },
        s: int,
        f: int,
        path: hashed path
    }
    """

    def __init__(self, queue) -> None:
        # Initialize each seed with s and f counters
        self.queue = [{"data": seed, "s": 0, "f": 0} for seed in queue]
        self.paths: List[str] = []

    def getAverage(self):
        total = 0
        for ele in self.queue:
            total += ele["f"]
        return total / len(self.queue)

    def chooseNext(self):
        # Sort queue by s(i) first, then by f(i)
        sorted_queue = sorted(self.queue, key=lambda x: (x.get("s", 0), x.get("f", 0)))

        # Select seed with lowest counters
        chosen_seed = sorted_queue[0]

        # Increment selection counter s(i)
        chosen_seed["s"] = chosen_seed.get("s", 0) + 1

        return chosen_seed


class DjIsInteresting(AbstractIsInteresting):
    def __init__(self) -> None:
        pass

    def __call__(self, hashed_path: str, paths: List) -> bool:
        """
        Check if hashed arcs are new. If new add to paths in seed.
        Returns:
        - bool indicating if a new path was found
        """
        if hashed_path not in paths:
            paths.append(hashed_path)
            return True

        return False


class DjPowerSchedule(AbstractPowerSchedule):
    # TODO: metrics should be measured based on the type of mutation? to see which mutation is producing the best
    def __init__(self) -> None:
        self.energy_const = 1000
        self.p = 0.95
        self.max_energy: int = 150000

    def assignEnergy(self, input, average_f) -> int:
        """
        Exponential cutoff algorithm
        """
        print((self.energy_const / self.p) * (2 ** input["s"]))
        if input["f"] > average_f:
            return 0

        return min(
            int((self.energy_const / self.p) * (2 ** input["s"])), self.max_energy
        )


class DjMutator(AbstractMutator):
    def __init__(self) -> None:
        # Common words for word-based mutations
        self.common_words = [
            "test",
            "admin",
            "user",
            "password",
            "select",
            "delete",
            "update",
            "insert",
            "script",
            "alert",
            "document",
            "window",
            "undefined",
            "null",
            "true",
            "false",
            "function",
            "object",
            "array",
            "string",
            "number",
            "boolean",
            "error",
            "exception",
            "system",
            "database",
            "query",
            "table",
            "column",
            "row",
            "index",
            "key",
            "value",
            "input",
            "output",
            "file",
            "directory",
            "path",
            "url",
            "http",
            "https",
            "ftp",
            "localhost",
            "server",
            "client",
            "request",
            "response",
            "header",
            "body",
            "data",
        ]

        # Special characters for injection testing
        self.special_chars = [
            "'",
            '"',
            "`",
            ";",
            "\\",
            "/",
            "*",
            "+",
            "-",
            "=",
            "<",
            ">",
            "?",
            "!",
            "@",
            "#",
            "$",
            "%",
            "^",
            "&",
            "(",
            ")",
            "[",
            "]",
            "{",
            "}",
            "|",
            "~",
            ",",
            ".",
            "_",
        ]

        # SQL injection patterns
        self.sql_patterns = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "' AND 1=1--",
            "admin'--",
            "' OR ''='",
            "1' OR '1'='1",
            "' OR 'x'='x",
        ]

        # XSS patterns
        self.xss_patterns = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "onmouseover=alert(1)",
            "<svg onload=alert(1)>",
            "'\"<script>alert(1)</script>",
            '<img src="x" onerror="alert(1)">',
            "<body onload=alert(1)>",
            '<iframe src="javascript:alert(1)">',
            "data:text/html,<script>alert(1)</script>",
        ]

    def mutateInput(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Mutate input fields using various common mutation techniques."""
        mutated_data = input.copy()
        field = random.choice(list(mutated_data.keys()))

        if isinstance(mutated_data[field], str):
            str_mutation_methods: List[Callable[[str], str]] = [
                self.bit_flip,
                self.byte_insert,
                self.byte_delete,
                self.replace_with_extreme_string,
                self.word_mutation,
                self.special_char_mutation,
                self.sql_injection_mutation,
                self.xss_mutation,
                self.unicode_mutation,
                self.format_string_mutation,
                self.path_traversal_mutation,
                self.long_string_mutation,
            ]
            # Apply 1-3 mutations
            num_mutations = random.randint(1, 3)
            for _ in range(num_mutations):
                mutation = random.choice(str_mutation_methods)
                mutated_data[field] = mutation(mutated_data[field])

        elif isinstance(mutated_data[field], (int, float)):
            # Type for numeric mutation methods
            num_mutation_methods: List[Callable[[Union[int, float]], float]] = [
                self.replace_with_extreme_float,
                self.random_float_mutation,
            ]
            mutation: Callable[[Union[int, float]], float] = random.choice(
                num_mutation_methods
            )
            mutated_data[field] = mutation(mutated_data[field])

        return mutated_data

    def bit_flip(self, data: str) -> str:
        """Flip multiple random bits in a string."""
        if not data:
            return data
        s = list(data)
        num_flips = random.randint(1, max(1, len(s) // 10))
        for _ in range(num_flips):
            pos = random.randint(0, len(s) - 1)
            s[pos] = chr(ord(s[pos]) ^ (1 << random.randint(0, 7)))
        return "".join(s)

    def byte_insert(self, data: str) -> str:
        """Insert multiple random bytes into a string."""
        if not data:
            return data
        num_inserts = random.randint(1, 5)
        for _ in range(num_inserts):
            pos = random.randint(0, len(data))
            char = chr(random.randint(32, 126))
            data = data[:pos] + char + data[pos:]
        return data

    def byte_delete(self, data: str) -> str:
        """Delete multiple random bytes from a string."""
        if not data:
            return data
        num_deletes = random.randint(1, min(5, len(data)))
        for _ in range(num_deletes):
            if not data:
                break
            pos = random.randint(0, len(data) - 1)
            data = data[:pos] + data[pos + 1 :]
        return data

    def replace_with_extreme_string(self, data: str) -> str:
        """Replace string with extreme values."""
        extreme_values = [
            "",  # Empty string
            "\x00" * random.randint(1, 100),  # Null bytes
            "\xff" * random.randint(1, 100),  # 0xFF bytes
            "A" * random.randint(1000, 10000),  # Long string of As
            "Z" * random.randint(5000, 50000),  # Very long string of Zs
            " " * random.randint(100, 1000),  # Long string of spaces
            "\n" * random.randint(10, 100),  # Multiple newlines
            "\r\n" * random.randint(10, 100),  # Multiple CRLF
            "\t" * random.randint(10, 100),  # Multiple tabs
            "%" * random.randint(100, 1000),  # Long string of % for format string
            "../" * random.randint(10, 100),  # Path traversal
            "🔥" * random.randint(10, 100),  # Unicode emojis
            "א" * random.randint(10, 100),  # RTL text
        ]
        return random.choice(extreme_values)

    def word_mutation(self, data: str) -> str:
        """Mutate using common words."""
        mutation_type = random.randint(1, 3)
        if mutation_type == 1:  # Replace with random word
            return random.choice(self.common_words)
        elif mutation_type == 2:  # Append random word
            return data + random.choice(self.common_words)
        else:  # Insert random word
            words = data.split()
            if not words:
                return random.choice(self.common_words)
            pos = random.randint(0, len(words))
            words.insert(pos, random.choice(self.common_words))
            return " ".join(words)

    def special_char_mutation(self, data: str) -> str:
        """Add special characters."""
        num_chars = random.randint(1, 5)
        for _ in range(num_chars):
            pos = random.randint(0, len(data))
            char = random.choice(self.special_chars)
            data = data[:pos] + char + data[pos:]
        return data

    def sql_injection_mutation(self, data: str) -> str:
        """Add SQL injection patterns."""
        return random.choice(self.sql_patterns)

    def xss_mutation(self, data: str) -> str:
        """Add XSS patterns."""
        return random.choice(self.xss_patterns)

    def unicode_mutation(self, data: str) -> str:
        """Add Unicode characters."""
        unicode_ranges: List[Tuple[int, int]] = [
            (0x0080, 0x00FF),  # Latin-1 Supplement
            (0x0100, 0x017F),  # Latin Extended-A
            (0x0180, 0x024F),  # Latin Extended-B
            (0x0370, 0x03FF),  # Greek and Coptic
            (0x0400, 0x04FF),  # Cyrillic
            (0x0600, 0x06FF),  # Arabic
            (0x3040, 0x309F),  # Hiragana
            (0x30A0, 0x30FF),  # Katakana
            (0x4E00, 0x9FFF),  # CJK Unified Ideographs
        ]
        range_start, range_end = random.choice(unicode_ranges)
        char = chr(random.randint(range_start, range_end))
        return data + char

    def format_string_mutation(self, data: str) -> str:
        """Add format string patterns."""
        format_strings = [
            "%s",
            "%d",
            "%n",
            "%x",
            "%p",
            "%s" * 10,
            "%x" * 10,
            "%n" * 10,
            "%s%p%x%d",
            "%.1024d",
            "%p%p%p%p",
            "%#0123456x",
            "%@",
            "%n%n%n%n%n",
        ]
        return data + random.choice(format_strings)

    def path_traversal_mutation(self, data: str) -> str:
        """Add path traversal patterns."""
        traversal_patterns = [
            "../" * random.randint(1, 10) + "etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "./.././.././.././../etc/shadow",
            "%2e%2e%2f" * random.randint(1, 5),
            "....//....//....//etc/hosts",
        ]
        return random.choice(traversal_patterns)

    def long_string_mutation(self, data: str) -> str:
        """Create very long strings."""
        length = random.randint(5000, 100000)
        pattern = random.choice(
            [
                "A",
                "1",
                "!",
                "#",
                "$",
                "%",
                "&",
                "*",
                "AB",
                "12",
                "!@",
                "#$",
                "%^",
                "&*",
                "ABC",
                "123",
                "!@#",
                "#$%",
                "%^&",
                "&*(",
            ]
        )
        return pattern * (length // len(pattern))

    def replace_with_extreme_float(self, data: float) -> float:
        """Replace float with extreme values."""
        return random.choice(
            [
                float("inf"),
                -float("inf"),
                0,
                -9999999,
                9999999,
                float("nan"),
                1e-308,
                1e308,  # Double precision bounds
                2.2250738585072014e-308,  # Min normal double
                1.7976931348623157e308,  # Max double
            ]
        )

    def random_float_mutation(self, data: float) -> float:
        """Apply random float mutations."""
        mutation_type = random.randint(1, 3)
        if mutation_type == 1:
            return data + random.uniform(-1e10, 1e10)
        elif mutation_type == 2:
            return data * random.uniform(-1e5, 1e5)
        else:
            return data / random.uniform(-1e5, 1e5)


class DjGreyboxFuzzer(AbstractGreyboxFuzzer):
    """Greybox fuzzer with AFL-inspired coverage tracking and power scheduling."""

    def __init__(
        self,
        seed: DjSeed,
        power_schedule: DjPowerSchedule,
        mutator: DjMutator,
        is_interesting: DjIsInteresting,
    ) -> None:
        self.server_process = None
        self.seed = seed
        self.power_schedule = power_schedule
        self.mutator = mutator
        self.is_interesting = is_interesting
        # Type for bug reports
        BugReport = Dict[str, Any]
        self.bugs: List[BugReport] = []
        self.max_iterations = 10

    def log_results(
        self, input: Dict[str, Any], output: Any, is_interesting: bool
    ) -> None:
        return super().log_results(input, output, is_interesting)

    def visualize_results(self) -> None:
        return super().visualize_results()

    def start_server(self):
        # wrap django server with branch coverage to track arcs
        self.server_process = subprocess.Popen(
            ["coverage", "run", "--branch", "django/manage.py", "runserver", "8000"]
        )
        # wait 5s for server to start
        time.sleep(5)

    def stop_server(self):
        self.server_process.terminate()

    def send_request(self, input) -> Optional[requests.Response]:
        """Send a request to Django and return the response."""
        print(".", end="", flush=True)  # Progress indicator
        base_url = "http://127.0.0.1:8000/datatb/product/add/"
        headers = {"Content-Type": "application/json"}

        start_time = time.time()
        try:
            response = requests.post(base_url, headers=headers, json=input, timeout=5)
            elapsed_time = time.time() - start_time

            if elapsed_time > 5:
                msg = (
                    f"[WARNING] Request took too long ({elapsed_time:.2f}s)\n"
                    f"Input: {input}"
                )
                logging.warning(msg)

            if response.status_code not in [200, 201]:
                msg = (
                    f"[ERROR] Unexpected response: {response.status_code}\n"
                    f"Response: {response.text}\nInput: {input}"
                )
                logging.error(msg)

            return response

        except requests.exceptions.Timeout:
            elapsed_time = time.time() - start_time
            msg = (
                f"[ERROR] Request timed out after {elapsed_time:.2f}s\n"
                f"Input: {input}"
            )
            logging.error(msg)
            return None
        except ValueError as ve:
            # JSON serialization issue (e.g., NaN, Infinity)
            if "Out of range float values are not JSON compliant" in str(ve):
                logging.error(f"[ERROR] JSON encoding failed: {ve}\nInput: {input}")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"[ERROR] Request failed: {e}\nInput: {input}")
            return None

    # hash coverage data for easy comparison on whether a path is new
    def hash_cov_data(self, cov_data: CoverageData):
        path_coverage = {}  # data: (file_name, [branch arcs])
        for filename in cov_data.measured_files():
            lines = cov_data.arcs(filename)
            path_coverage[filename] = lines

        return self.hash_arcs(path_coverage)

    def hash_arcs(self, path_coverage: Dict):
        combined = []
        for fname in sorted(path_coverage.keys()):
            combined.append(fname)
            combined.extend(
                f"{a[0]}->{a[1]}"
                for a in sorted(path_coverage[fname] if path_coverage[fname] else [])
            )
        path_str = "|".join(combined)
        return hashlib.sha1(path_str.encode()).hexdigest()

    def run(self) -> None:
        """Main fuzzing loop."""
        self.start_server()
        cov = Coverage(data_file=".coverage")
        cov.erase()  # clear previous coverage data before starting loop

        logging.info("[INFO] Fuzzer started.")

        for _ in range(self.max_iterations):
            test_case = self.seed.chooseNext()
            energy = self.power_schedule.assignEnergy(test_case, self.seed.getAverage())
            logging.info(f"seed: {self.seed.queue}")
            logging.info(f"energy: {energy}")

            for _ in range(energy):
                # increment f by 1 for this seed input
                test_case["f"] += 1

                # Mutate and test
                mutated_test = self.mutator.mutateInput(test_case["data"])
                logging.info(f"input: {mutated_test}")

                cov.start()
                # TODO: send concurrent requests to overload server
                self.send_request(mutated_test)
                cov.stop()

                cov_data = cov.get_data()
                hashed_arcs = self.hash_cov_data(cov_data)
                cov.erase()

                # add hash to list of paths found in seed and isInteresting?
                if self.is_interesting(hashed_arcs, self.seed.paths):
                    logging.info(f"[INFO] New path found. \nInput: {mutated_test} ")

                # check for server crashes or hangs

        logging.info("[INFO] Fuzzer completed.")
        self.stop_server()


def main() -> None:
    seed = DjSeed(
        queue=[
            {
                "name": "abcdefghijklmnopqrstuvwxyz",
                "info": "abcdefghijklmnopqrstuvwxyz",
                "price": 121.23,
            },
            {"name": "aaaaaaaaaaaa", "info": "aaaaaaaaaaaa", "price": 1},
            {"name": "", "info": "", "price": 0},
        ]
    )
    power_schedule = DjPowerSchedule()
    mutator = DjMutator()
    is_interesting = DjIsInteresting()

    fuzzer = DjGreyboxFuzzer(seed, power_schedule, mutator, is_interesting)
    try:
        fuzzer.run()
    except KeyboardInterrupt:
        fuzzer.stop_server()


if __name__ == "__main__":
    main()
