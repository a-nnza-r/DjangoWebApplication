from coverage import Coverage, CoverageData, CoverageException
import random
import subprocess
import hashlib
import time
import requests
import logging
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import (
    Dict,
    List,
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

# --- Helper function for AFL-style bucketing ---
def _count_to_bucket_index(count: int) -> int:
    """Maps hit count to an AFL-like bucket index."""
    if count <= 0: return -1 # Should not happen for actual hits
    if count == 1: return 0
    if count == 2: return 1
    if count == 3: return 2
    if count <= 7: return 3
    if count <= 15: return 4
    if count <= 31: return 5
    if count <= 127: return 6
    return 7
# --- End Helper ---


class DjIsInteresting(AbstractIsInteresting):
    """
    Determines if a run is interesting based on AFL-style hit count bucketing.
    Updates the global coverage map if new, higher buckets are reached.
    """
    def __init__(self) -> None:
        # No state needed within the class itself anymore
        pass

    def __call__(self, 
                 arc_hit_counts: Dict[Tuple[str, int, int], int], 
                 global_coverage_map: Dict[Tuple[str, int, int], int]
                 ) -> bool:
        """
        Checks if the current run's hit counts reveal new coverage patterns
        based on AFL-style buckets. Updates the global map.

        Args:
            arc_hit_counts: Hit counts for arcs from the current run.
            global_coverage_map: The global map storing the highest bucket index seen per arc.

        Returns:
            True if the run is interesting (found a new higher bucket), False otherwise.
        """
        is_run_interesting = False
        
        if not arc_hit_counts:
             # If coverage failed or returned nothing, it's not interesting
            return False

        for arc, current_hit_count in arc_hit_counts.items():
            current_bucket_index = _count_to_bucket_index(current_hit_count)
            
            # Get the highest bucket index seen so far for this arc
            # Default to -1 (meaning never seen) if not in the map
            previous_max_bucket_index = global_coverage_map.get(arc, -1) 

            if current_bucket_index > previous_max_bucket_index:
                # This arc reached a higher bucket than ever before!
                is_run_interesting = True
                # Update the global map with the new highest bucket index
                global_coverage_map[arc] = current_bucket_index
                # Log the specific arc that was interesting (optional, can be verbose)
                # logging.debug(f"[DEBUG] Interesting arc found: {arc} - New bucket: {current_bucket_index} (Count: {current_hit_count}), Previous max bucket: {previous_max_bucket_index}")

        return is_run_interesting


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
                self.arith_inc_dec_str,
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
                self.arith_inc_dec_num,
                self.replace_with_extreme_int,
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
                # float("inf"),
                # -float("inf"),
                # float("nan"),
                0,
                -9999999,
                9999999,
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

    def arith_inc_dec_str(self, data: str) -> str:
        """Perform arithmetic inc/dec mutations on characters in the string."""
        if not data:
            return data

        s = list(data)
        num_mutations = random.randint(1, max(1, len(s) // 4))
        for _ in range(num_mutations):
            pos = random.randint(0, len(s) - 1)
            delta = random.choice([-1, +1, -2, +2])
            new_char = chr((ord(s[pos]) + delta) % 128)  # wrap within ASCII
            s[pos] = new_char
        return "".join(s)

    def arith_inc_dec_num(self, data: Union[int, float]) -> Union[int, float]:
        """Perform arithmetic inc/dec on numbers."""
        delta = random.choice([-1, +1, -10, +10, -100, +100])
        if isinstance(data, int):
            return data + delta
        elif isinstance(data, float):
            return data + float(delta)
        return data

    def replace_with_extreme_int(self, data: Union[int, float]) -> Union[int, float]:
        """Replace integer with extreme values for boundary testing."""
        extreme_int_values = [
            0,  # Zero
            -2147483648,  # Min 32-bit signed int
            2147483647,  # Max 32-bit signed int
            -9223372036854775808,  # Min 64-bit signed int
            9223372036854775807,  # Max 64-bit signed int
            -999999999999999999999999999,  # Very large negative
            999999999999999999999999999,  # Very large positive
            2**31,  # Overflow 32-bit int
            -(2**31 + 1),
            -(2**32 + 1),
            2**63,  # Overflow 64-bit int
            -(2**63 + 1),
        ]
        return random.choice(extreme_int_values)


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
        self.cov = Coverage(data_suffix=True, branch=True, auto_data=True) # Initialize Coverage object
        # --- Global Coverage Map ---
        # Stores the highest bucket index seen for each arc (filename, start, end)
        self.global_coverage_map: Dict[Tuple[str, int, int], int] = {} 
        # --- End Global Coverage Map ---
        # Type for bug reports
        BugReport = Dict[str, Any]
        self.bugs: List[BugReport] = []
        self.max_iterations = 30 

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

        if self.server_process is None:
            logging.error(f"[ERROR] server not running")
        elif self.server_process.poll() is not None:
            # server crashed
            logging.error(
                f"[ERROR] Server crashed, exit code {self.server_process.poll()}"
            )

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

    # --- New method to get arc hit counts ---
    def get_arc_hit_counts(self, cov_data: Optional[CoverageData]) -> Dict[Tuple[str, int, int], int]:
        """
        Extracts edge hit counts from CoverageData.
        Assumes duplicates in arcs() list represent multiple hits.
        Returns a dictionary mapping (filename, start, end) -> hit_count.
        """
        hit_counts: Dict[Tuple[str, int, int], int] = {}
        if not cov_data:
            logging.warning("[WARNING] No coverage data provided to get_arc_hit_counts.")
            return hit_counts
            
        try:
            measured_files = cov_data.measured_files()
            if not measured_files:
                # This can happen if the executed code wasn't measured (e.g., only external libraries)
                logging.debug("[DEBUG] No measured files found in coverage data.")
                return hit_counts

            for filename in measured_files:
                arcs = cov_data.arcs(filename)
                if arcs: # arcs can be None if no branches executed in the file
                    for start, end in arcs:
                        # Ensure start and end are integers
                        if isinstance(start, int) and isinstance(end, int):
                             # Filter out arcs indicating non-execution, like (-1, 0) or similar coverage.py internals if they appear
                            if start >= 0 and end >= 0:
                                arc_tuple = (filename, start, end)
                                hit_counts[arc_tuple] = hit_counts.get(arc_tuple, 0) + 1
                        else:
                             logging.warning(f"[WARNING] Non-integer arc component found in {filename}: ({start}, {end})")

        except Exception as e:
            logging.error(f"[ERROR] Failed to process coverage arcs: {e}")
            # Return potentially partial counts or empty dict? Empty seems safer.
            return {}
            
        # logging.debug(f"[DEBUG] Extracted hit counts: {hit_counts}") # Optional: very verbose
        return hit_counts
    # --- End of new method ---

    def _execute_test_case(self, test_input: Dict[str, Any]) -> Optional[requests.Response]:
        """Executes a single test case (sends request) without individual coverage."""
        # Coverage is now handled outside this worker function
        response = None
        try:
            response = self.send_request(test_input)
        except Exception as e:
            # Log exceptions during request sending, but don't handle coverage here
            logging.error(f"[ERROR] Unexpected exception during request sending: {e}\nInput: {test_input}")
            # We might lose the response if an error occurs here, but coverage is batch-level anyway
            
        return response


    def run(self) -> None:
        """Main fuzzing loop with concurrent requests."""
        self.start_server()
        self.cov.erase()  # Clear any stale coverage data before starting

        logging.info("[INFO] Fuzzer started.")

        max_workers = 5  # Number of concurrent requests
        iteration_count = 0 # Use a separate counter for logging iterations

        while iteration_count < self.max_iterations: # Loop based on iterations for clarity
            test_case = self.seed.chooseNext()
            # Calculate energy based on the chosen seed *before* modifying its 'f' counter
            energy = self.power_schedule.assignEnergy(test_case, self.seed.getAverage())
            
            logging.info(f"[INFO] Iteration {iteration_count + 1}: Chose seed {test_case['data']} with s={test_case['s']-1}, f={test_case['f']}. Assigned energy: {energy}") # Log s before increment

            if energy == 0:
                logging.info(f"[INFO] Iteration {iteration_count + 1}: Seed has 0 energy, skipping mutations.")
                iteration_count += 1
                continue # Skip to next iteration if no energy

            mutated_tests_for_batch = []
            for _ in range(energy):
                # Increment failure counter *before* mutation for this attempt
                test_case["f"] += 1 
                mutated_test = self.mutator.mutateInput(test_case["data"])
                mutated_tests_for_batch.append(mutated_test)

            logging.info(f"[INFO] Iteration {iteration_count + 1}: Generated {len(mutated_tests_for_batch)} mutations.")

            # --- Start Coverage for the whole batch ---
            self.cov.erase() 
            self.cov.start()
            
            batch_responses: Dict[Any, Optional[requests.Response]] = {}
            try:
                # Process requests concurrently
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Map inputs to futures
                    future_to_input = {executor.submit(self._execute_test_case, mutated_test): mutated_test for mutated_test in mutated_tests_for_batch}

                    for future in as_completed(future_to_input):
                        mutated_test = future_to_input[future]
                        try:
                            # Get response from the future result
                            response = future.result()
                            if response is None:
                                logging.error(f"[ERROR] Request failed (returned None) for input: {mutated_test}")
                            # else: Process response if needed (e.g., check status codes, content for bugs)

                        except Exception as e:
                            logging.error(f"[ERROR] Exception processing future result: {str(e)}\nInput: {mutated_test}")
            finally:
                 # --- Stop Coverage after the batch ---
                try:
                    self.cov.stop()
                except CoverageException as ce:
                     logging.error(f"[ERROR] Coverage stop error after batch: {ce}")
                
            # --- Process Batch Coverage ---
            cov_data = self.cov.get_data()
            arc_hit_counts = None
            if cov_data and cov_data.measured_files():
                arc_hit_counts = self.get_arc_hit_counts(cov_data)
            else:
                 logging.warning(f"[WARNING] No coverage data collected or no measured files for batch from seed {test_case['data']}")

            if arc_hit_counts is not None:
                # Check if the *entire batch* yielded interesting coverage
                is_batch_interesting = self.is_interesting(arc_hit_counts, self.global_coverage_map)

                if is_batch_interesting:
                    # If the batch was interesting, we add the *original seed* back to the queue
                    # This isn't ideal AFL, as we don't know *which* mutation was responsible,
                    # but it's a safer starting point than per-input coverage with threads.
                    # We could potentially add *all* inputs from the batch, but that might bloat the queue.
                    # Adding the original seed encourages further mutation around this area.
                    logging.info(f"[INFO] [COVERAGE_EVOLUTION] Iteration: {iteration_count + 1}, New coverage found! Original Seed: {test_case['data']}. Total unique coverage paths/arcs discovered: {len(self.global_coverage_map)}")
                    # Add the *original seed* back with reset counters
                    self.seed.queue.append({"data": test_case['data'], "s": 0, "f": 0})
                    # Note: The global_coverage_map was already updated inside is_interesting
            # --- End Batch Coverage Processing ---


            # Log coverage status update after processing all mutations for this seed/iteration
            logging.info(f"[INFO] [COVERAGE_STATUS] Iteration: {iteration_count + 1} completed. Total unique coverage paths/arcs discovered: {len(self.global_coverage_map)}")
            iteration_count += 1 # Increment iteration counter

        logging.info(f"[INFO] Fuzzer completed {self.max_iterations} iterations. Final unique coverage paths/arcs discovered: {len(self.global_coverage_map)}")
        self.stop_server()
        # Optionally combine coverage data from suffixed files if needed for a final report
        # try:
        #     final_coverage = Coverage(data_file=".coverage") # Specify the main file
        #     final_coverage.combine() 
        #     logging.info("[INFO] Combined coverage data.")
        #     # Generate report (e.g., final_coverage.html_report(directory='covhtml'))
        # except CoverageException as e:
        #     logging.error(f"[ERROR] Failed to combine coverage data: {e}")


def main() -> None:
    seed = DjSeed(
        queue=[
            {
                "name": "abcdefghijklmnopqrstuvwxyz",
                "info": "abcdefghijklmnopqrstuvwxyz",
                "price": 121.23,
            },
            # {"name": "aaaaaaaaaaaa", "info": "aaaaaaaaaaaa", "price": 1}, # Example seeds
            # {"name": "", "info": "", "price": 0}, # Example seeds
            # {"name": 0, "info": 0, "price": 0}, # Example seeds
            {"name": 1234567890, "info": 1234567890, "price": 1.3}, # Example seeds
            {"name": 1234567890, "info": "1234567890", "price": 1.3}, # Example seeds
            {"name": "1234567890", "info": 1234567890, "price": 1.3}, # Example seeds
        ]
    )
    power_schedule = DjPowerSchedule()
    mutator = DjMutator()
    # is_interesting instance is now stateless, just holds the logic
    is_interesting = DjIsInteresting() 

    fuzzer = DjGreyboxFuzzer(seed, power_schedule, mutator, is_interesting)
    try:
        fuzzer.run()
    except KeyboardInterrupt:
        fuzzer.stop_server()


if __name__ == "__main__":
    main()
