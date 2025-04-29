from coverage import Coverage, CoverageData, CoverageException
import random
import subprocess
import hashlib
import time
import requests
import logging
import json # Added for structured logging and safe repr
import threading
from queue import Queue
# Removed ThreadPoolExecutor, as_completed for sequential execution
import sys
import os
import yaml
import signal # Import the signal module
import psutil # For memory checking
import argparse # For command-line arguments
import traceback # For logging exceptions


from typing import (
    Dict,
    List,
    Any,
    Callable,
    Optional,
    Union,
    Tuple,
)

# Use relative import since abstractUpdated is in the same package
from abstractUpdated import (
    AbstractIsInteresting,
    AbstractGreyboxFuzzer,
    AbstractMutator,
    AbstractPowerSchedule,
    AbstractSeed,
)

# Setup basic logging (will be reconfigured in main for run-specific file)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# --- Setup dedicated loggers for structured data ---
# NOTE: Logger configuration is moved to main() to use run-specific paths
exp_logger = logging.getLogger('FuzzSeqLogLogger') # For overall experiment progress
interesting_logger = logging.getLogger('InterestingMutationsLogger') # For interesting mutations
# --- End logger setup ---


class DjSeed(AbstractSeed):
    """
    Represents a seed input for the fuzzer.
    Stores the input data and associated fuzzing counters.
    """
    def __init__(self, queue: List[Dict[str, Any]]) -> None:
        # Initialize each seed with s and f counters, ensuring data is copied
        self.queue = [{"data": seed.copy(), "s": 0, "f": 0} for seed in queue]
        # self.paths: List[str] = [] # Path tracking removed from seed, handled globally

    def getAverage(self) -> float:
        """Calculates the average 'f' (favourite) counter across the queue."""
        if not self.queue:
            return 0.0
        total_f = sum(ele.get("f", 0) for ele in self.queue)
        # Avoid division by zero if queue is empty
        return total_f / len(self.queue) if self.queue else 0.0


    def chooseNext(self) -> Optional[Dict[str, Any]]:
        """Chooses the next seed based on AFL's strategy (lowest s, then lowest f)."""
        if not self.queue:
            return None

        # Sort queue by s(i) first, then by f(i)
        # Use get with default 0 for safety
        sorted_queue = sorted(self.queue, key=lambda x: (x.get("s", 0), x.get("f", 0)))

        # Select seed with lowest counters
        chosen_seed = sorted_queue[0]

        # Increment selection counter s(i)
        chosen_seed["s"] = chosen_seed.get("s", 0) + 1

        return chosen_seed

class DjIsInteresting(AbstractIsInteresting):
    """
    Determines if a run (represented by its arc hit counts) is interesting
    based on AFL-style hit count bucketing. Updates the global coverage map.
    """
    def __init__(self) -> None:
        # This class is stateless regarding the check itself.
        pass

    @staticmethod
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

    def __call__(self,
                 arc_hit_counts: Dict[Tuple[str, int, int], int],
                 global_coverage_map: Dict[Tuple[str, int, int], int]
                 ) -> bool:
        """
        Checks if the current run's hit counts reveal new coverage patterns
        based on AFL-style buckets. Updates the global map if interesting.

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
            # Use the static method within the class
            current_bucket_index = DjIsInteresting._count_to_bucket_index(current_hit_count)

            # Get the highest bucket index seen so far for this arc
            # Default to -1 (meaning never seen) if not in the map
            previous_max_bucket_index = global_coverage_map.get(arc, -1)

            if current_bucket_index > previous_max_bucket_index:
                # This arc reached a higher bucket than ever before!
                is_run_interesting = True
                # Update the global map with the new highest bucket index
                global_coverage_map[arc] = current_bucket_index
                # Optional: Log the specific interesting arc (can be verbose)
                # logging.debug(f"Interesting arc: {arc}, New Bucket: {current_bucket_index} (Count: {current_hit_count}), Prev Max: {previous_max_bucket_index}")

        return is_run_interesting


class DjPowerSchedule(AbstractPowerSchedule):
    """
    Assigns energy to seeds based on AFL's exponential cutoff algorithm.
    Energy determines how many mutations are generated from a seed.
    """
    def __init__(self, config: Dict[str, Any]) -> None: # Accept config
        # Constants for energy calculation, read from config with defaults
        self.energy_const = config.get('energy_const', 1000) # Default 1000
        self.p = 0.95 # Probability factor (related to how quickly energy drops) - Keep hardcoded for now or add to config?
        self.max_energy: int = config.get('max_energy', 15000) # Default 15000
        logging.info(f"PowerSchedule initialized with energy_const={self.energy_const}, max_energy={self.max_energy}")

    def assignEnergy(self, input_seed: Dict[str, Any], average_f: float) -> int:
        """
        Calculates energy using an exponential cutoff algorithm.
        Penalizes seeds that have been selected many times ('s') or
        have failed to produce interesting results often ('f').

        Args:
            input_seed: The seed dictionary containing 's' and 'f' counters.
            average_f: The average 'f' counter across the entire seed queue.

        Returns:
            The calculated energy (number of mutations to generate).
        """
        # Use get with default 0 for safety
        s_val = input_seed.get("s", 0)
        f_val = input_seed.get("f", 0)

        # If the seed's failure rate is significantly above average, assign 0 energy
        # Avoid division by zero or penalizing early seeds if avg_f is 0
        if average_f > 0 and f_val > average_f * 2: # Example: Penalize if f is > 2x average
             logging.debug(f"Assigning 0 energy to seed (f={f_val} > 2*avg_f={average_f*2:.2f})")
             return 0

        # Calculate potential energy based on selection count 's'
        # Add basic overflow protection for the exponent
        try:
            # Limit s_val to prevent excessively large exponents (e.g., 30 is reasonable)
            safe_s_val = min(s_val, 30)
            exponent_term = 2 ** safe_s_val
        except OverflowError:
            # If s_val is too large, treat as max energy
            exponent_term = float('inf')
            logging.warning(f"Overflow calculating exponent for s_val={s_val}. Using max energy.")

        # Calculate potential energy, handling potential infinity
        if exponent_term == float('inf'):
            potential_energy = float('inf')
        else:
            # Avoid division by zero for p
            if self.p == 0:
                 potential_energy = float('inf') # Or handle as error
            else:
                 potential_energy = (self.energy_const / self.p) * exponent_term

        # Determine final energy, capping at max_energy
        if potential_energy == float('inf'):
             final_energy = self.max_energy
        else:
             # Ensure result is int, cap at max_energy
             final_energy = min(int(potential_energy), self.max_energy)

        # logging.debug(f"Assigning energy: {final_energy} (s={s_val}, f={f_val}, avg_f={average_f:.2f})")
        return final_energy

class DjMutator(AbstractMutator):
    # TODO: consider adding PSO for mutations, probability distribution of mutations should be based on their success in the explore phase
    def __init__(self, config_path: str = "fuzzer/fuzzer_config.yaml", use_constraints: bool = True) -> None:
        """
        Initialize the mutator, loading input structure constraints if enabled.

        Args:
            config_path: Path to the YAML configuration file containing 'input_structure'.
            use_constraints: Flag indicating whether to load and use constraints.
        """
        self.use_constraints = use_constraints
        self.input_structure = {} # Store parsed structure/constraints here

        if self.use_constraints:
            try:
                if config_path and os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        full_config = yaml.safe_load(f) # Load the full config temporarily
                    if full_config and 'input_structure' in full_config:
                        # Only store the input_structure part
                        self.input_structure = full_config['input_structure']
                        logging.info(f"Mutator loaded input structure from: {config_path}")
                    else:
                        logging.warning(f"Config file found at {config_path}, but missing 'input_structure' key. Constraint mutation may be limited.")
                else:
                     logging.warning(f"No fuzzer configuration file found at {config_path}. Constraint mutation may be limited.")
            except yaml.YAMLError as e:
                logging.error(f"Error parsing YAML configuration file {config_path} for mutator: {e}")
                self.input_structure = {}
            except Exception as e:
                logging.error(f"Error loading configuration file {config_path} for mutator: {e}")
                self.input_structure = {}
        else:
            logging.info("Mutator initialized with constraint-aware mutation DISABLED.")


        # Common words for word-based mutations
        self.common_words = [
            "test", "admin", "user", "password", "select", "delete", "update", "insert",
            "script", "alert", "document", "window", "undefined", "null", "true", "false",
            "function", "object", "array", "string", "number", "boolean", "error", "exception",
            "system", "database", "query", "table", "column", "row", "index", "key", "value",
            "input", "output", "file", "directory", "path", "url", "http", "https", "ftp",
            "localhost", "server", "client", "request", "response", "header", "body", "data",
        ]
        # Special characters for injection testing
        self.special_chars = [
            "'", '"', "`", ";", "\\", "/", "*", "+", "-", "=", "<", ">", "?", "!", "@", "#",
            "$", "%", "^", "&", "(", ")", "[", "]", "{", "}", "|", "~", ",", ".", "_",
        ]
        # SQL injection patterns
        self.sql_patterns = [
            "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", "' UNION SELECT * FROM users--",
            "' AND 1=1--", "admin'--", "' OR ''='", "1' OR '1'='1", "' OR 'x'='x",
        ]
        # XSS patterns
        self.xss_patterns = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
            "onmouseover=alert(1)", "<svg onload=alert(1)>", "'\"<script>alert(1)</script>",
            '<img src="x" onerror="alert(1)">', "<body onload=alert(1)>", '<iframe src="javascript:alert(1)">',
            "data:text/html,<script>alert(1)</script>",
        ]

    def mutateInput(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mutate input fields using various common mutation techniques."""
        mutated_data = input_data.copy() # Operate on a copy

        # Ensure there are keys to choose from
        if not mutated_data:
            return mutated_data

        field = random.choice(list(mutated_data.keys()))
        original_value = mutated_data.get(field) # Use get for safety

        # Handle cases where the chosen field might have been deleted or is None
        if original_value is None:
             mutated_data[field] = random.choice(["", "mutated_none", 0])
             return mutated_data

        # --- Get constraints for the field IF enabled ---
        constraints = None
        if self.use_constraints:
            field_config = self.input_structure.get(field, {})
            constraints = field_config.get('constraints') if isinstance(field_config, dict) else None
        # --- End Get constraints ---

        if isinstance(original_value, str):
            # Choose mutation list based on whether constraints are enabled
            if self.use_constraints:
                # Constraint-aware string mutations
                str_mutation_methods: List[Callable[[str, Optional[Dict[str, Any]]], str]] = [
                    self.bit_flip,
                    self.byte_insert, # Respects max_length
                    self.byte_delete, # Respects min_length
                    self.replace_with_extreme_string, # Respects min/max_length
                    self.word_mutation, # Respects min/max_length
                    self.special_char_mutation, # Respects max_length
                    self.sql_injection_mutation, # Respects max_length
                    self.xss_mutation, # Respects max_length
                    self.unicode_mutation, # Respects max_length
                    self.format_string_mutation, # Respects max_length
                    self.path_traversal_mutation, # Respects max_length
                    self.long_string_mutation, # Respects min/max_length
                    self.arith_inc_dec_str,
                    self.char_repeat, # Respects max_length
                    self.char_swap,
                    self.byte_overwrite,
                    self.block_overwrite
                ]
            else:
                # Simpler, non-constraint-aware string mutations
                str_mutation_methods: List[Callable[[str, Optional[Dict[str, Any]]], str]] = [
                    self.bit_flip, # Basic bit flip
                    self.byte_overwrite, # Basic byte overwrite
                    self.block_overwrite, # Basic block overwrite
                    self.char_swap, # Basic swap
                    lambda s, constraints=None: random.choice(self.common_words), # Replace with common word (ignore constraints)
                    lambda s, constraints=None: random.choice(self.sql_patterns), # Replace with SQL pattern (ignore constraints)
                    lambda s, constraints=None: random.choice(self.xss_patterns), # Replace with XSS pattern (ignore constraints)
                    lambda s, constraints=None: "A" * random.randint(1, 100), # Replace with random length 'A's
                ]

            mutation = random.choice(str_mutation_methods)
            try:
                 # Pass original value and constraints (which might be None)
                mutated_data[field] = mutation(original_value, constraints=constraints)
            except Exception as e:
                 # Fallback for unexpected errors during string mutation
                 logging.warning(f"Error during string mutation for field '{field}' (value: {original_value}, constraints: {constraints}, use_constraints: {self.use_constraints}): {e}. Falling back.")
                 mutated_data[field] = random.choice([original_value, "", "mutated_error"]) # Fallback

        elif isinstance(original_value, int):
            # Choose mutation list based on whether constraints are enabled
            if self.use_constraints:
                # Constraint-aware integer mutations
                int_mutation_methods: List[Callable[[int, Optional[Dict[str, Any]]], int]] = [
                    self.arith_inc_dec_int,       # Respects min/max_value
                    self.replace_with_extreme_int, # Respects min/max_value, specific_values
                    self.int_bit_flip,            # Respects min/max_value (optional check)
                    self.int_byte_swap            # Respects min/max_value (optional check)
                ]
            else:
                # Simpler, non-constraint-aware integer mutations
                int_mutation_methods: List[Callable[[int, Optional[Dict[str, Any]]], int]] = [
                    lambda i, constraints=None: i + random.choice([-1, 1, -10, 10, -100, 100]), # Basic arithmetic
                    lambda i, constraints=None: random.choice([0, -1, 1, 2**15-1, -(2**15)]), # Basic extremes
                    self.int_bit_flip, # Basic bit flip (without constraint check)
                    self.int_byte_swap # Basic byte swap (without constraint check)
                ]

            mutation = random.choice(int_mutation_methods)
            try:
                # Pass original value and constraints (which might be None)
                mutated_value = mutation(original_value, constraints=constraints)
                # Ensure mutation returns int or handle conversion/error
                mutated_data[field] = int(mutated_value)
            except (OverflowError, ValueError, TypeError) as e:
                 logging.warning(f"Error during integer mutation for field '{field}' (value: {original_value}, constraints: {constraints}, use_constraints: {self.use_constraints}): {e}. Falling back.")
                 mutated_data[field] = random.choice([0, 1, -1]) # Integer fallback

        elif isinstance(original_value, float):
            # Choose mutation list based on whether constraints are enabled
            if self.use_constraints:
                # Constraint-aware float mutations
                _float_only_mutations: List[Callable[[float, Optional[Dict[str, Any]]], float]] = [
                    self.replace_with_extreme_float, # Respects min/max_value, specific_values
                    self.random_float_mutation,      # Respects min/max_value
                    self.arith_inc_dec_float,      # Respects min/max_value
                ]
                _int_to_float_mutations: List[Callable[[int, Optional[Dict[str, Any]]], int]] = [
                     self.replace_with_extreme_int, # Respects min/max_value, specific_values
                     self.arith_inc_dec_int         # Respects min/max_value
                ]
                possible_mutations = _float_only_mutations * 2 + _int_to_float_mutations
            else:
                # Simpler, non-constraint-aware float mutations
                _float_only_mutations: List[Callable[[float, Optional[Dict[str, Any]]], float]] = [
                    lambda f, constraints=None: f + random.uniform(-100.0, 100.0), # Basic arithmetic
                    lambda f, constraints=None: f * random.uniform(-10.0, 10.0), # Basic scaling
                    lambda f, constraints=None: random.choice([0.0, 1.0, -1.0, 1e-5, -1e-5, 1e5, -1e5]), # Basic extremes
                ]
                possible_mutations = _float_only_mutations # Only use float mutations

            mutation = random.choice(possible_mutations)
            try:
                if mutation in _float_only_mutations:
                    # Apply float mutation directly
                    mutated_value = mutation(original_value, constraints=constraints)
                else: # This branch only runs if use_constraints is True
                    # Apply int mutation and cast result to float
                    int_result = mutation(int(original_value) if original_value.is_integer() else 0, constraints=constraints) # Call int mutation
                    mutated_value = float(int_result) # Cast result to float

                # Ensure result is a valid float
                mutated_data[field] = float(mutated_value)
            except (OverflowError, ValueError, TypeError) as e:
                 logging.warning(f"Error during float mutation for field '{field}' (value: {original_value}, constraints: {constraints}, use_constraints: {self.use_constraints}): {e}. Falling back.")
                 mutated_data[field] = random.choice([0.0, 1.0, -1.0]) # Float fallback

        # TODO: Handle other types if necessary (e.g., bool, list, dict) - currently ignored

        return mutated_data

    # --- Mutation Implementations ---

    def bit_flip(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Flip random bits in a string. Constraints currently unused."""
        # Constraints unused but included for consistent signature
        if not data: return data
        s = list(data)
        num_flips = random.randint(1, max(1, len(s) // 10))
        for _ in range(num_flips):
            if not s: break
            pos = random.randint(0, len(s) - 1)
            try:
                s[pos] = chr(ord(s[pos]) ^ (1 << random.randint(0, 7)))
            except ValueError:
                pass
        return "".join(s)

    def byte_insert(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Insert random bytes, respecting max_length constraint."""
        max_len = constraints.get('max_length') if constraints else None

        # If already at max length, cannot insert
        if max_len is not None and len(data) >= max_len:
            return data

        num_inserts = random.randint(1, 5)
        s = list(data)

        for _ in range(num_inserts):
            # Stop inserting if we hit max length
            if max_len is not None and len(s) >= max_len:
                break
            pos = random.randint(0, len(s))
            char = chr(random.randint(32, 126))
            s.insert(pos, char)
        return "".join(s)

    def byte_delete(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Delete random bytes, respecting min_length constraint."""
        if not data: return data

        min_len = constraints.get('min_length', 0) if constraints else 0

        # Calculate max possible deletions without violating min_len
        max_possible_deletes = max(0, len(data) - min_len)
        if max_possible_deletes == 0:
            return data # Cannot delete anything

        # Limit deletions based on what's possible and a reasonable max (e.g., 5)
        num_deletes = random.randint(1, min(5, max_possible_deletes))

        s = list(data)
        for _ in range(num_deletes):
            # This check should be redundant now due to calculation above, but safe to keep
            if not s: break
            pos = random.randint(0, len(s) - 1)
            del s[pos]
        return "".join(s)

    def replace_with_extreme_string(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Replace string with extreme values, trying to respect length constraints."""
        min_len = constraints.get('min_length', 0) if constraints else 0
        max_len = constraints.get('max_length') if constraints else float('inf') # Use infinity if no max

        # Generate potential extreme values
        extreme_values_generators = [
            lambda: "", # Empty string
            lambda: "\x00" * random.randint(min_len, min(50, int(max_len)) if max_len != float('inf') else 50),
            lambda: "\xff" * random.randint(min_len, min(50, int(max_len)) if max_len != float('inf') else 50),
            lambda: ''.join(random.choices(string.ascii_lowercase, k=random.randint(min_len, min(2000, int(max_len)) if max_len != float('inf') else 2000))),
            lambda: ''.join(random.choices(string.ascii_uppercase, k=random.randint(min_len, min(4000, int(max_len)) if max_len != float('inf') else 4000))),
            lambda: " " * random.randint(min_len, min(500, int(max_len)) if max_len != float('inf') else 500),
            lambda: "\n" * random.randint(min_len, min(50, int(max_len)) if max_len != float('inf') else 50),
            lambda: "../" * random.randint(min(min_len // 3, 1), min(20, int(max_len // 3)) if max_len != float('inf') else 20),
            lambda: "%s%n" * random.randint(min(min_len // 3, 1), min(20, int(max_len // 3)) if max_len != float('inf') else 20),
            lambda: ''.join(random.choices(string.digits, k=random.randint(min_len, min(1000, int(max_len)) if max_len != float('inf') else 1000))),        
        ]

        # Try to generate a valid extreme value
        attempts = 0
        while attempts < 10: # Try a few times to generate a valid one
             generator = random.choice(extreme_values_generators)
             try:
                 value = generator()
                 if min_len <= len(value) <= max_len:
                     return value
             except ValueError: # Handle potential issues with random range if min_len > max_len etc.
                 pass
             attempts += 1

        # Fallback if no valid extreme value generated easily
        fallback_len = random.randint(min_len, int(max_len) if max_len != float('inf') else min_len + 10)
        return "X" * fallback_len


    def word_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Insert or replace with common words, respecting length constraints."""
        min_len = constraints.get('min_length', 0) if constraints else 0
        max_len = constraints.get('max_length') if constraints else float('inf')

        word = random.choice(self.common_words)
        mutation_type = random.randint(1, 3)

        if mutation_type == 1: # Replace with word
            res = word
        elif mutation_type == 2: # Append word
            res = data + " " + word # Add space for clarity
        else: # Insert word
            words = data.split()
            if not words:
                res = word
            else:
                pos = random.randint(0, len(words))
                words.insert(pos, word)
                res = " ".join(words)

        # Adjust result to fit constraints
        if len(res) < min_len:
            # If too short, try appending original data or padding
            if len(data + " " + res) >= min_len and len(data + " " + res) <= max_len:
                 res = data + " " + res
            else:
                 padding_needed = min_len - len(res)
                 res += "X" * padding_needed # Pad with 'X'

        # Truncate if too long
        if len(res) > max_len:
            res = res[:int(max_len)] # Ensure max_len is int if not inf

        # Final check: if after adjustments it's still too short (e.g., max_len was < min_len initially)
        # return original data as fallback
        if len(res) < min_len:
             # If original data fits, return it, otherwise return a minimally valid string
             if min_len <= len(data) <= max_len:
                 return data
             else:
                 # Construct a minimal valid string if possible
                 return "Y" * min(min_len, int(max_len) if max_len != float('inf') else min_len)

        return res

    def special_char_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Add special characters, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        if max_len is not None and len(data) >= max_len:
            return data # Cannot insert

        num_chars = random.randint(1, 5)
        s = list(data)
        for _ in range(num_chars):
            if max_len is not None and len(s) >= max_len:
                break # Stop if max length reached
            pos = random.randint(0, len(s))
            char = random.choice(self.special_chars)
            s.insert(pos, char)
        return "".join(s)

    def sql_injection_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Replace with SQL injection patterns, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        pattern = random.choice(self.sql_patterns)
        return pattern[:max_len] if max_len is not None else pattern

    def xss_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Replace with XSS patterns, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        pattern = random.choice(self.xss_patterns)
        return pattern[:max_len] if max_len is not None else pattern

    def unicode_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Add Unicode characters, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        if max_len is not None and len(data) >= max_len:
            return data # Cannot insert

        unicode_ranges = [(0x0080, 0x07FF), (0x0E00, 0x0E7F), (0x1100, 0x11FF)]
        range_start, range_end = random.choice(unicode_ranges)
        try:
            char = chr(random.randint(range_start, range_end))
            char.encode('utf-8')
            return data + char
        except (ValueError, UnicodeEncodeError):
            return data

    def format_string_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Add format string patterns, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        if max_len is not None and len(data) >= max_len:
             return data # Cannot append

        format_strings = ["%s", "%d", "%n", "%x", "%p", "%s"*5, "%x"*5, "%n"*5]
        chosen_format = random.choice(format_strings)

        res = data + chosen_format
        return res[:max_len] if max_len is not None else res


    def path_traversal_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Replace with path traversal patterns, respecting max_length."""
        max_len = constraints.get('max_length') if constraints else None
        patterns = ["../"*random.randint(1, 5), "..\\"*random.randint(1, 5)]
        chosen_pattern = random.choice(patterns) + "etc/passwd" # Example target
        return chosen_pattern[:max_len] if max_len is not None else chosen_pattern

    def long_string_mutation(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Create long strings, respecting length constraints."""
        min_len = constraints.get('min_length', 1000) if constraints else 1000 # Default min if not specified
        max_len = constraints.get('max_length', 5000) if constraints else 5000 # Default max if not specified

        # Ensure min_len is not greater than max_len
        if min_len > max_len:
            min_len = max_len

        length = random.randint(min_len, max_len)
        pattern = random.choice(["A", "1", "!#", "AB"])
        # Ensure pattern is not empty to avoid division by zero
        if not pattern: pattern = "A"

        return pattern * (length // len(pattern))

    def byte_overwrite(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Overwrite a character at a random position with a random byte."""
        # Constraints currently unused but kept for signature consistency
        if not data: return data
        s = list(data)
        pos = random.randint(0, len(s) - 1)
        s[pos] = chr(random.randint(32, 126)) # Overwrite with a printable ASCII char
        return "".join(s)

    def block_overwrite(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Overwrite a block of characters with random bytes."""
         # Constraints currently unused but kept for signature consistency
        if not data: return data
        s = list(data)
        # Ensure block_len is at least 1 and doesn't exceed string length
        block_len = random.randint(1, max(1, len(s)))
        # Ensure start_pos allows for block_len without going out of bounds
        start_pos = random.randint(0, max(0, len(s) - block_len))

        for i in range(block_len):
             # Check index just in case, though calculation above should prevent OOB
            if start_pos + i < len(s):
                s[start_pos + i] = chr(random.randint(32, 126))

        return "".join(s)

    def char_repeat(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Repeat a character at a random position, respecting max_length."""
        if not data: return data
        max_len = constraints.get('max_length') if constraints else None
        if max_len is not None and len(data) >= max_len:
            return data # Cannot repeat if already at max length

        pos = random.randint(0, len(data) - 1)
        char_to_repeat = data[pos]
        # Repeat a small number of times
        repeat_count = random.randint(1, 5)

        repeated_part = char_to_repeat * repeat_count
        res = data[:pos+1] + repeated_part + data[pos+1:]

        # Truncate if exceeding max_len after repeat
        return res[:max_len] if max_len is not None else res

    def char_swap(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Swap two characters at random positions."""
        # Constraints are not directly used here but kept for signature consistency
        if len(data) < 2: return data # Need at least two chars to swap

        s = list(data)
        pos1 = random.randint(0, len(s) - 1)
        pos2 = random.randint(0, len(s) - 1)
        # Ensure positions are different for a meaningful swap
        attempts = 0
        while pos1 == pos2 and attempts < 5: # Avoid infinite loop on len 1 (though checked above)
            pos2 = random.randint(0, len(s) - 1)
            attempts += 1
        if pos1 == pos2: return data # Give up if couldn't find different positions quickly

        s[pos1], s[pos2] = s[pos2], s[pos1]
        return "".join(s)

    # --- Type-Specific Extreme Value Mutations (Constraint-Aware) ---
    def replace_with_extreme_float(self, data: float, constraints: Optional[Dict[str, Any]] = None) -> float:
        """Replace float with extreme float values, considering constraints."""
        import sys
        # Default extreme float values
        default_values = [
            0.0, -1.0, 1.0,
            sys.float_info.min, sys.float_info.max,
            -sys.float_info.max, sys.float_info.epsilon,
            -sys.float_info.epsilon,
        ]

        potential_values = default_values

        # Add values from constraints if they exist
        if constraints:
            # Use float() to handle potential int constraints being applied to float field
            if 'min_value' in constraints:
                potential_values.append(float(constraints['min_value']))
            if 'max_value' in constraints:
                potential_values.append(float(constraints['max_value']))
            if 'specific_values' in constraints and isinstance(constraints['specific_values'], list):
                 potential_values.extend([float(v) for v in constraints['specific_values'] if isinstance(v, (int, float))])

        # Determine bounds for filtering (use float for comparison)
        min_bound = float(constraints.get('min_value', -float('inf'))) if constraints else -float('inf')
        max_bound = float(constraints.get('max_value', float('inf'))) if constraints else float('inf')

        # Filter potential values to respect min/max bounds
        valid_values = [v for v in potential_values if min_bound <= v <= max_bound]

        # Ensure there's at least one value to choose
        if not valid_values:
            # Fallback logic similar to int, adapted for float
            if data == data and min_bound <= data <= max_bound: # Check data is not NaN and within bounds
                valid_values.append(data)
            elif min_bound <= 0.0 <= max_bound:
                 valid_values.append(0.0)
            elif min_bound != -float('inf'):
                 valid_values.append(min_bound)
            else: # Should only happen if bounds are impossible (-inf, -inf)
                 valid_values.append(0.0)

        # Remove duplicates (doesn't reliably work with NaN, but filter handles it)
        # Using list(dict.fromkeys(valid_values)) might be better if order matters less
        unique_valid_values = []
        seen = set()
        for v in valid_values:
            if v not in seen: # Simplified check now that NaN is gone
                unique_valid_values.append(v)
                seen.add(v)

        return random.choice(unique_valid_values)

    def random_float_mutation(self, data: float, constraints: Optional[Dict[str, Any]] = None) -> float:
        """Apply random arithmetic mutations to a float, respecting constraints."""
        # Determine bounds from constraints or use defaults
        min_bound = float(constraints.get('min_value', -sys.float_info.max)) if constraints else -sys.float_info.max
        max_bound = float(constraints.get('max_value', sys.float_info.max)) if constraints else sys.float_info.max

        mutation_type = random.randint(1, 3)
        try:
            if mutation_type == 1:
                # Add/subtract a value, ensuring it stays within bounds
                delta = random.uniform(-1e5, 1e5)
                res = data + delta
            elif mutation_type == 2:
                # Multiply by a factor, check bounds
                factor = random.uniform(-100, 100)
                res = data * factor
            else:
                # Divide by a factor, check bounds
                divisor = random.uniform(-100, 100)
                # Avoid division by zero or very small numbers causing overflow
                if abs(divisor) < 1e-10:
                    res = data # Or return a random valid float? For now, return original.
                else:
                    res = data / divisor

            # Clamp result to bounds
            # Handle potential NaN from operations before clamping
            if res != res: # Check for NaN
                 # logging.debug(f"NaN generated during random_float_mutation for {data}. Returning original.")
                 return data
            clamped_res = max(min_bound, min(max_bound, res))
            return clamped_res

        except (OverflowError, ValueError):
             # Fallback if mutation causes issues
             logging.debug(f"Exception during random_float_mutation for {data}. Falling back.")
             # Ensure fallback is within bounds if possible
             fallback_val = data # Default to original
             if min_bound <= 0.0 <= max_bound:
                 fallback_val = 0.0
             elif min_bound != -float('inf') and min_bound <= max_bound:
                 fallback_val = min_bound
             elif max_bound != float('inf') and min_bound <= max_bound:
                 fallback_val = max_bound
             # Clamp the chosen fallback just in case
             return max(min_bound, min(max_bound, fallback_val)) if min_bound <= max_bound else data


    def arith_inc_dec_str(self, data: str, constraints: Optional[Dict[str, Any]] = None) -> str:
        """Perform arithmetic inc/dec mutations on characters in the string."""
        # Constraints unused but included for consistent signature
        if not data: return data
        s = list(data)
        num_mutations = random.randint(1, max(1, len(s) // 5))
        for _ in range(num_mutations):
            if not s: break
            pos = random.randint(0, len(s) - 1)
            delta = random.choice([-1, +1, -2, +2])
            try:
                original_ord = ord(s[pos])
                new_ord = max(32, min(126, original_ord + delta))
                s[pos] = chr(new_ord)
            except ValueError:
                pass
        return "".join(s)

    def arith_inc_dec_num(self, data: Union[int, float]) -> Union[int, float]:
        delta = random.choice([-1, +1, -10, +10, -100, +100])
        try:
            if isinstance(data, int):
                res = data + delta
                if -9223372036854775808 <= res <= 9223372036854775807:
                    return res
                else: return data
            elif isinstance(data, float):
                res = data + float(delta)
                return max(-1.7e308, min(1.7e308, res))
        except OverflowError:
            return data
        return data # Return original on overflow

    # --- Type-Specific Arithmetic Mutations (Constraint-Aware) ---
    def arith_inc_dec_int(self, data: int, constraints: Optional[Dict[str, Any]] = None) -> int:
        """Perform arithmetic inc/dec on integers, respecting constraints if provided."""
        delta = random.choice([-1, +1, -10, +10, -100, +100])

        # Determine bounds from constraints or use defaults
        min_bound = constraints.get('min_value', -9223372036854775808) if constraints else -9223372036854775808
        max_bound = constraints.get('max_value', 9223372036854775807) if constraints else 9223372036854775807

        try:
            res = data + delta
            # Check against specified or default bounds
            if min_bound <= res <= max_bound:
                return res
            else:
                # If result is out of bounds, return original value
                return data
        except OverflowError: # Should be rare with Python's large ints, but safe
            return data # Return original on overflow

    def arith_inc_dec_float(self, data: float, constraints: Optional[Dict[str, Any]] = None) -> float:
        """Perform arithmetic inc/dec on floats, respecting constraints."""
        delta = random.choice([-1.0, +1.0, -10.0, +10.0, -100.0, +100.0])

        # Determine bounds from constraints or use defaults
        min_bound = float(constraints.get('min_value', -sys.float_info.max)) if constraints else -sys.float_info.max
        max_bound = float(constraints.get('max_value', sys.float_info.max)) if constraints else sys.float_info.max

        try:
            res = data + delta
            # Clamp result to bounds
            # Handle potential NaN from operations before clamping
            if res != res: # Check for NaN
                 # logging.debug(f"NaN generated during arith_inc_dec_float for {data}. Returning original.")
                 return data
            clamped_res = max(min_bound, min(max_bound, res))
            return clamped_res
        except (OverflowError, ValueError):
             # Fallback if mutation causes issues
             logging.debug(f"Exception during arith_inc_dec_float for {data}. Falling back.")
             # Ensure fallback is within bounds if possible (similar logic to random_float_mutation)
             fallback_val = data
             if min_bound <= 0.0 <= max_bound:
                 fallback_val = 0.0
             elif min_bound != -float('inf') and min_bound <= max_bound:
                 fallback_val = min_bound
             elif max_bound != float('inf') and min_bound <= max_bound:
                 fallback_val = max_bound
             return max(min_bound, min(max_bound, fallback_val)) if min_bound <= max_bound else data

    def replace_with_extreme_int(self, data: int, constraints: Optional[Dict[str, Any]] = None) -> int:
        """Replace integer with extreme integer values, considering constraints."""
        # Default extreme values
        default_values = [
            0, -1, 1,
            # Common boundaries
            2**15 - 1, -(2**15), 2**16 - 1, -(2**16 -1), # Standard 16-bit limits
            2**15, -(2**15), 2**16, -(2**16),
            2**31 - 1, -(2**31), 2**32 - 1, -(2**32 -1), # Standard 32-bit limits
            2**31, -(2**31), 2**32, -(2**32),
            2**63 - 1, -(2**63), # Standard 64-bit limits
        ]

        potential_values = default_values

        # Add values from constraints if they exist
        if constraints:
            if 'min_value' in constraints:
                potential_values.append(constraints['min_value'])
            if 'max_value' in constraints:
                potential_values.append(constraints['max_value'])
            if 'specific_values' in constraints and isinstance(constraints['specific_values'], list):
                potential_values.extend([v for v in constraints['specific_values'] if isinstance(v, int)])

        # Determine bounds for filtering
        min_bound = constraints.get('min_value', -float('inf')) if constraints else -float('inf')
        max_bound = constraints.get('max_value', float('inf')) if constraints else float('inf')

        # Filter potential values to respect min/max bounds
        valid_values = [v for v in potential_values if min_bound <= v <= max_bound]

        # Ensure there's at least one value to choose (e.g., 0 or original data if filtering is too strict)
        if not valid_values:
            # Fallback: try original value if within bounds, else 0 if within bounds, else min_bound if finite
            if min_bound <= data <= max_bound:
                valid_values.append(data)
            elif min_bound <= 0 <= max_bound:
                 valid_values.append(0)
            elif min_bound != -float('inf'):
                 valid_values.append(int(min_bound)) # Cast needed if min_bound came from float constraint
            else: # Should only happen if bounds are impossible (-inf, -inf)
                 valid_values.append(0)

        # Remove duplicates
        unique_valid_values = list(set(valid_values))

        return random.choice(unique_valid_values)

    # --- Integer Bit/Byte Mutations ---
    def int_bit_flip(self, data: int, constraints: Optional[Dict[str, Any]] = None) -> int:
        """Flip a random bit in the integer's binary representation."""
        # Constraints are not directly used for bit flipping but kept for signature consistency
        if data == 0: # Flipping a bit in 0 results in a power of 2
            return 1 << random.randint(0, 16) # Flip a bit in the lower 16 bits for practicality

        # Convert to bytes, flip a bit, convert back
        try:
            num_bytes = (data.bit_length() + 7) // 8
            data_bytes = data.to_bytes(num_bytes, byteorder='little', signed=(data < 0))

            byte_list = list(data_bytes)
            if not byte_list: return data # Should not happen if data != 0

            # Choose a random byte and bit position
            byte_index = random.randint(0, len(byte_list) - 1)
            bit_index = random.randint(0, 7)

            # Flip the bit
            byte_list[byte_index] ^= (1 << bit_index)

            # Convert back to integer
            mutated_data = int.from_bytes(bytes(byte_list), byteorder='little', signed=(data < 0))

            # Optional: Check if mutated value respects min/max constraints if provided
            if constraints:
                 min_bound = constraints.get('min_value', -float('inf'))
                 max_bound = constraints.get('max_value', float('inf'))
                 if not (min_bound <= mutated_data <= max_bound):
                     return data # Revert if mutation violates bounds

            return mutated_data
        except OverflowError:
             # Handle cases where bit flip might result in an extremely large number
             # (less likely with Python's arbitrary precision, but possible)
             logging.warning(f"OverflowError during int_bit_flip for {data}. Returning original.")
             return data
        except Exception as e:
             logging.warning(f"Error during int_bit_flip for {data}: {e}. Returning original.")
             return data

    def int_byte_swap(self, data: int, constraints: Optional[Dict[str, Any]] = None) -> int:
        """Swap two random bytes in the integer's representation."""
        # Constraints are not directly used for byte swapping but kept for signature consistency
        if data == 0: return 0 # Swapping bytes in 0 does nothing

        try:
            # Determine number of bytes needed, handle signedness
            num_bytes = (data.bit_length() + 7) // 8
            # Need at least 2 bytes to swap
            if num_bytes < 2: return data

            is_signed = data < 0
            data_bytes = data.to_bytes(num_bytes, byteorder='little', signed=is_signed)

            byte_list = list(data_bytes)

            # Choose two distinct byte indices to swap
            idx1 = random.randint(0, len(byte_list) - 1)
            idx2 = random.randint(0, len(byte_list) - 1)
            attempts = 0
            while idx1 == idx2 and attempts < 5: # Try to get different indices
                idx2 = random.randint(0, len(byte_list) - 1)
                attempts += 1
            if idx1 == idx2: return data # Give up if couldn't find distinct indices

            # Swap the bytes
            byte_list[idx1], byte_list[idx2] = byte_list[idx2], byte_list[idx1]

            # Convert back to integer
            mutated_data = int.from_bytes(bytes(byte_list), byteorder='little', signed=is_signed)

            # Optional: Check constraints
            if constraints:
                 min_bound = constraints.get('min_value', -float('inf'))
                 max_bound = constraints.get('max_value', float('inf'))
                 if not (min_bound <= mutated_data <= max_bound):
                     return data # Revert if mutation violates bounds

            return mutated_data
        except OverflowError:
             logging.warning(f"OverflowError during int_byte_swap for {data}. Returning original.")
             return data
        except Exception as e:
             logging.warning(f"Error during int_byte_swap for {data}: {e}. Returning original.")
             return data


class DjGreyboxFuzzer(AbstractGreyboxFuzzer):
    """
    Greybox fuzzer for Django applications using batch-level coverage
    with AFL-inspired bucketing and concurrent requests.
    Integrates constraint-aware mutation and improved error handling.
    """

    def __init__(
        self,
        seed: DjSeed,
        power_schedule: DjPowerSchedule,
        is_interesting: DjIsInteresting,
        config_path: str = "fuzzer/fuzzer_config.yaml",
        run_id: str = "run_0" # Add run_id for output directory structuring
    ) -> None:
        self.config = self._load_config(config_path) # Load config
        self.run_id = run_id
        self.config_path = config_path # Store config path for reference

        # --- Feature Flags from Config (Moved earlier) ---
        self.use_coverage_feedback = self.config.get('use_coverage_feedback', True)
        self.use_constraint_mutation = self.config.get('use_constraint_mutation', True) # Mutator needs to handle this internally
        self.use_seed_prioritization = self.config.get('use_seed_prioritization', True)
        # --- End Feature Flags ---

        self.server_process: Optional[subprocess.Popen] = None
        self.seed = seed
        self.power_schedule = power_schedule # Already initialized with config
        # Pass the main config path AND the constraint flag (now assigned) to the mutator
        self.mutator = DjMutator(config_path=self.config_path, use_constraints=self.use_constraint_mutation)
        self.is_interesting = is_interesting

        # --- Experiment Settings from Config ---
        self.experiment_name = self.config.get('experiment_name', 'default_exp')
        self.target_name = self.config.get('target_name', 'default_target')
        # Default output base dir relative to fuzzer location if not specified
        self.output_base_dir = self.config.get('output_base_dir', os.path.join(os.path.dirname(__file__), 'evaluation_runs', self.experiment_name))
        self.run_duration_hours = self.config.get('run_duration_hours', 0) # Default 0 hours (run indefinitely or until other limits)
        self.run_duration_seconds = self.run_duration_hours * 3600 if self.run_duration_hours > 0 else float('inf')

        # --- Configure Coverage Object ---
        # Use the specific coverage data file base name from config
        coverage_data_file_base = self.config.get('coverage_data_file', f'.coverage_{self.experiment_name}')
        # Place coverage file inside the run-specific output directory
        self.coverage_data_file_path = os.path.join(self.get_run_output_dir(), f"{coverage_data_file_base}") # No suffix needed if auto_data=False
        self.cov = Coverage(
            branch=True,
            auto_data=False, # Disable auto_data to explicitly control the file name
            data_file=self.coverage_data_file_path,
            config_file=False # Prevent loading external .coveragerc
            # source=[self.config.get('coverage_source')] if self.config.get('coverage_source') else None # Configure source directly
        )
        logging.info(f"Coverage configured to use data file: {self.coverage_data_file_path}")
        # --- End Coverage Config ---

        # --- Global State ---
        # Stores the highest bucket index seen for each arc (filename, start, end)
        self.global_coverage_map: Dict[Tuple[str, int, int], int] = {}
        # Stores hashes of unique paths encountered (based on arcs + bucket counts)
        self.global_unique_path_hashes: set[str] = set()
        # Stores all unique arcs ever seen
        self.global_unique_arcs: set[Tuple[str, int, int]] = set()
        # --- End Global State ---

        # Type for bug reports
        BugReport = Dict[str, Any]
        self.bugs: List[BugReport] = [] # Store inputs that cause specific failures

        # Fuzzing Limits - Read from config with defaults
        self.max_iterations = self.config.get('max_iterations', 100)
        self.total_mutation_limit = self.config.get('total_mutation_limit', 1000000) # Use higher default from new configs
        self.request_timeout = self.config.get('request_timeout', 2) # Read request timeout

        # Tracking
        self.start_time = time.time() # Record fuzzer start time
        self.mutation_count_total = 0
        self.last_successful_input: Optional[Dict[str, Any]] = None
        self.last_successful_input_repr: str = "N/A"
        self.last_successful_input_path_hash: str = "INITIAL" # Path hash of last successful input

        # Unique Error Tracking
        # Stores signatures: (type, details_key, path_hash)
        self.unique_errors: set[Tuple[str, str, str]] = set()
        # Stores full details of unique errors found
        self.unique_error_details: List[Dict[str, Any]] = []

        # Placeholder strings used when exact path hash isn't available/applicable
        self.PLACEHOLDER_PATH_HASHES: set[str] = {
            "INITIAL", # Before any successful run
            "N/A", # General placeholder
            "N/A_POST_CRASH",
            "N/A_POST_TIMEOUT",
            "N/A_POST_CONN_ERROR",
            "CRASHED", # Used in exp log when server crashed during run
            "CRASH_RESTART_FAIL", # Used in exp log
            "NO_ARCS",
            "NO_COVERAGE_DATA",
            "COVERAGE_ERROR",
            "COVERAGE_EXCEPTION",
            "FUZZER_LOOP", # For exceptions in the main fuzzer loop
            "N/A_IN_RUN", # Placeholder for path hash when coverage isn't processed per mutation
            "SERVER_START_FAIL", # Placeholder if server fails to start for a mutation
        }

    def get_run_output_dir(self) -> str:
        """Constructs the output directory path for the current run."""
        # Ensure base directory exists, create if not
        # Use os.path.join for cross-platform compatibility
        run_dir = os.path.join(self.output_base_dir, self.run_id)
        # Use try-except for robustness, especially if multiple processes might try to create it
        try:
            os.makedirs(run_dir, exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating output directory {run_dir}: {e}")
            # Fallback to current directory? Or raise error? For now, log and continue.
            return "." # Fallback to current directory
        return run_dir

    def _log_unique_error(self, bug_report: Dict[str, Any], path_hash: str) -> None:
        """Logs an error to the unique errors list, bypassing signature check if path_hash is a placeholder."""
        is_placeholder = path_hash in self.PLACEHOLDER_PATH_HASHES

        if is_placeholder:
            # Log every instance if path hash is a placeholder
            self.unique_error_details.append(bug_report)
            logging.info(f"Added unique error instance (placeholder path '{path_hash}'): {self.safe_repr(bug_report)}")
        else:
            # Check signature uniqueness only if path hash is valid
            error_signature = self._generate_error_signature(bug_report, path_hash)
            if error_signature not in self.unique_errors:
                self.unique_errors.add(error_signature)
                self.unique_error_details.append(bug_report)
                logging.info(f"Added UNIQUE error signature ({error_signature}): {self.safe_repr(bug_report)}")
            # else: Signature already seen, do not log again as unique


    def _generate_error_signature(self, bug_report: Dict[str, Any], path_hash: str) -> Tuple[str, str, str]:
        """Generates a unique signature tuple for an error based on type, key details, and path hash."""
        error_type = bug_report.get("type", "unknown_type")
        details_key = "N/A" # Default

        if error_type == "http_error":
            details_key = f"status_{bug_report.get('status_code', 'unknown')}"
        elif error_type.startswith("timeout"): # Covers timeout_alive, timeout_crash, timeout_memory_dos
            # Timeouts on the same path are considered the same for now, could add duration buckets later
            details_key = "timeout"
        elif error_type == "crash":
            details_key = f"exit_{bug_report.get('exit_code', 'unknown')}"
        elif error_type == "connection_error":
            # Often related to crashes, group by path
            details_key = "connection_error"
        elif error_type == "request_exception":
            # Group by error message prefix if available
            error_msg = str(bug_report.get('error', ''))[:50] # Use first 50 chars of error
            details_key = f"req_exc_{error_msg}"
        elif error_type == "unexpected_request_error":
            error_msg = str(bug_report.get('error', ''))[:50]
            details_key = f"unexp_req_err_{error_msg}"
        elif error_type == "fuzzer_exception":
             error_msg = str(bug_report.get('error', ''))[:50]
             details_key = f"fuzzer_exc_{error_msg}"
        # Add more specific key generation for other types if needed

        return (error_type, details_key, path_hash)

    def log_results(
        self, input: Dict[str, Any], output: Any, is_interesting: bool
    ) -> None:
        # Placeholder - specific logging happens within the run loop
        pass

    def visualize_results(self) -> None:
        # Placeholder - could generate reports or visualizations later
        pass

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Loads the YAML configuration file."""
        config = {}
        try:
            if config_path and os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {} # Ensure it's a dict even if file is empty
                logging.info(f"Fuzzer loaded configuration from: {config_path}")
            else:
                logging.warning(f"Fuzzer configuration file not found at {config_path}. Using defaults.")
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML configuration file {config_path}: {e}. Using defaults.")
        except Exception as e:
            logging.error(f"Error loading configuration file {config_path}: {e}. Using defaults.")
        return config

    def safe_repr(self, data: Any) -> str:
        """Attempts JSON dump, falls back to repr, ensuring ASCII for safety."""
        try:
            # Use ensure_ascii=True for safer logging in various environments
            return json.dumps(data, ensure_ascii=True)
        except TypeError:
            # Fallback to repr, ensuring it's ASCII encodable
            try:
                return repr(data).encode('ascii', 'backslashreplace').decode('ascii')
            except Exception:
                return "[REPR_ERROR]" # Final fallback

    def start_server(self):
        """Starts the Django server wrapped with coverage."""
        # Clean up previous coverage files before starting to avoid interference
        try:
            coverage_data_file_base = self.cov.config.data_file
            # Remove the main file and any parallel files from previous runs
            if os.path.exists(coverage_data_file_base):
                os.remove(coverage_data_file_base)
            for filename in os.listdir('.'):
                if filename.startswith(coverage_data_file_base + "."):
                    try:
                        os.remove(filename)
                    except OSError as e:
                        logging.warning(f"Error removing old coverage file {filename}: {e}")
        except Exception as e:
            logging.warning(f"Error cleaning up old coverage files: {e}")

        if self.server_process and self.server_process.poll() is None:
            logging.warning("Server process already running. Skipping start.")
            return

        # --- Read target execution config ---
        target_script = self.config.get('target_script')
        target_args = self.config.get('target_args', []) # Default to empty list
        coverage_source = self.config.get('coverage_source') # Can be None or empty

        if not target_script:
            logging.critical("`target_script` not defined in configuration. Cannot start server.")
            return
        if not os.path.exists(target_script):
             logging.critical(f"Target script '{target_script}' not found. Cannot start server.")
             return
        if not isinstance(target_args, list):
             logging.warning(f"`target_args` in config is not a list. Using empty list. Value: {target_args}")
             target_args = []
        # --- End Read target execution config ---

        # Use the coverage object's data file setting
        coverage_data_file = self.cov.config.data_file

        # --- Build the command dynamically ---
        cmd = [
            sys.executable, # Use the current Python interpreter
            "-m", "coverage", "run",
            "--branch",
            "--data-file", coverage_data_file, # Use configured data file
        ]
        # Add optional source flag
        if coverage_source:
             cmd.extend(["--source", coverage_source])

        # Add the target script and its arguments
        cmd.append(target_script)
        cmd.extend(target_args)
        # --- End Build the command dynamically ---

        logging.info(f"Starting target with command: {' '.join(cmd)}")
        try:
            # Start process, redirect stdout/stderr to avoid polluting fuzzer logs unless debugging
            # Define log file paths within the run directory
            stdout_log_path = os.path.join(self.get_run_output_dir(), 'runner_stdout.log')
            stderr_log_path = os.path.join(self.get_run_output_dir(), 'runner_stderr.log')

            # Open log files for writing
            self.stdout_log_file = open(stdout_log_path, 'w')
            self.stderr_log_file = open(stderr_log_path, 'w')

            self.server_process = subprocess.Popen(
                cmd,
                stdout=self.stdout_log_file,
                stderr=self.stderr_log_file,
                text=True,
                # Set process group ID to easily kill the whole group later if needed
                preexec_fn=os.setsid if sys.platform != "win32" else None
            )
            logging.info("Waiting for server to initialize...")
            time.sleep(2) # Simple wait, could be improved with port check


            # Check if server started successfully
            poll_result = self.server_process.poll()
            if poll_result is None:
                logging.info(f"Server started successfully (PID: {self.server_process.pid}).")
            else:
                logging.error(f"Server failed to start or exited immediately with code {poll_result}.")
                self.server_process = None
        except Exception as e:
            logging.error(f"Failed to start server process: {e}", exc_info=True)
            self.server_process = None
        finally:
            # Ensure log files are closed if server fails to start
            if self.server_process is None:
                if hasattr(self, 'stdout_log_file') and self.stdout_log_file:
                    self.stdout_log_file.close()
                if hasattr(self, 'stderr_log_file') and self.stderr_log_file:
                    self.stderr_log_file.close()


    def _log_server_output(self):
        """Logs stdout/stderr from the server process if available."""
        # This method is less useful now as output goes to files, but kept for potential direct debugging
        if not self.server_process: return
        try:
            stdout_data, stderr_data = self.server_process.communicate(timeout=0.1) # Short timeout
            if stdout_data and stdout_data.strip():
                 logging.debug(f"Server stdout:\n{stdout_data.strip()}")
            if stderr_data and stderr_data.strip():
                 logging.warning(f"Server stderr:\n{stderr_data.strip()}")
        except subprocess.TimeoutExpired:
            logging.debug("Timeout reading server output after termination/crash.")
        except Exception as e:
            logging.warning(f"Error reading server output: {e}")

    def stop_server(self):
        """Stops the Django server process gracefully, then forcefully if needed."""
        if not self.server_process or self.server_process.poll() is not None:
            logging.debug("Server process already stopped or not started.")
            self.server_process = None
            # Ensure log files are closed if they exist
            if hasattr(self, 'stdout_log_file') and self.stdout_log_file:
                try: self.stdout_log_file.close()
                except Exception as e: logging.warning(f"Error closing stdout log: {e}")
            if hasattr(self, 'stderr_log_file') and self.stderr_log_file:
                try: self.stderr_log_file.close()
                except Exception as e: logging.warning(f"Error closing stderr log: {e}")
            return

        pid = self.server_process.pid
        logging.info(f"Attempting to stop server process (PID: {pid})...")
        try:
            # Try SIGINT first (Ctrl+C), which coverage should handle
            logging.debug(f"Sending SIGINT to process group {pid}...")
            os.killpg(os.getpgid(pid), signal.SIGINT)
            self.server_process.wait(timeout=10) # Wait for graceful shutdown
            logging.info(f"Server process (PID: {pid}) terminated after SIGINT.")
        except subprocess.TimeoutExpired:
            logging.warning(f"Server process (PID: {pid}) did not terminate after SIGINT. Sending SIGTERM...")
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                self.server_process.wait(timeout=2)
                logging.info(f"Server process (PID: {pid}) terminated after SIGTERM.")
            except subprocess.TimeoutExpired:
                logging.error(f"Server process (PID: {pid}) did not terminate after SIGTERM. Sending SIGKILL.")
                os.killpg(os.getpgid(pid), signal.SIGKILL)
                self.server_process.wait(timeout=1) # Wait briefly after kill
                logging.info(f"Server process (PID: {pid}) terminated after SIGKILL.")
            except Exception as e:
                 logging.error(f"Error sending SIGTERM/SIGKILL to server (PID: {pid}): {e}", exc_info=True)
        except Exception as e:
            logging.error(f"Error stopping server process (PID: {pid}): {e}", exc_info=True)
            # Ensure process is killed if any error occurs during shutdown sequence
            try:
                if self.server_process.poll() is None:
                    logging.warning(f"Force killing server process (PID: {pid}) due to error during shutdown.")
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                    self.server_process.wait(timeout=1)
            except Exception as kill_err:
                 logging.error(f"Error during final force kill (PID: {pid}): {kill_err}")
        finally:
            # Ensure log files are closed after stopping
            if hasattr(self, 'stdout_log_file') and self.stdout_log_file:
                try: self.stdout_log_file.close()
                except Exception as e: logging.warning(f"Error closing stdout log: {e}")
            if hasattr(self, 'stderr_log_file') and self.stderr_log_file:
                try: self.stderr_log_file.close()
                except Exception as e: logging.warning(f"Error closing stderr log: {e}")
            self.server_process = None # Mark as stopped

    def send_request(self, input_data: Dict[str, Any]) -> Optional[requests.Response]:
        """Sends a single POST request to the target Django endpoint read from config."""
        # Read endpoint and timeout from config, provide defaults if missing
        target_url = self.config.get('target_endpoint')
        if not target_url:
            logging.error("Target endpoint not found in configuration. Cannot send request.")
            return None
        request_timeout = self.config.get('request_timeout', 2) # Default 2 seconds

        headers = {"Content-Type": "application/json"}
        input_repr = self.safe_repr(input_data)

        # Check server status *before* sending
        if self.server_process is None or self.server_process.poll() is not None:
            exit_code = self.server_process.poll() if self.server_process else 'N/A'
            logging.error(f"Server not running or crashed (exit code: {exit_code}) before sending request. Input: {input_repr}. Attrib: {self.last_successful_input_repr}")
            # Log crash attributed to the last known successful input and path
            if self.last_successful_input is not None:
                 # Attribute crash to last successful input and its path hash
                 bug_report = {"type": "crash", "input": self.last_successful_input, "exit_code": exit_code, "path_hash": self.last_successful_input_path_hash, "trigger": "pre_request_check"}
                 # Log using the helper method
                 self._log_unique_error(bug_report, self.last_successful_input_path_hash)

                 self.last_successful_input = None # Reset attribution
                 self.last_successful_input_repr = "N/A"
                 self.last_successful_input_path_hash = "N/A_POST_CRASH" # Reset path hash attribution
            # Attempt restart (might be handled by the main loop's crash check)
            # self.stop_server()
            # self.start_server()
            # if self.server_process is None or self.server_process.poll() is not None:
            #     logging.critical("Failed to restart server after crash detected pre-request.")
            #     # Log critical failure?
            return None # Indicate failure to send

        response = None
        start_time = time.time()
        try:
            response = requests.post(target_url, headers=headers, json=input_data, timeout=request_timeout) # Use config timeout
            elapsed_time = time.time() - start_time

            # Log near timeouts (e.g., if elapsed > 95% of timeout)
            if elapsed_time > request_timeout * 0.95:
                logging.warning(f"Request near timeout ({elapsed_time:.2f}s / {request_timeout}s). Input: {input_repr}")

            # Check for HTTP errors (client/server)
            if response.status_code >= 400:
                logging.error(f"HTTP {response.status_code} for {input_repr}. Response: {response.text[:500]}")
                # Use last successful path hash for HTTP errors triggered by current input
                bug_report = {"type": "http_error", "input": input_data, "status_code": response.status_code, "response_text": response.text[:500], "path_hash": self.last_successful_input_path_hash}
                # Log using the helper method
                self._log_unique_error(bug_report, self.last_successful_input_path_hash)
                # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional

                # Don't update last_successful_input on HTTP error

            else: # Success (2xx or 3xx)
                 # Update last successful input ONLY on success
                 # Path hash is updated in the run loop after coverage is processed
                 self.last_successful_input = input_data
                 self.last_successful_input_repr = input_repr
                 # self.last_successful_input_path_hash will be updated later

            return response

        except requests.exceptions.Timeout:
            elapsed_time = time.time() - start_time
            logging.error(f"Request timed out after {elapsed_time:.2f}s. Input: {input_repr}")

            # --- Investigate Timeout ---
            timeout_type = "timeout_alive" # Assume alive initially
            exit_code = None
            memory_usage_mb = None # Initialize memory usage
            if self.server_process and self.server_process.poll() is not None:
                # Server process terminated during the request
                exit_code = self.server_process.poll()
                timeout_type = "timeout_crash"
                logging.error(f"Server process found terminated (exit code: {exit_code}) after request timeout. Input: {input_repr}")
                # TODO: Consider attempting server restart here or rely on the main loop's check?
                # For now, just log the crash type. The main loop will handle restart if needed.
            else:
                # Server process is still running, but request timed out
                logging.warning(f"Server process still running after request timeout. Input: {input_repr}")
                # --- Check Memory Usage (if psutil is available) ---
                if psutil and self.server_process:
                    try:
                        pid = self.server_process.pid
                        proc = psutil.Process(pid)
                        mem_info = proc.memory_info()
                        memory_usage_mb = mem_info.rss / (1024 * 1024) # Convert RSS bytes to MB
                        # Read memory threshold from config, default to 1024 MB
                        MEMORY_THRESHOLD_MB = self.config.get('memory_threshold_mb', 1024)

                        logging.debug(f"Process {pid} memory usage: {memory_usage_mb:.2f} MB (Threshold: {MEMORY_THRESHOLD_MB} MB)")

                        if memory_usage_mb > MEMORY_THRESHOLD_MB:
                            timeout_type = "timeout_memory_dos"
                            logging.error(f"High memory usage detected ({memory_usage_mb:.2f} MB > {MEMORY_THRESHOLD_MB} MB) after timeout. Potential DoS. Input: {input_repr}")
                        # else: timeout_type remains "timeout_alive"

                    except psutil.NoSuchProcess:
                        logging.warning(f"psutil: Process {pid} not found during memory check (likely terminated between checks).")
                        # Process died between poll() and memory check, treat as crash?
                        # For simplicity, keep as timeout_alive for now, but could refine.
                    except Exception as e:
                        logging.warning(f"psutil: Error checking memory for process {pid}: {e}")
                # --- End Memory Check ---

            bug_report = {
                "type": timeout_type,
                "input": input_data,
                "duration": elapsed_time,
                "exit_code": exit_code, # Will be None if timeout_alive or timeout_memory_dos
                "memory_usage_mb": memory_usage_mb, # Add memory usage if checked
                "path_hash": self.last_successful_input_path_hash # Attribute timeout to last known good path
            }
            # Log using the helper method
            self._log_unique_error(bug_report, self.last_successful_input_path_hash)
            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
            # --- End Investigation ---

            self.last_successful_input = None # Reset attribution on any timeout
            self.last_successful_input_repr = "N/A"
            self.last_successful_input_path_hash = "N/A_POST_TIMEOUT" # Reset path hash attribution
            return None
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Connection error: {e}. Input: {input_repr}. Server might have crashed.")
            # Check server status immediately after connection error
            exit_code = None # Initialize exit_code here
            if self.server_process and self.server_process.poll() is not None:
                 exit_code = self.server_process.poll()
                 logging.error(f"Server confirmed crashed after ConnectionError (exit code: {exit_code}). Input: {input_repr}")
                 # Attribute crash to the input that triggered the connection error, using last known good path
                 bug_report = {"type": "crash", "input": input_data, "exit_code": exit_code, "trigger": "connection_error", "path_hash": self.last_successful_input_path_hash}
                 # Log using the helper method
                 self._log_unique_error(bug_report, self.last_successful_input_path_hash)
                 # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
            else:
                 # Server might still be running, but connection failed (e.g., network issue, server busy)
                 bug_report = {"type": "connection_error", "input": input_data, "error": str(e), "path_hash": self.last_successful_input_path_hash}
                 # Log using the helper method
                 self._log_unique_error(bug_report, self.last_successful_input_path_hash)
                 # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional

            self.last_successful_input = None # Reset attribution
            self.last_successful_input_repr = "N/A"
            self.last_successful_input_path_hash = "N/A_POST_CONN_ERROR" # Reset path hash attribution
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}. Input: {input_repr}")
            bug_report = {"type": "request_exception", "input": input_data, "error": str(e), "path_hash": self.last_successful_input_path_hash}
            # Log using the helper method
            self._log_unique_error(bug_report, self.last_successful_input_path_hash)
            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
            # Don't reset attribution here, as the server might still be okay
            return None
        except Exception as e:
            logging.error(f"Unexpected error during send_request: {e}. Input: {input_repr}", exc_info=True)
            bug_report = {"type": "unexpected_request_error", "input": input_data, "error": str(e), "path_hash": self.last_successful_input_path_hash}
            # Log using the helper method
            self._log_unique_error(bug_report, self.last_successful_input_path_hash)
            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
            # Consider resetting attribution depending on the error type
            return None

    def hash_arcs_with_counts(self, arc_hit_counts: Dict[Tuple[str, int, int], int]) -> str:
        """Hashes arcs along with their bucketed hit counts for path identification."""
        if not arc_hit_counts:
            return hashlib.sha1(b"").hexdigest() # Hash for empty coverage

        combined = []
        # Sort by filename, then start line, then end line for consistent hashing
        for arc_tuple in sorted(arc_hit_counts.keys()):
            filename, start, end = arc_tuple
            count = arc_hit_counts[arc_tuple]
            # Use the static method from DjIsInteresting class
            bucket = DjIsInteresting._count_to_bucket_index(count)
            # Include filename, arc, and bucket in the element to hash
            combined.append(f"{os.path.basename(filename)}:{start}->{end}:B{bucket}")

        path_str = "|".join(combined)
        return hashlib.sha1(path_str.encode()).hexdigest()

    def get_arc_hit_counts(self, cov_data: Optional[CoverageData]) -> Dict[Tuple[str, int, int], int]:
        """
        Extracts arc hit counts from CoverageData.
        Assumes duplicates in arcs() list represent multiple hits.
        """
        hit_counts: Dict[Tuple[str, int, int], int] = {}
        if not cov_data:
            logging.warning("No coverage data provided to get_arc_hit_counts.")
            return hit_counts

        try:
            measured_files = cov_data.measured_files()
            if not measured_files:
                logging.debug("No measured files found in coverage data.")
                return hit_counts

            for filename in measured_files:
                # Optional: Filter out non-project files if needed
                # if "DjangoWebApplication/django" not in filename: continue
                try:
                    arcs = cov_data.arcs(filename)
                    if arcs:
                        for start, end in arcs:
                            # Basic validation of arc data
                            if isinstance(start, int) and isinstance(end, int) and start >= -1 and end >= -1: # Allow -1 for entry points etc.
                                arc_tuple = (filename, start, end)
                                hit_counts[arc_tuple] = hit_counts.get(arc_tuple, 0) + 1
                            else:
                                # logging.warning(f"Ignoring invalid arc data for {filename}: ({start}, {end})")
                                pass
                except Exception as arc_err:
                     logging.error(f"Failed to get arcs for file {filename}: {arc_err}", exc_info=True)

        except Exception as e:
            logging.error(f"Failed to process coverage data: {e}", exc_info=True)
            return {} # Return empty on error
        return hit_counts

    # _execute_batch removed for sequential execution

    def run(self) -> None:
        """Main fuzzing loop executing requests sequentially with per-request coverage."""

        iteration_count = 0
        self.mutation_count_total = 0 # Reset total mutation count

        try: # Wrap in try/finally to ensure server stops
            self.start_server()
            if not self.server_process:
                 logging.critical("Server failed to start. Aborting fuzzing run.")
                 return

            logging.info(f"Fuzzer started (Sequential Mode). Max iterations: {self.max_iterations}, Max mutations: {self.total_mutation_limit}")
            # Log header for the experiment log file
            exp_logger.info(json.dumps({"event": "start", "mode": "sequential", "max_iterations": self.max_iterations, "total_mutation_limit": self.total_mutation_limit}))
            exp_logger.info(json.dumps({"event": "header", "columns": ["iteration", "mutation_index_total", "seed_data", "seed_s_pre", "seed_f_pre", "mutated_input", "execution_success", "mutation_path_hash", "mutation_unique_arcs_count", "new_unique_arcs_count", "is_mutation_interesting", "added_to_queue", "total_unique_arcs", "total_unique_paths", "mutation_time_ms", "execution_time_ms"]}))


            # Main loop: Continues until max iterations, total mutation limit, or duration reached, or queue empty
            while (iteration_count < self.max_iterations and
                   self.mutation_count_total < self.total_mutation_limit and
                   (time.time() - self.start_time) < self.run_duration_seconds):

                # Check duration limit again inside loop
                if (time.time() - self.start_time) >= self.run_duration_seconds:
                    logging.info(f"Run duration limit ({self.run_duration_hours} hours) reached. Stopping.")
                    break

                if not self.seed.queue:
                    logging.warning("Seed queue is empty. Stopping fuzzing.")
                    break

                iteration_count += 1
                chosen_seed_dict = self.seed.chooseNext()
                if chosen_seed_dict is None: # Should not happen if queue checked
                    logging.error("chooseNext returned None despite non-empty queue.")
                    break

                # --- Get seed info *before* modification for logging ---
                seed_data = chosen_seed_dict['data']
                seed_data_repr = self.safe_repr(seed_data)
                seed_s_pre_select = chosen_seed_dict.get('s', 1) - 1 # s was just incremented
                seed_f_pre_mutate = chosen_seed_dict.get('f', 0) # f is incremented below

                # Calculate energy for this seed
                energy = 1 # Default energy
                current_avg_f = 0.0 # Default if not calculated
                fixed_energy_value = 100 # Define a fixed energy value for non-prioritized runs

                if self.use_seed_prioritization:
                    # Only calculate dynamic energy if prioritization is enabled
                    current_avg_f = self.seed.getAverage()
                    energy = self.power_schedule.assignEnergy(chosen_seed_dict, current_avg_f)
                    logging.debug(f"Seed prioritization enabled. Avg f={current_avg_f:.2f}. Calculated energy: {energy}")
                else:
                    # Assign a fixed, moderate energy if prioritization is disabled
                    energy = fixed_energy_value
                    logging.debug(f"Seed prioritization disabled, using fixed energy: {fixed_energy_value}")


                logging.info(f"--- Iteration {iteration_count}/{self.max_iterations} ---")
                logging.info(f"Selected seed (s={seed_s_pre_select}, f={seed_f_pre_mutate}): {seed_data_repr}")
                logging.info(f"Avg f={current_avg_f:.2f}. Assigned energy: {energy}")

                if energy == 0:
                    logging.info("Seed has 0 energy, skipping mutations.")
                    # Log skipped mutation to experiment log
                    log_entry = {
                        "event": "mutation_log", "iteration": iteration_count,
                        "mutation_index_total": self.mutation_count_total,
                        "seed_data": seed_data_repr, "seed_s_pre": seed_s_pre_select, "seed_f_pre": seed_f_pre_mutate,
                        "mutated_input": "N/A (Skipped)", "execution_success": False,
                        "mutation_path_hash": "N/A", "mutation_unique_arcs_count": 0, "new_unique_arcs_count": 0,
                        "is_mutation_interesting": False, "added_to_queue": False,
                        "total_unique_arcs": len(self.global_unique_arcs), "total_unique_paths": len(self.global_unique_path_hashes),
                        "mutation_time_ms": 0.0, "execution_time_ms": 0.0 # Add 0 timings for skipped
                    }
                    exp_logger.info(json.dumps(log_entry, ensure_ascii=False))
                    continue # Go to next iteration

                # --- Sequential Mutation Loop ---
                mutations_to_attempt = min(energy, self.total_mutation_limit - self.mutation_count_total)
                logging.info(f"Attempting {mutations_to_attempt} mutations for this seed.")

                for mutation_index_in_iteration in range(mutations_to_attempt):
                    if self.mutation_count_total >= self.total_mutation_limit:
                         logging.warning(f"Reached total mutation limit ({self.total_mutation_limit}). Stopping early.")
                         break # Break inner loop

                    self.mutation_count_total += 1
                    # Increment seed's failure counter *for each mutation attempt*
                    chosen_seed_dict["f"] = chosen_seed_dict.get("f", 0) + 1

                    mutation_start_time = time.perf_counter()
                    mutated_input = self.mutator.mutateInput(seed_data)
                    mutation_end_time = time.perf_counter()
                    mutation_time_ms = (mutation_end_time - mutation_start_time) * 1000

                    mutated_input_repr = self.safe_repr(mutated_input)
                    logging.debug(f"Iter {iteration_count}, Mut #{self.mutation_count_total}: Input {mutated_input_repr} (Mutation took {mutation_time_ms:.2f} ms)")

                    # --- Execute Single Mutation & Collect Coverage ---
                    execution_success = False
                    response = None
                    cov_data = None
                    arc_hit_counts = {}
                    mutation_path_hash = "N/A"
                    mutation_unique_arcs_count = 0
                    new_unique_arcs_count = 0
                    is_mutation_interesting = False
                    added_to_queue = False
                    server_crashed_this_run = False
                    execution_time_ms = 0.0 # Initialize execution time

                    # Check for crash *before* sending request
                    if self.server_process is None or self.server_process.poll() is not None:
                        exit_code = self.server_process.poll() if self.server_process else 'N/A'
                        logging.error(f"Server crashed (exit code: {exit_code}) *before* mutation {self.mutation_count_total}. Input: {mutated_input_repr}. Attrib Input: {self.last_successful_input_repr}, Attrib Path: {self.last_successful_input_path_hash}")
                        if self.last_successful_input is not None:
                            # Attribute crash to last successful input and its path hash
                            bug_report = {"type": "crash", "input": self.last_successful_input, "exit_code": exit_code, "path_hash": self.last_successful_input_path_hash, "trigger": "pre_mutation_check"}
                            # Log using the helper method
                            self._log_unique_error(bug_report, self.last_successful_input_path_hash)
                            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional

                            self.last_successful_input = None # Reset attribution
                            self.last_successful_input_repr = "N/A"
                            self.last_successful_input_path_hash = "N/A_POST_CRASH" # Reset path hash attribution
                        # Attempt restart
                        self.stop_server()
                        self.start_server()
                        if self.server_process is None or self.server_process.poll() is not None:
                            logging.critical(f"Failed to restart server after crash detected before mutation {self.mutation_count_total}. Stopping.")
                            # Log failure to experiment log before breaking
                            log_entry = {
                                "event": "mutation_log", "iteration": iteration_count, "mutation_index_total": self.mutation_count_total,
                                "seed_data": seed_data_repr, "seed_s_pre": seed_s_pre_select, "seed_f_pre": seed_f_pre_mutate,
                                "mutated_input": mutated_input_repr, "execution_success": False, "mutation_path_hash": "CRASH_RESTART_FAIL",
                                "mutation_unique_arcs_count": 0, "new_unique_arcs_count": 0, "is_mutation_interesting": False, "added_to_queue": False,
                                "total_unique_arcs": len(self.global_unique_arcs), "total_unique_paths": len(self.global_unique_path_hashes),
                                "mutation_time_ms": mutation_time_ms, "execution_time_ms": 0.0 # Log timings
                            }
                            exp_logger.info(json.dumps(log_entry, ensure_ascii=False))
                            break # Stop fuzzing run entirely
                        else:
                            logging.info("Server restarted successfully.")

                    # If server is running (or restarted), proceed with request
                    if self.server_process and self.server_process.poll() is None:
                        self.cov.erase() # Erase data for this specific run
                        self.cov.start()
                        try:
                            execution_start_time = time.perf_counter()
                            response = self.send_request(mutated_input)
                            execution_end_time = time.perf_counter()
                            execution_time_ms = (execution_end_time - execution_start_time) * 1000

                            if response is not None:
                                # Consider request successful if we got any response (error or not)
                                # Specific bug logging (timeout, http_error, connection_error) happens in send_request
                                execution_success = True
                                # Check if it was specifically an HTTP error response
                                if response.status_code >= 400:
                                     pass # Bug already logged by send_request
                                # else: 2xx/3xx - last_successful_input updated in send_request
                            # else: response is None, bug logged by send_request (timeout, conn error, etc.)

                        except Exception as e:
                            execution_end_time = time.perf_counter()
                            execution_time_ms = (execution_end_time - execution_start_time) * 1000 if 'execution_start_time' in locals() else 0.0
                            logging.error(f"Unexpected exception during send_request call for mutation {self.mutation_count_total}: {e}\nInput: {mutated_input_repr}", exc_info=True)
                            # Use last known good path hash for this unexpected error
                            bug_report = {"type": "send_request_call_exception", "input": mutated_input, "error": str(e), "path_hash": self.last_successful_input_path_hash}
                            # Log using the helper method
                            self._log_unique_error(bug_report, self.last_successful_input_path_hash)
                            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
                            execution_success = False # Mark as failed
                        finally:
                            # Stop coverage measurement for this request
                            try:
                                self.cov.stop()
                                # Combine is needed even in sequential if using data_suffix/parallel_mode implicitly
                                self.cov.combine()
                            except CoverageException as ce:
                                logging.error(f"Coverage stop/combine error after mutation {self.mutation_count_total}: {ce}")
                            except Exception as e:
                                logging.error(f"Unexpected error during coverage stop/combine: {e}", exc_info=True)

                        # Check for crash *after* the request attempt
                        if self.server_process and self.server_process.poll() is not None:
                            exit_code = self.server_process.poll()
                            logging.error(f"Server crashed (exit code: {exit_code}) *after* mutation {self.mutation_count_total}. Input: {mutated_input_repr}.")
                            # Path hash for this crash will be determined *after* this block, if coverage was collected before crash
                            # We'll add the bug report *after* getting the path hash
                            server_crashed_this_run = True
                            execution_success = False # Don't process coverage if server crashed
                            self.last_successful_input = None # Reset attribution
                            self.last_successful_input_repr = "N/A"
                            self.last_successful_input_path_hash = "N/A_POST_CRASH" # Reset path hash attribution
                            # Attempt restart immediately for the next mutation
                            self.stop_server()
                            self.start_server()
                            if self.server_process is None or self.server_process.poll() is not None:
                                logging.critical(f"Failed to restart server after crash during mutation {self.mutation_count_total}. Stopping.")
                                # Log failure to experiment log before breaking
                                log_entry = {
                                    "event": "mutation_log", "iteration": iteration_count, "mutation_index_total": self.mutation_count_total,
                                    "seed_data": seed_data_repr, "seed_s_pre": seed_s_pre_select, "seed_f_pre": seed_f_pre_mutate,
                                    "mutated_input": mutated_input_repr, "execution_success": False, "mutation_path_hash": "CRASH_RESTART_FAIL",
                                    "mutation_unique_arcs_count": 0, "new_unique_arcs_count": 0, "is_mutation_interesting": False, "added_to_queue": False,
                                    "total_unique_arcs": len(self.global_unique_arcs), "total_unique_paths": len(self.global_unique_path_hashes),
                                    "mutation_time_ms": mutation_time_ms, "execution_time_ms": execution_time_ms # Log timings
                                }
                                exp_logger.info(json.dumps(log_entry, ensure_ascii=False))
                                break # Stop fuzzing run entirely
                            else:
                                logging.info("Server restarted successfully.")

                    # --- Process Coverage (Always if server didn't crash) ---
                    if not server_crashed_this_run:
                        try:
                            cov_data = self.cov.get_data()
                            if cov_data and cov_data.measured_files():
                                arc_hit_counts = self.get_arc_hit_counts(cov_data)
                                if arc_hit_counts:
                                    mutation_path_hash = self.hash_arcs_with_counts(arc_hit_counts) # Calculate hash
                                    mutation_arcs_set = set(arc_hit_counts.keys()) # Calculate arcs
                                    mutation_unique_arcs_count = len(mutation_arcs_set)
                                    new_arcs = mutation_arcs_set - self.global_unique_arcs
                                    new_unique_arcs_count = len(new_arcs)

                                    # --- Update global state (always, if coverage available) ---
                                    is_new_path = mutation_path_hash not in self.global_unique_path_hashes
                                    if is_new_path:
                                        self.global_unique_path_hashes.add(mutation_path_hash)
                                    if new_unique_arcs_count > 0:
                                        self.global_unique_arcs.update(mutation_arcs_set)
                                    # --- End Update global state ---

                                    # --- Calculate interestingness (always, updates global_coverage_map) ---
                                    # Note: self.is_interesting updates the global_coverage_map internally
                                    is_mutation_interesting = self.is_interesting(arc_hit_counts, self.global_coverage_map)
                                    # --- End Calculate interestingness ---

                                    # --- Update last successful path hash ONLY on successful execution ---
                                    if execution_success:
                                        self.last_successful_input_path_hash = mutation_path_hash

                                    # --- Log interesting mutations (always if interesting) ---
                                    if is_new_path or is_mutation_interesting:
                                        reason = []
                                        if is_new_path: reason.append("new_path")
                                        if is_mutation_interesting: reason.append("new_bucket")
                                        interesting_log_entry = {
                                            "event": "interesting_mutation",
                                            "mutation_index_total": self.mutation_count_total,
                                            "timestamp": time.time(),
                                            "mutated_input": mutated_input_repr,
                                            "seed_data": seed_data_repr,
                                            "mutation_path_hash": mutation_path_hash,
                                            "reason": "_and_".join(reason),
                                            "new_unique_arcs_count": new_unique_arcs_count,
                                            "total_unique_arcs": len(self.global_unique_arcs),
                                            "total_unique_paths": len(self.global_unique_path_hashes)
                                        }
                                        interesting_logger.info(json.dumps(interesting_log_entry, ensure_ascii=False))

                                        # --- Add to queue ONLY if feedback is enabled ---
                                        if self.use_coverage_feedback:
                                            logging.info(f"Mutation {self.mutation_count_total} interesting and feedback enabled. Adding to queue.")
                                            self.seed.queue.append({"data": mutated_input.copy(), "s": 0, "f": 0})
                                            added_to_queue = True
                                        else:
                                            logging.debug(f"Mutation {self.mutation_count_total} interesting but feedback disabled. Not adding to queue.")
                                else: # No arcs found
                                    mutation_path_hash = "NO_ARCS"
                                    if execution_success:
                                         self.last_successful_input_path_hash = mutation_path_hash
                                    logging.warning(f"No arc hit counts extracted for mutation {self.mutation_count_total}: {mutated_input_repr}")
                            else: # No measured files
                                mutation_path_hash = "NO_COVERAGE_DATA"
                                if execution_success:
                                     self.last_successful_input_path_hash = mutation_path_hash
                                logging.warning(f"No coverage data measured or loaded for mutation {self.mutation_count_total}: {mutated_input_repr}")
                        except CoverageException as ce:
                            logging.error(f"Failed to get/load coverage data after mutation {self.mutation_count_total}: {ce}")
                            mutation_path_hash = "COVERAGE_ERROR"
                        except Exception as e:
                            logging.error(f"Unexpected error processing coverage for mutation {self.mutation_count_total}: {e}", exc_info=True)
                            mutation_path_hash = "COVERAGE_EXCEPTION"
                    else: # Server crashed this run
                        mutation_path_hash = "CRASHED"
                        # Reset counts as they are meaningless if server crashed before coverage processing
                        mutation_unique_arcs_count = 0
                        new_unique_arcs_count = 0
                        is_mutation_interesting = False # Ensure these are reset if server crashed
                        added_to_queue = False

                    # --- Handle Post-Mutation Crash Logging (Now that path_hash is available) ---
                    if server_crashed_this_run:
                        # We already logged the crash event, now add unique error if applicable
                        # Use the mutation_path_hash calculated (or error string if coverage failed)
                        bug_report = {"type": "crash", "input": mutated_input, "exit_code": exit_code, "trigger": "post_mutation", "path_hash": mutation_path_hash}
                        # Log using the helper method
                        self._log_unique_error(bug_report, mutation_path_hash)
                        # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional

                    # --- Log Mutation Data to Experiment Log ---
                    log_entry = {
                        "event": "mutation_log",
                        "iteration": iteration_count,
                        "mutation_index_total": self.mutation_count_total,
                        "seed_data": seed_data_repr,
                        "seed_s_pre": seed_s_pre_select,
                        "seed_f_pre": seed_f_pre_mutate, # Log f before this mutation's increment
                        "mutated_input": mutated_input_repr,
                        "execution_success": execution_success and not server_crashed_this_run, # Mark false if crashed
                        "mutation_path_hash": mutation_path_hash if not server_crashed_this_run else "CRASHED",
                        "mutation_unique_arcs_count": mutation_unique_arcs_count if not server_crashed_this_run else 0,
                        "new_unique_arcs_count": new_unique_arcs_count if not server_crashed_this_run else 0,
                        "is_mutation_interesting": is_mutation_interesting if not server_crashed_this_run else False,
                        "added_to_queue": added_to_queue,
                        "total_unique_arcs": len(self.global_unique_arcs),
                        "total_unique_paths": len(self.global_unique_path_hashes),
                        "mutation_time_ms": mutation_time_ms,
                        "execution_time_ms": execution_time_ms
                    }
                    exp_logger.info(json.dumps(log_entry, ensure_ascii=False))
                    # --- End Mutation Logging ---

                    if server_crashed_this_run:
                        logging.warning(f"Server crashed during mutation {self.mutation_count_total}, continuing to next mutation after restart.")
                        # No need to break the inner loop here unless restart fails (handled above)

                # --- End of inner mutation loop ---
                if self.mutation_count_total >= self.total_mutation_limit:
                     break # Break outer loop if limit reached within inner loop

                # Log end of iteration status
                logging.info(f"Iteration {iteration_count} finished processing seed. Total Mutations: {self.mutation_count_total}. Queue Size: {len(self.seed.queue)}")

            # --- End of main fuzzing loop (while) ---

        except KeyboardInterrupt:
            logging.info("Fuzzing interrupted by user.")
        except Exception as e:
            logging.error(f"Unhandled exception in main fuzzing loop: {e}", exc_info=True)
            # Use "FUZZER_LOOP" as path hash for fuzzer-level exceptions
            bug_report = {"type": "fuzzer_exception", "error": str(e), "traceback": traceback.format_exc(), "path_hash": "FUZZER_LOOP"}
            # Log using the helper method - "FUZZER_LOOP" is a placeholder
            self._log_unique_error(bug_report, "FUZZER_LOOP")
            # if bug_report not in self.bugs: self.bugs.append(bug_report) # Optional
            # Log to experiment log as well
            exp_logger.error(json.dumps({"event": "fuzzer_exception", "error": str(e)}, ensure_ascii=False))
        finally:
            logging.info("Fuzzing run finished. Stopping server...")
            self.stop_server()

            # --- Save Unique Errors ---
            # Construct path within the run-specific output directory
            unique_errors_filename = self.config.get('unique_errors_file', 'unique_errors.jsonl')
            unique_errors_filepath = os.path.join(self.get_run_output_dir(), unique_errors_filename)
            logging.info(f"Saving {len(self.unique_error_details)} unique errors found to {unique_errors_filepath}...")
            try:
                with open(unique_errors_filepath, 'w') as f: # Overwrite file at the end
                    for error_detail in self.unique_error_details:
                        try:
                            # Use default=str to handle non-serializable items like Exception objects if any
                            f.write(json.dumps(error_detail, default=str) + '\n')
                        except Exception as json_err:
                            logging.error(f"Could not serialize unique error detail: {json_err}. Detail: {error_detail}")
                            f.write(json.dumps({"error": "Serialization failed", "original_detail_repr": repr(error_detail)}) + '\n')
                logging.info(f"Successfully saved unique errors to {unique_errors_filepath}")
            except Exception as e:
                logging.error(f"Failed to save unique errors to {unique_errors_filepath}: {e}", exc_info=True)
            # --- End Save Unique Errors ---

            # --- Process Final Coverage ---
            final_coverage_arcs = 0
            # final_coverage_paths = 0 # Path hashing isn't meaningful without per-mutation data
            try:
                logging.info("Attempting to process final coverage data...")
                # Combine data files generated by the target process
                self.cov.combine(strict=False) # Use strict=False to ignore errors if no data file found

                # Load the combined data from the file system
                final_cov_data = CoverageData(basename=self.coverage_data_file_path) # Use the correct path
                final_cov_data.read() # Read the combined data file

                if final_cov_data and final_cov_data.measured_files():
                    final_arc_hit_counts = self.get_arc_hit_counts(final_cov_data)
                    final_coverage_arcs = len(final_arc_hit_counts) # Count unique arcs found in the whole run
                    logging.info(f"Final coverage processing: Found {final_coverage_arcs} unique arcs.")
                    # Optional: Could generate a final coverage report here if needed
                    # self.cov.report(file=sys.stdout)
                    # self.cov.html_report(directory='covhtml_final')
                else:
                    logging.warning("No final coverage data found or loaded after run.")
            except CoverageException as ce:
                logging.error(f"Failed to combine/read final coverage data: {ce}")
            except Exception as e:
                logging.error(f"Unexpected error processing final coverage: {e}", exc_info=True)
            # --- End Process Final Coverage ---


            # --- Final Summary ---
            final_summary = {
                "event": "end",
                "total_iterations_completed": iteration_count,
                "total_mutations_run": self.mutation_count_total,
                "final_total_unique_arcs": final_coverage_arcs, # Use arcs found at the end
                "final_total_unique_paths": len(self.global_unique_path_hashes), # Path hashes are not reliable now
                "final_seed_queue_size": len(self.seed.queue) if self.seed else 0,
                "final_bug_count": len(self.unique_error_details) # Use unique errors count
            }
            exp_logger.info(json.dumps(final_summary, ensure_ascii=False)) # Log summary to exp log

            logging.info("--- Fuzzing Summary ---")
            logging.info(f"Completed Iterations: {iteration_count}")
            logging.info(f"Total Mutations Executed: {self.mutation_count_total}")
            logging.info(f"Final Unique Arcs Found (End of Run): {final_coverage_arcs}") # Report final arcs
            logging.info(f"Final Unique Path Hashes Found (Not Reliable): {len(self.global_unique_path_hashes)}")
            logging.info(f"Final Seed Queue Size: {len(self.seed.queue) if self.seed else 0}") # Check if seed exists
            logging.info(f"Total Unique Errors Found: {len(self.unique_error_details)}") # Log count of unique errors

            # Log the unique errors found (already saved to file)
            if self.unique_error_details:
                logging.info("--- Unique Errors Summary (details in file) ---")
                # Log summary to experiment log
                exp_logger.info(json.dumps({"event": "final_unique_errors_summary", "count": len(self.unique_error_details)}))
                # Log first few unique errors to main log for quick overview
                for i, bug in enumerate(self.unique_error_details[:5]): # Log first 5
                    bug_repr = self.safe_repr(bug)
                    logging.info(f"Unique Error #{i+1}: {bug_repr}")
                if len(self.unique_error_details) > 5:
                    logging.info(f"... and {len(self.unique_error_details) - 5} more unique errors (see {unique_errors_filepath}).")
            else:
                logging.info("No unique errors recorded.")
                exp_logger.info(json.dumps({"event": "final_unique_errors_summary", "count": 0}))


            logging.info("-----------------------")


def load_seeds_from_jsonl(file_path: str) -> List[Dict[str, Any]]:
    """Loads initial seeds from a JSON Lines file."""
    seeds = []
    if not os.path.exists(file_path):
        logging.error(f"Seed file not found: {file_path}. Returning empty seed list.")
        return seeds
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                if not line: # Skip empty lines
                    continue
                try:
                    seed_data = json.loads(line)
                    if isinstance(seed_data, dict):
                        seeds.append(seed_data)
                    else:
                        logging.warning(f"Skipping non-dictionary item in seed file {file_path} at line {line_num + 1}: {line}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON in seed file {file_path} at line {line_num + 1}: {e}. Line: '{line}'")
    except Exception as e:
        logging.error(f"Error reading seed file {file_path}: {e}")
    logging.info(f"Loaded {len(seeds)} seeds from {file_path}")
    return seeds

def main() -> None:
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Run Django Greybox Fuzzer with specific configuration.")
    parser.add_argument('--config', type=str, default="fuzzer/fuzzer_config.yaml",
                        help='Path to the YAML configuration file.')
    parser.add_argument('--run_id', type=str, default="run_0",
                        help='Identifier for this specific run (used for output directory).')
    args = parser.parse_args()
    config_path = args.config
    run_id = args.run_id
    # --- End Argument Parsing ---


    # --- Load Config First ---
    config = {}
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            logging.info(f"Main loaded configuration from: {config_path}")
        else:
            logging.warning(f"Main: Fuzzer configuration file not found at {config_path}. Using defaults.")
            config_path = None # Indicate default config wasn't found
    except yaml.YAMLError as e:
        logging.error(f"Main: Error parsing YAML configuration file {config_path}: {e}. Using defaults.")
        config_path = None
    except Exception as e:
        logging.error(f"Main: Error loading configuration file {config_path}: {e}. Using defaults.")
        config_path = None
    # --- End Config Loading ---

    # --- Configure Logging (Now with run_id and output_dir) ---
    # Determine output directory based on config (if loaded) or default structure
    output_base_dir_cfg = config.get('output_base_dir', './evaluation_runs/default/')
    run_output_dir = os.path.join(output_base_dir_cfg, run_id)
    os.makedirs(run_output_dir, exist_ok=True)

    # Configure root logger (basic info)
    report_log_path = os.path.join(run_output_dir, 'fuzz_report.log')
    # Remove existing handlers before adding new ones
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        filename=report_log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode='w' # Overwrite report log each run
    )

    # Configure experiment logger (detailed JSON)
    exp_log_path = os.path.join(run_output_dir, 'fuzz_exp.jsonl')
    # Remove existing handlers from exp_logger before adding new ones
    for handler in exp_logger.handlers[:]:
        exp_logger.removeHandler(handler)
    exp_file_handler = logging.FileHandler(exp_log_path, mode='w') # Overwrite exp log each run
    exp_formatter = logging.Formatter('%(asctime)s - %(message)s') # Keep simple format
    exp_file_handler.setFormatter(exp_formatter)
    exp_logger.addHandler(exp_file_handler)
    exp_logger.setLevel(logging.DEBUG)
    exp_logger.propagate = False

    # Configure interesting mutations logger (detailed JSON)
    interesting_log_path = os.path.join(run_output_dir, 'interesting_mutations.jsonl')
    # Remove existing handlers from interesting_logger before adding new ones
    for handler in interesting_logger.handlers[:]:
        interesting_logger.removeHandler(handler)
    interesting_file_handler = logging.FileHandler(interesting_log_path, mode='w') # Overwrite log each run
    interesting_formatter = logging.Formatter('%(message)s') # Log only the JSON message
    interesting_file_handler.setFormatter(interesting_formatter)
    interesting_logger.addHandler(interesting_file_handler)
    interesting_logger.setLevel(logging.DEBUG) # Capture all interesting events
    interesting_logger.propagate = False

    logging.info(f"Configured report logger to: {report_log_path}")
    logging.info(f"Configured experiment logger to: {exp_log_path}")
    logging.info(f"Configured interesting mutations logger to: {interesting_log_path}")
    # --- End Logging Config ---


    # --- Load Initial Seeds ---
    # Use config_path only if it was successfully loaded
    seed_file_path_cfg = config.get('seed_file_path', 'fuzzer/initial_seeds.jsonl') # Adjusted default path
    initial_seeds = load_seeds_from_jsonl(seed_file_path_cfg)
    if not initial_seeds:
        logging.critical("No initial seeds loaded. Cannot start fuzzing. Exiting.")
        return # Exit if no seeds could be loaded
    # --- End Seed Loading ---

    seed_queue = DjSeed(queue=initial_seeds) # Use loaded seeds
    # Pass loaded config to PowerSchedule
    power_schedule = DjPowerSchedule(config=config)
    # Mutator loads its own part of the config, pass the path
    # The use_constraints flag will be read from the loaded config inside the fuzzer __init__
    mutator = DjMutator(config_path=config_path if config_path else "fuzzer/fuzzer_config.yaml")
    is_interesting = DjIsInteresting()

    # Pass the instantiated components and config path/run_id to the fuzzer
    fuzzer = DjGreyboxFuzzer(
        seed=seed_queue,
        power_schedule=power_schedule,
        is_interesting=is_interesting,
        config_path=config_path if config_path else "fuzzer/fuzzer_config.yaml", # Pass original path or default
        run_id=run_id
    )

    try:
        fuzzer.run()
    except KeyboardInterrupt:
        logging.info("Fuzzing interrupted by user (main).")
        # Cleanup should be handled by fuzzer's finally block
    except Exception as e:
        logging.critical(f"Unhandled exception in main: {e}", exc_info=True)
    finally:
         # Explicitly stop server here as a final safety net
        if 'fuzzer' in locals() and hasattr(fuzzer, 'stop_server') and fuzzer.server_process:
            logging.info("Ensuring server is stopped from main finally block.")
            fuzzer.stop_server()
        logging.info("Main function finished.")


if __name__ == "__main__":
    # Add traceback import for logging exceptions in the main loop and final summary
    import traceback
    main()
