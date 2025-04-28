

# Fuzzer Design & Implementation Summary (Django Target - As of Version)

## Design Overview

*   **Architecture:** Python-based Greybox Fuzzer (`DjangoGreyboxFuzzer.py`).
*   **Goal:** Find bugs (crashes, hangs, errors) in target applications, initially focusing on a Django web application accessed via HTTP.
*   **Core Principle:** Coverage-guided fuzzing using feedback from target execution.
*   **Abstraction:** Built upon abstract base classes (`abstractUpdated.py`) for core components (Seed, Mutator, PowerSchedule, IsInteresting, Fuzzer) to facilitate future extension (e.g., for BLE target).

## Design Details & Key Choices

*   **Coverage Mechanism:**
    *   **Choice:** AFL-style edge coverage (arc coverage via `coverage.py`) with hit count bucketing (`_count_to_bucket_index`, `DjIsInteresting`).
    *   **Reasoning:** Provides finer-grained feedback than simple path hashing, potentially leading to better exploration of state space and bug discovery, inspired by proven techniques in AFL.
    *   **Implementation:** Uses `coverage.py` library to instrument and collect data from the target Python script run as a subprocess. Global map (`global_coverage_map`) stores the highest bucket index seen per arc.
    *   **Challenge:** Current implementation struggles with reliably loading/combining coverage data between runs (`.coverage_seqlog`).
*   **Execution Model:**
    *   **Choice:** Sequential execution (`DjangoGreyboxFuzzer.py`). Target application runs in a separate subprocess.
    *   **Reasoning:** Simplifies coverage collection per mutation compared to earlier concurrent models (`ThreadPoolExecutor`) which faced challenges with `coverage.py` in threads. Allows for stopping/restarting the target to gather coverage after each input.
    *   **Implementation:** Uses `subprocess.Popen` to start the target script (defined in config) under `coverage run`. Sends HTTP request via `requests`. Stops/restarts the target process for each mutation.
*   **Feedback Loop:**
    *   **Seed Selection (`DjSeed.chooseNext`):** AFL-inspired strategy prioritizing seeds selected less often (`s` counter) and those that haven't failed often (`f` counter).
    *   **Energy Assignment (`DjPowerSchedule`):** AFL-inspired exponential energy calculation based on `s` and `f` counters, rewarding seeds that lead to interesting results and penalizing unproductive ones. Configurable base energy (`energy_const`) and max energy (`max_energy`).
    *   **Interestingness (`DjIsInteresting`):** An input is considered interesting if it discovers new arcs or hits existing arcs with a count that falls into a higher AFL-style bucket. Interesting inputs are added back to the seed queue.
*   **Mutation (`DjMutator`):**
    *   **Choice:** Constraint-aware mutation where possible, falling back to general techniques.
    *   **Reasoning:** Aims to generate more valid and potentially deeper inputs by respecting basic type/length constraints defined in the configuration, while still allowing for boundary/injection tests.
    *   **Implementation:** Reads `input_structure` from `fuzzer_config.yaml`. Applies type-specific mutations (int, float, string) considering constraints (min/max length/value). Includes common strategies like bit/byte flips, arithmetic ops, extreme values, SQLi/XSS patterns, etc. This approach simplifies the fuzzing process, particularly when the target application performs initial input validation or parsing. By generating inputs that are more likely to pass these initial checks, constraint-aware mutation helps focus the fuzzer's efforts on the core application logic (the System Under Test - SUT) rather than repeatedly generating inputs that are immediately rejected by the parser. This can lead to more efficient discovery of deeper bugs within the SUT itself.
*   **Configuration:**
    *   **Choice:** Externalize all key settings and initial inputs.
    *   **Reasoning:** Improve usability and flexibility, allowing testers to adapt the fuzzer without code changes.
    *   **Implementation:** Uses YAML (`fuzzer_config.yaml`) for parameters (target endpoint, limits, energy, target command, seed path, etc.) and JSON Lines (`initial_seeds.jsonl`) for initial seeds.
*   **Error/Bug Detection:**
    *   **Choice:** Monitor for common failure modes: crashes, hangs/timeouts, HTTP errors.
    *   **Reasoning:** Cover typical web application failure scenarios.
    *   **Implementation:**
        *   Crashes: `subprocess.poll()` checks before/after requests.
        *   Timeouts: `requests` library timeout, supplemented by `psutil` memory check during timeout investigation to detect potential memory DoS.
        *   HTTP Errors: Checks `response.status_code >= 400`.
        *   Logging: Detected bugs stored in `self.bugs` list and logged to `fuzz_report_seqlog.log` and structured `fuzz_exp_seqlog.log`. Unique errors (differentiated by error type, key details, and path hash) are stored in `self.unique_error_details` and saved to a configured JSON Lines file (`unique_errors.jsonl` by default) at the end of the run.
    *   **Path Hash Attribution for Unique Errors:** A key objective is to associate each unique error with the specific code path exercised by the input that triggered it. This is achieved by computing a path hash based on the sequence and hit counts (bucketed) of coverage arcs. However, attributing the correct path hash presents challenges depending on when the error is detected relative to coverage measurement:
        *   **Challenge:** The path hash for a given `mutated_input` can only be computed *after* its execution completes (or terminates) and the corresponding coverage data is processed. Errors detected *during* the execution (e.g., timeouts, HTTP errors within `send_request`) occur before this path hash is available.
        *   **Attribution Strategy:**
            *   *Crashes (Pre-Mutation):* If the server crashes *before* processing the current `mutated_input`, the crash is attributed to the state left by the `last_successful_input`. The path hash associated with this error is `last_successful_input_path_hash`.
            *   *Errors During Request (Timeout, HTTP Error, Connection Error, etc.):* For errors detected within the `send_request` function (i.e., during the processing of `mutated_input`), the exact path hash for this input is not yet known. As the best available approximation, these errors are associated with the `last_successful_input_path_hash`, providing context based on the presumed state leading into the failing request.
            *   *Successful Execution:* If `send_request` completes and the server remains stable, the `mutation_path_hash` is calculated from the collected coverage. If the execution was successful (e.g., 2xx/3xx response), `last_successful_input_path_hash` is updated to this `mutation_path_hash`.
            *   *Crashes (Post-Mutation):* If the server crashes *after* `send_request` completes but *before* the next mutation begins (detected in the main `run` loop), the crash is directly attributed to the `mutated_input` just processed. The path hash associated with this crash is the `mutation_path_hash` computed from the coverage data collected during that specific run (even if coverage collection itself encountered issues, resulting in placeholder hashes like "COVERAGE_ERROR").
        *   **Implementation:** This refined attribution logic is implemented within the `send_request` and `run` methods via the `_log_unique_error` helper function. This function ensures that the `path_hash` field in the `bug_report` dictionary reflects the most accurate path context available at the time of error detection. Crucially, if the determined `path_hash` is identified as a placeholder string (e.g., "N/A_POST_CRASH", "COVERAGE_ERROR", "FUZZER_LOOP", etc., indicating unavailable or unreliable path information), the error instance is *always* added to the `unique_error_details` list, bypassing the standard signature-based uniqueness check. This ensures that all errors occurring under conditions where the exact path cannot be determined are captured for analysis. If the `path_hash` is a valid hash, the standard uniqueness check based on the signature `(error_type, details_key, path_hash)` is performed against the `self.unique_errors` set before adding the error details.
    *   **Challenge:** The reliability of coverage data collection itself remains a primary concern, potentially impacting the accuracy of path hashes, especially in crash scenarios. The strategy of logging all instances with placeholder hashes mitigates data loss when coverage fails but may lead to a higher volume of reported unique errors requiring manual inspection.

## Empirical Evaluation Setup & Execution

*   **Goal:** Evaluate the effectiveness and efficiency of different fuzzer configurations based on the RQs in `empirical evaluation.docx` and the plan in `evaluationPlan.md`.
*   **Configurations & Feature Flags:**
    *   `full`: All features enabled.
        *   `use_coverage_feedback=true`: Interesting inputs (new path/bucket) are added to the seed queue.
        *   `use_constraint_mutation=true`: Mutator uses type/length constraints defined in `input_structure`.
        *   `use_seed_prioritization=true`: Dynamic energy is assigned to seeds based on performance (s/f counters) via `DjPowerSchedule`.

    *   `no_coverage`: Disables coverage feedback loop (`use_coverage_feedback=false`, `use_seed_prioritization=false`) but keeps constraint mutation (`use_constraint_mutation=true`). Tests the impact of coverage guidance.
    *   `no_prioritization`: Disables dynamic energy assignment (`use_seed_prioritization=false`) but keeps coverage feedback for adding seeds (`use_coverage_feedback=true`) and constraint mutation (`use_constraint_mutation=true`). Tests the impact of the power schedule.
*   **Execution Strategy:**
    *   **Runner Script (`run_experiments.py`):** Automates the execution process.
    *   **Concurrency:** Runs the different configurations (`full`, `no_coverage`, `no_prioritization`) concurrently for each repetition round, leveraging the fact that each configuration uses a different target server port (8000, 8002, 8004).
    *   **Repetitions:** Executes 5 repetitions for each configuration to assess stability and allow for statistical analysis.
    *   **Duration:** Initial test runs set to 10 minutes (0.17 hours) per fuzzer instance via the `run_duration_hours` config parameter.
*   **Logging & Data Collection:**
    *   **Run-Specific Directories:** Each run (config + repetition) logs to a unique directory (e.g., `evaluation_runs/django/full/run_1/`).
    *   **Standard Logs:** `fuzz_report.log` (general fuzzer status) and `fuzz_exp.jsonl` (detailed per-mutation data).
    *   **Unique Errors:** `unique_errors.jsonl` logs unique errors found.
    *   **Interesting Mutations:** `interesting_mutations.jsonl` logs inputs that triggered new paths or coverage buckets, along with timestamps and mutation counts, for analyzing discovery rate.
    *   **Coverage Data:** `.coverage_*` files are generated for each run, allowing post-run analysis even for configurations that don't use coverage for feedback (e.g., `random`, `no_coverage`).
*   **Refinements During Setup:**
    *   Added `interesting_mutations.jsonl` logging.
    *   Corrected fuzzer logic to ensure coverage data is always collected/logged when possible, but feedback mechanisms (adding seeds, dynamic energy) are correctly controlled by flags (`use_coverage_feedback`, `use_seed_prioritization`).
    *   Fixed bugs in mutator lambda functions and `hash_arcs_with_counts`.
    *   Refined `run_experiments.py` to handle output directories correctly based on config values.

## Empirical Evaluation Analysis Setup (Phase 3)

*   **Goal:** Create the structure for analyzing the results generated in Phase 2, based on the plan in `evaluationPlan.md`.
*   **Analysis Notebook (`evaluation_analysis.ipynb`):**
    *   Created the Jupyter Notebook `DjangoWebApplication/evaluation_analysis.ipynb`.
    *   Implemented a flexible `load_fuzzer_data` function to read `fuzz_exp_*.jsonl` files from specified run directories (initially `evaluation_runs-1_run/`), parse metadata from paths, and perform basic data cleaning/type conversion (timestamps, numerics, booleans, elapsed time).
    *   Added code cells with plots and calculations for the initial analysis based on the single repetition run:
        *   **RQ1 (Effectiveness):** Plots for cumulative unique bugs vs. time, cumulative interesting inputs vs. time, cumulative coverage (arcs) vs. time, and cumulative coverage vs. iterations.
        *   **RQ2 (Efficiency):** Calculations for time to first bug and average operation times (mutation/execution), with checks for required log fields.
        *   **RQ3 (Baseline Comparison):** Added markdown guidance explaining how to use the RQ1 plots for comparison.
        *   **RQ4 (Stability):** Added box plots for final bugs, interesting inputs, and coverage, structured to handle multiple runs (currently displaying single-run data).
    *   Included `TODO` comments for remaining tasks like detailed bug parsing and final interpretation based on full experimental results.
*   **Status:** The notebook is set up to perform the core analysis. Full interpretation and potentially more detailed analysis (e.g., specific bug types) are pending the execution of further repetitions (Phase 2 - Full Execution).

## Implementation Challenges (Current/Past)

*   **Coverage Data Handling:** Reliably collecting, combining, and loading coverage data from the target subprocess using `coverage.py` has been a major challenge, especially with process restarts. This is the **highest priority bug** to fix.
*   **Concurrency vs. Coverage:** Previous attempts using `ThreadPoolExecutor` made per-mutation coverage difficult with `coverage.py`. Led to the current sequential model, which introduces performance overhead due to process restarts but simplifies coverage logic (though still buggy).
*   **Error Detection Robustness:** Ensuring detection mechanisms (`poll`, `requests` timeout) are sufficient for all relevant bug types in the target environment.

## Future considerations

To make it truly general-purpose and capable of fuzzing imported functions from a package directly, significant refactoring would be necessary. Here's a potential approach:

Abstract Target Interaction: We could introduce an abstraction layer, perhaps a TargetExecutor base class.
HttpTargetExecutor: Would encapsulate the current logic (starting server, sending requests, stopping server).
FunctionTargetExecutor: Would take a reference to the target function, handle calling it directly with mutated inputs, and manage coverage (potentially using coverage.py's programmatic API if running in the same process, or wrapping a subprocess call).
Configuration: The fuzzer_config.yaml would need to specify the executor_type (e.g., http or function) and provide the relevant parameters (like target_endpoint for HTTP or target_module and target_function for direct calls).
Fuzzer Core Logic: The main run loop in DjGreyboxFuzzer would interact with the TargetExecutor interface, abstracting away the specifics of how the target is invoked and how results/coverage are obtained.
