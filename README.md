# Setup

1. Create new env by `python -m venv .venv`
2. Activate env by `.venv\Scripts\activate` or (bash/zsh: `source .venv/bin/activate`)
3. Run `pip install -r requirements.txt`
4. To fuzz django, run `python -m fuzzer.DjangoGreyboxFuzzer`
5. To fuzz smart lock, run `python -m fuzzer.SmartlockGreyboxFuzzer`. Press `Ctrl+C` to stop the script.

# Fuzzing and Experimentation

This project includes greybox fuzzers for the Django application and a Smart Lock target.

## Fuzzer Scripts

*   `fuzzer/DjangoGreyboxFuzzer.py`: Fuzzer specifically designed for the Django web application target.
*   `fuzzer/SmartlockGreyboxFuzzer.py`: Fuzzer for the Smart Lock target.

## Configuration Files

The behavior of the fuzzers is controlled by YAML configuration files located in the `fuzzer/` directory (e.g., `fuzzer/fuzzer_config_full_django.yaml`). These files allow you to customize various aspects of the fuzzing process, including:

*   **Experiment Settings:** `experiment_name`, `target_name`, `output_base_dir` (where results are stored), `run_duration_hours`.
*   **Fuzzer Features:** Enable/disable features like `use_coverage_feedback`, `use_constraint_mutation`, `use_seed_prioritization`.
*   **Fuzzer Parameters:** `target_endpoint`, `max_iterations`, `request_timeout`, `seed_file_path`, etc.
*   **Target Execution:** How to run the target application (`target_script`, `target_args`) and configure coverage (`coverage_source`, `coverage_data_file`).
*   **Input Structure:** Define the expected format and constraints (`input_structure`) for the data sent to the target API.

## Initial Seeds

The fuzzer starts with initial inputs provided in `fuzzer/initial_seeds.jsonl`. This file contains JSON objects, one per line, representing valid or interesting starting requests.

## Running a Single Fuzzer Instance

You can run a fuzzer directly using a specific configuration file. This is useful for testing a single configuration or debugging.

```bash
# Example for Django fuzzer with the 'full' configuration
python -m fuzzer.DjangoGreyboxFuzzer --config fuzzer/fuzzer_config_full_django.yaml
```

The fuzzer will run based on the settings in the specified YAML file. Output (logs, errors, coverage data) will typically be placed in a directory defined by `output_base_dir` within the config file, often combined with a `run_id` if provided.

## Running Experiments

The `run_experiments.py` script automates the process of running the fuzzer with multiple configurations and repetitions.

**Usage:**

```bash
python run_experiments.py --fuzzer-script <path_to_fuzzer> --config-pattern <pattern_for_configs> --target-name <target> --repetitions <num_repetitions>
```

**Arguments:**

*   `--fuzzer-script`: Path to the fuzzer script (e.g., `fuzzer/DjangoGreyboxFuzzer.py`).
*   `--config-pattern`: Glob pattern to find the configuration files to use (e.g., `'fuzzer/fuzzer_config_*_django.yaml'`). Remember to use quotes around patterns with wildcards.
*   `--target-name`: A name for the target application (e.g., `django`), used for organizing output directories if not fully specified in the config.
*   `--repetitions`: The number of times to repeat the fuzzing process for *each* configuration file found.

**Example:**

```bash
# Run the Django fuzzer with all 'django' configs, 5 times each
python run_experiments.py --fuzzer-script fuzzer/DjangoGreyboxFuzzer.py --config-pattern 'fuzzer/fuzzer_config_*_django.yaml' --target-name django --repetitions 5
```

The script will:
1.  Find all YAML files matching the `--config-pattern`.
2.  For each repetition (from 1 to `--repetitions`):
    *   Start a separate thread for each configuration file found.
    *   Run the specified `--fuzzer-script` with the corresponding `--config` file and a unique `run_id` (e.g., `run_1`, `run_2`).
3.  Outputs (runner logs, fuzzer logs, unique errors, coverage data) for each run are stored in subdirectories within the `output_base_dir` specified in the respective configuration file (e.g., `evaluation_runs/django/full/run_1/`, `evaluation_runs/django/random/run_1/`, etc.).
