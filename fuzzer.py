import logging

import os
import yaml
import argparse
import asyncio  # Ensure async operations work

import fuzzer.DjangoGreyboxFuzzer as Dj

import fuzzer.SmartlockGreyboxFuzzer as Sl


def run_django_fuzzer(config_path, run_id):
    # --- Load Config First ---
    config = {}
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}
            logging.info(f"Main loaded configuration from: {config_path}")
        else:
            logging.warning(
                f"Main: Fuzzer configuration file not found at {config_path}. Using defaults."
            )
            config_path = None  # Indicate default config wasn't found
    except yaml.YAMLError as e:
        logging.error(
            f"Main: Error parsing YAML configuration file {config_path}: {e}. Using defaults."
        )
        config_path = None
    except Exception as e:
        logging.error(
            f"Main: Error loading configuration file {config_path}: {e}. Using defaults."
        )
        config_path = None
    # --- End Config Loading ---

    # --- Configure Logging (Now with run_id and output_dir) ---
    # Determine output directory based on config (if loaded) or default structure
    output_base_dir_cfg = config.get("output_base_dir", "./evaluation_runs/default/")
    run_output_dir = os.path.join(output_base_dir_cfg, run_id)
    os.makedirs(run_output_dir, exist_ok=True)

    # Configure root logger (basic info)
    report_log_path = os.path.join(run_output_dir, "fuzz_report.log")
    # Remove existing handlers before adding new ones
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        filename=report_log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode="w",  # Overwrite report log each run
    )

    # Configure experiment logger (detailed JSON)
    exp_log_path = os.path.join(run_output_dir, "fuzz_exp.jsonl")
    # Remove existing handlers from exp_logger before adding new ones
    for handler in Dj.exp_logger.handlers[:]:
        Dj.exp_logger.removeHandler(handler)
    exp_file_handler = logging.FileHandler(
        exp_log_path, mode="w"
    )  # Overwrite exp log each run
    exp_formatter = logging.Formatter("%(asctime)s - %(message)s")  # Keep simple format
    exp_file_handler.setFormatter(exp_formatter)
    Dj.exp_logger.addHandler(exp_file_handler)
    Dj.exp_logger.setLevel(logging.DEBUG)
    Dj.exp_logger.propagate = False

    # Configure interesting mutations logger (detailed JSON)
    interesting_log_path = os.path.join(run_output_dir, "interesting_mutations.jsonl")
    # Remove existing handlers from interesting_logger before adding new ones
    for handler in Dj.interesting_logger.handlers[:]:
        Dj.interesting_logger.removeHandler(handler)
    interesting_file_handler = logging.FileHandler(
        interesting_log_path, mode="w"
    )  # Overwrite log each run
    interesting_formatter = logging.Formatter(
        "%(message)s"
    )  # Log only the JSON message
    interesting_file_handler.setFormatter(interesting_formatter)
    Dj.interesting_logger.addHandler(interesting_file_handler)
    Dj.interesting_logger.setLevel(logging.DEBUG)  # Capture all interesting events
    Dj.interesting_logger.propagate = False

    logging.info(f"Configured report logger to: {report_log_path}")
    logging.info(f"Configured experiment logger to: {exp_log_path}")
    logging.info(f"Configured interesting mutations logger to: {interesting_log_path}")
    # --- End Logging Config ---

    # --- Load Initial Seeds ---
    # Use config_path only if it was successfully loaded
    seed_file_path_cfg = config.get(
        "seed_file_path", "DjangoWebApplication/fuzzer/initial_seeds.jsonl"
    )
    initial_seeds = Dj.load_seeds_from_jsonl(seed_file_path_cfg)
    if not initial_seeds:
        logging.critical("No initial seeds loaded. Cannot start fuzzing. Exiting.")
        return  # Exit if no seeds could be loaded
    # --- End Seed Loading ---

    seed_queue = Dj.DjSeed(queue=initial_seeds)  # Use loaded seeds
    # Pass loaded config to PowerSchedule
    power_schedule = Dj.DjPowerSchedule(config=config)
    # Mutator loads its own part of the config, pass the path
    # The use_constraints flag will be read from the loaded config inside the fuzzer __init__
    mutator = Dj.DjMutator(
        config_path=config_path if config_path else "fuzzer_config.yaml"
    )  # Pass original path or default
    is_interesting = Dj.DjIsInteresting()

    # Pass the instantiated components and config path/run_id to the fuzzer
    fuzzer = Dj.DjGreyboxFuzzer(
        seed=seed_queue,
        power_schedule=power_schedule,
        is_interesting=is_interesting,
        config_path=(
            config_path if config_path else "fuzzer_config.yaml"
        ),  # Pass original path or default
        run_id=run_id,
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
        if (
            "fuzzer" in locals()
            and hasattr(fuzzer, "stop_server")
            and fuzzer.server_process
        ):
            logging.info("Ensuring server is stopped from main finally block.")
            fuzzer.stop_server()
        logging.info("Main function finished.")


def run_ble_fuzzer(config_path, run_id):
    # --- Load Config First ---
    config = {}
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}
            logging.info(f"Main (BLE): Loaded configuration from: {config_path}")
        else:
            logging.warning(
                f"Main (BLE): Fuzzer configuration file not found at {config_path}. Using defaults."
            )
            config_path = None  # Indicate default config wasn't found
    except yaml.YAMLError as e:
        logging.error(
            f"Main (BLE): Error parsing YAML configuration file {config_path}: {e}. Using defaults."
        )
        config_path = None
    except Exception as e:
        logging.error(
            f"Main (BLE): Error loading configuration file {config_path}: {e}. Using defaults."
        )
        config_path = None
    # --- End Config Loading ---

    # --- Configure Logging (Now with run_id and output_dir) ---
    # Determine output directory based on config (if loaded) or default structure
    output_base_dir_cfg = config.get(
        "output_base_dir", "./evaluation_runs/smartlock/default/"
    )  # Default for smartlock
    run_output_dir = os.path.join(output_base_dir_cfg, run_id)
    os.makedirs(run_output_dir, exist_ok=True)

    # Configure root logger for general info (similar to Django)
    report_log_path = os.path.join(run_output_dir, "smartlock_report.log")
    # Remove existing handlers before adding new ones to avoid duplication if run multiple times
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        filename=report_log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode="w",  # Overwrite report log each run
    )
    logging.info(f"Configured report logger to: {report_log_path}")

    # Configure the specific logger used within SmartlockGreyboxFuzzer.py
    # Redirect its output to the run-specific directory
    smartlock_log_path = os.path.join(
        run_output_dir, "smartlock_fuzzer.log"
    )  # Specific log for the fuzzer run
    sl_logger = (
        logging.getLogger()
    )  # Get the root logger, as Smartlock fuzzer uses basicConfig/logging directly

    # Remove the default handler if it exists (the one created in SmartlockGreyboxFuzzer)
    # This is tricky as it's added *inside* the Sl.run_fuzzer call.
    # A better approach would be to pass the logger or config to Sl.run_fuzzer.
    # For now, we'll set up the main report log here, and the Sl fuzzer will *also* log to its default file.
    # TODO: Refactor SmartlockGreyboxFuzzer to accept logger configuration.

    # Configure the specific logger used within SmartlockGreyboxFuzzer.py
    # Redirect its output to the run-specific directory
    smartlock_fuzzer_logger = logging.getLogger(
        "fuzzer.SmartlockGreyboxFuzzer"
    )  # Get the specific logger instance
    # Remove existing handlers from smartlock_fuzzer_logger before adding new ones
    for handler in smartlock_fuzzer_logger.handlers[:]:
        smartlock_fuzzer_logger.removeHandler(handler)

    smartlock_log_path = os.path.join(
        run_output_dir, "smartlock_fuzzer.log"
    )  # Specific log for the fuzzer run
    smartlock_file_handler = logging.FileHandler(
        smartlock_log_path, mode="w"
    )  # Overwrite log each run
    smartlock_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    smartlock_file_handler.setFormatter(smartlock_formatter)
    smartlock_fuzzer_logger.addHandler(smartlock_file_handler)
    smartlock_fuzzer_logger.setLevel(logging.INFO)  # Set level as needed

    # Configure unique errors logger
    unique_errors_log_path = os.path.join(
        run_output_dir,
        config.get(
            "unique_errors_file", "unique_errors_smartlock.jsonl"
        ),  # Use config value
    )
    unique_errors_logger = logging.getLogger(
        "fuzzer.SmartlockGreyboxFuzzer.unique_errors"
    )  # A dedicated logger for unique errors
    for handler in unique_errors_logger.handlers[:]:
        unique_errors_logger.removeHandler(handler)
    unique_errors_file_handler = logging.FileHandler(
        unique_errors_log_path, mode="w"
    )  # Overwrite log each run
    unique_errors_formatter = logging.Formatter(
        "%(message)s"
    )  # Log only the JSON message
    unique_errors_file_handler.setFormatter(unique_errors_formatter)
    unique_errors_logger.addHandler(unique_errors_file_handler)
    unique_errors_logger.setLevel(logging.INFO)  # Capture unique errors

    logging.info(f"Configured Smartlock fuzzer logger to: {smartlock_log_path}")
    logging.info(f"Configured unique errors logger to: {unique_errors_log_path}")
    # --- End Logging Config ---

    logging.info(f"Starting Smartlock fuzzer for run_id: {run_id}")
    try:
        # Pass config and run_output_dir to the fuzzer function
        asyncio.run(Sl.run_fuzzer(config, run_output_dir))
    except KeyboardInterrupt:
        logging.info("Smartlock fuzzing interrupted by user (main).")
    except Exception as e:
        logging.critical(f"Unhandled exception in main (BLE): {e}", exc_info=True)
    finally:
        logging.info(f"Smartlock fuzzer run {run_id} finished.")


def main() -> None:
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Run Django Greybox Fuzzer with specific configuration."
    )
    # "django" or "ble"
    parser.add_argument(
        "--target",
        type=str,
        default="django",
        help="Target of fuzzing",
    )
    parser.add_argument(
        "--config",
        type=str,
        # Default is now conditional based on target, handled below
        # default="fuzzer/fuzzer_config.yaml", # Removed fixed default
        help="Path to the YAML configuration file. Defaults depend on the target.",
    )
    parser.add_argument(
        "--run_id",
        type=str,
        default="run_0",
        help="Identifier for this specific run (used for output directory).",
    )
    args = parser.parse_args()
    target = args.target
    config_path_arg = args.config  # Store the argument value
    run_id = args.run_id
    # --- End Argument Parsing ---

    # Determine default config path based on target if not provided
    if config_path_arg:
        config_path = config_path_arg
    elif target == "django":
        config_path = "fuzzer/fuzzer_config_full_django.yaml"  # Default for Django
        print(f"No --config specified, using default for Django: {config_path}")
    elif target == "ble":
        config_path = "fuzzer/fuzzer_config_smartlock.yaml"  # Default for BLE
        print(f"No --config specified, using default for BLE: {config_path}")
    else:
        print("Error: Target flag must be 'django' or 'ble'.")
        return  # Exit if target is invalid

    # Check if the determined config path exists before proceeding
    if not os.path.exists(config_path):
        print(
            f"Error: Configuration file not found at specified/default path: {config_path}"
        )
        return  # Exit if config file doesn't exist

    if target == "django":
        print(f"Running Django fuzzer with config: {config_path}, run_id: {run_id}")
        run_django_fuzzer(config_path, run_id)
    elif target == "ble":
        print(f"Running BLE fuzzer with config: {config_path}, run_id: {run_id}")
        run_ble_fuzzer(config_path, run_id)
    # The 'else' for invalid target is handled above


if __name__ == "__main__":
    # Add traceback import for logging exceptions in the main loop and final summary
    import traceback

    main()
