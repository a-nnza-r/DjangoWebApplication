import argparse
import subprocess
import os
import glob
import logging
from pathlib import Path
import time
import threading # Import threading module
import yaml # Import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s') # Added threadName

def run_experiment(fuzzer_script, config_path, run_id, target_name):
    """
    Runs a single fuzzer experiment instance.

    Args:
        fuzzer_script (str): Path to the fuzzer script.
        config_path (str): Path to the configuration file for this run.
        run_id (str): Identifier for this specific run (e.g., 'run_1').
        target_name (str): Name of the target application (e.g., 'django').
    """
    # --- Determine Output Directory from Config ---
    run_specific_output_dir = None
    config_name_for_log = Path(config_path).stem # Fallback name for logging
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
        output_base_dir_from_config = config_data.get('output_base_dir')
        config_name_for_log = config_data.get('experiment_name', config_name_for_log) # Use experiment name if available

        if output_base_dir_from_config:
            # Construct the full path for this specific run
            run_specific_output_dir = Path(output_base_dir_from_config) / run_id
        else:
            logging.warning(f"Could not find 'output_base_dir' in {config_path}. Falling back to filename-based dir.")
            # Fallback logic (less ideal, but prevents crashing)
            config_name_stem = Path(config_path).stem.replace('fuzzer_config_', '').replace(f'_{target_name}', '')
            run_specific_output_dir = Path('evaluation_runs') / target_name / config_name_stem / run_id

    except Exception as e:
        logging.error(f"Error reading output_base_dir from {config_path}: {e}. Falling back to filename-based dir.")
        # Fallback logic
        config_name_stem = Path(config_path).stem.replace('fuzzer_config_', '').replace(f'_{target_name}', '')
        run_specific_output_dir = Path('evaluation_runs') / target_name / config_name_stem / run_id

    # Ensure the directory exists
    run_specific_output_dir.mkdir(parents=True, exist_ok=True)
    # --- End Determine Output Directory ---

    # Construct the command to run the fuzzer
    command = [
        'python',
        fuzzer_script,
        '--config',
        config_path,
        '--run_id',
        run_id,
    ]

    # Use config_name_for_log derived from config if possible
    logging.info(f"Starting experiment: Config={config_name_for_log}, Run={run_id}, Target={target_name}")
    logging.info(f"Command: {' '.join(command)}")
    logging.info(f"Fuzzer output directory (from config): {run_specific_output_dir}")

    # Define log file paths within the run-specific directory for the runner's logs
    runner_stdout_log_path = run_specific_output_dir / 'runner_stdout.log'
    runner_stderr_log_path = run_specific_output_dir / 'runner_stderr.log'

    start_time = time.time()
    try:
        # Open runner log files for writing
        with open(runner_stdout_log_path, 'w') as stdout_log, open(runner_stderr_log_path, 'w') as stderr_log:
            # Run the fuzzer as a subprocess
            process = subprocess.Popen(
                command,
                stdout=stdout_log, # Capture fuzzer's stdout
                stderr=stderr_log, # Capture fuzzer's stderr
                text=True,
                cwd=os.getcwd() # Run fuzzer from the project root
            )
            process.wait() # Wait for the fuzzer process to complete
        end_time = time.time()
        duration = end_time - start_time
        if process.returncode == 0:
            logging.info(f"Experiment completed successfully: Config={config_name_for_log}, Run={run_id}. Duration: {duration:.2f} seconds.")
        else:
            # Fuzzer logs its own errors to its specific files. Runner logs fuzzer exit status.
            logging.error(f"Experiment process finished with non-zero exit code: Config={config_name_for_log}, Run={run_id}. Return code: {process.returncode}. Duration: {duration:.2f} seconds.")
            logging.error(f"Check fuzzer logs in {run_specific_output_dir} and runner stderr log: {runner_stderr_log_path}")

    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        logging.error(f"Exception occurred while running/monitoring experiment: Config={config_name_for_log}, Run={run_id}. Duration: {duration:.2f} seconds.", exc_info=True)
        # Log the exception to the runner's stderr log
        # Ensure the directory exists before trying to write the error log
        run_specific_output_dir.mkdir(parents=True, exist_ok=True)
        with open(runner_stderr_log_path, 'a') as stderr_log:
             stderr_log.write(f"\nRunner script exception during Popen/wait: {e}\n")


def main():
    parser = argparse.ArgumentParser(description="Run fuzzer experiments based on configuration files.")
    parser.add_argument('--fuzzer-script', required=True, help="Path to the fuzzer script (e.g., DjangoWebApplication/fuzzer/DjangoGreyboxFuzzer.py)")
    parser.add_argument('--config-pattern', required=True, help="Glob pattern for configuration files (e.g., 'DjangoWebApplication/fuzzer/fuzzer_config_*_django.yaml')")
    parser.add_argument('--target-name', required=True, help="Name of the target application (e.g., 'django')")
    parser.add_argument('--repetitions', type=int, default=5, help="Number of times to repeat each experiment configuration.")

    args = parser.parse_args()

    # Find configuration files matching the pattern
    config_files = glob.glob(args.config_pattern)
    if not config_files:
        logging.error(f"No configuration files found matching pattern: {args.config_pattern}")
        return

    logging.info(f"Found {len(config_files)} configuration files matching '{args.config_pattern}'.")
    logging.info(f"Will run {args.repetitions} repetitions. Each repetition runs {len(config_files)} configurations concurrently.")

    # Outer loop for repetitions
    for i in range(1, args.repetitions + 1):
        run_id = f"run_{i}"
        logging.info(f"--- Starting Repetition {i}/{args.repetitions} ---")
        threads_for_repetition = []

        # Inner loop to start one thread per configuration for this repetition
        for config_path in sorted(config_files):
            config_name_short = Path(config_path).stem.replace('fuzzer_config_', '').replace(f'_{args.target_name}', '')
            thread_name = f"{config_name_short}-{run_id}"
            logging.info(f"Preparing {thread_name} (Config: {config_path})")

            thread = threading.Thread(
                target=run_experiment,
                args=(args.fuzzer_script, config_path, run_id, args.target_name),
                name=thread_name
            )
            threads_for_repetition.append(thread)
            logging.info(f"Starting thread: {thread.name}")
            thread.start()
            # Optional small delay if needed
            # time.sleep(0.2)

        # Wait for all threads *for this repetition* to complete
        logging.info(f"Waiting for {len(threads_for_repetition)} threads in Repetition {i} to complete...")
        for thread in threads_for_repetition:
            thread.join()
            logging.info(f"Thread {thread.name} finished.")

        logging.info(f"--- Repetition {i}/{args.repetitions} Completed ---")
        logging.info("-" * 60) # Separator between repetitions

    logging.info("All experiment repetitions completed.")

if __name__ == "__main__":
    main()
    # example command:
    #python run_experiments.py --fuzzer-script fuzzer/DjangoGreyboxFuzzer.py --config-pattern 'fuzzer/fuzzer_config_*_django.yaml' --target-name django --repetitions 1
