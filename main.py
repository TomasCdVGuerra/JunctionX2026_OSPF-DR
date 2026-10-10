# Purpose:
# Primary CLI application entrypoint invoking the QuantumTrace scanner pipeline.
#
# Responsibilities:
# - Validate Python 3.12 runtime environment.
# - Dispatch command line execution directly to scanner.cli.main().
# - Propagate standard process exit codes to the invoking shell.
#
# Planned interface:
# - if __name__ == "__main__": executes sys.exit(scanner.cli.main()).
#
# Rules and edge cases:
# - Must remain lightweight and delegate all operational logic to scanner.cli.
# - Ensure keyboard interrupts (Ctrl+C) exit cleanly without printing raw stack traces.
#
# Scoring link:
# - Usability and demo (15%): Provides an expected, standard python main.py invocation entrypoint.
