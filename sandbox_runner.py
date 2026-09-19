import subprocess
import sys


SANDBOX_DIR = "./sandbox"


def run_in_sandbox(command):
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            f"{SANDBOX_DIR}:/workspace",
            "alpine:3.22",
            "sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
    )

    print(result.stdout, end="")

    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    return result.returncode


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sandbox_runner.py '<command>'")
        sys.exit(1)

    command = " ".join(sys.argv[1:])
    sys.exit(run_in_sandbox(command))
