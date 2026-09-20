import json
import subprocess
import sys
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

POLICY_FILE = BASE_DIR / "policy.json"
SANDBOX_DIR = BASE_DIR / "sandbox"
SANDBOX_ROOT = SANDBOX_DIR.resolve()

CPU_LIMIT = "0.25"
MEMORY_LIMIT = "64m"
PIDS_LIMIT = "64"
EXECUTION_TIMEOUT = 30
DOCKER_IMAGE = "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
DOCKER_BIN = "/usr/local/bin/docker"
TMP_SIZE = "10m"


def load_policy():
    try:
        with open(POLICY_FILE, "r") as f:
            policy = json.load(f)
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        print("DENY: POLICY ERROR")
        sys.exit(1)

    if not isinstance(policy, dict):
        print("DENY: INVALID POLICY SCHEMA")
        sys.exit(1)

    permissions = policy.get("permissions")

    if not isinstance(permissions, dict):
        print("DENY: INVALID POLICY SCHEMA")
        sys.exit(1)

    for filename, file_permission in permissions.items():
        if not isinstance(filename, str):
            print("DENY: INVALID POLICY SCHEMA")
            sys.exit(1)

        if not isinstance(file_permission, dict):
            print("DENY: INVALID POLICY SCHEMA")
            sys.exit(1)

        for action in ("read", "write"):
            if action in file_permission and not isinstance(
                file_permission[action], bool
            ):
                print("DENY: INVALID POLICY SCHEMA")
                sys.exit(1)

    return policy

def validate_filename(filename):
    if not filename:
        return False

    if filename in (".", ".."):
        return False

    if filename != os.path.basename(filename):
        return False

    if "/" in filename or "\\" in filename:
        return False

    for char in filename:
        if not (
            char.isalnum()
            or char in "._-"
        ):
            return False

    return True


def resolve_safe_path(filename):
    candidate = (SANDBOX_ROOT / filename).resolve(strict=False)

    try:
        candidate.relative_to(SANDBOX_ROOT)
    except ValueError:
        print(f"DENY: PATH OUTSIDE SANDBOX {filename}")
        sys.exit(1)

    return candidate


def is_allowed(filename, action):
    policy = load_policy()
    permissions = policy.get("permissions", {})
    file_permission = permissions.get(filename)

    if file_permission is None:
        return False

    return file_permission.get(action) is True


def _docker_sandbox_run(operation, filename, content=None):
    if operation == "read":
        volume_mode = "ro"
        container_command = [
            "cat",
            f"/workspace/{filename}",
        ]
        input_data = None

    elif operation == "write":
        volume_mode = "rw"
        container_command = [
            "tee",
            f"/workspace/{filename}",
        ]
        input_data = content

    else:
        return subprocess.CompletedProcess(
            [],
            returncode=1,
            stdout="",
            stderr="invalid sandbox operation",
        )

    docker_command = [
        DOCKER_BIN,
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "1000:1000",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--cpus={CPU_LIMIT}",
        f"--memory={MEMORY_LIMIT}",
        f"--pids-limit={PIDS_LIMIT}",
        f"--tmpfs=/tmp:rw,size={TMP_SIZE}",
    ]

    if input_data is not None:
        docker_command.append("-i")

    docker_command.extend(
        [
            "-v",
            f"{SANDBOX_ROOT}:/workspace:{volume_mode}",
            DOCKER_IMAGE,
        ]
    )

    docker_command.extend(container_command)

    try:
        return subprocess.run(
            docker_command,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=EXECUTION_TIMEOUT,
        )
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(
            docker_command,
            returncode=1,
            stdout="",
            stderr="sandbox execution error",
        )


def _docker_sandbox_read(filename):
    return _docker_sandbox_run("read", filename)

def read_file(filename):
    if not validate_filename(filename):
        print(f"DENY: INVALID FILENAME {filename}")
        sys.exit(1)

    raw_path = SANDBOX_ROOT / filename

    if raw_path.is_symlink():
        print(f"DENY: SYMLINK {filename}")
        sys.exit(1)

    path = resolve_safe_path(filename)


    if not is_allowed(filename, "read"):
        print(f"DENY: READ {filename}")
        sys.exit(1)

    result = _docker_sandbox_read(filename)

    if result.returncode != 0:
        print("DENY: sandbox execution failed")
        sys.exit(1)

    print(f"ALLOW: READ {filename}")
    print(result.stdout, end="")


def _docker_sandbox_write(filename, content):
    return _docker_sandbox_run("write", filename, content)

def write_file(filename, content):
    if not validate_filename(filename):
        print(f"DENY: INVALID FILENAME {filename}")
        sys.exit(1)

    raw_path = SANDBOX_ROOT / filename

    if raw_path.is_symlink():
        print(f"DENY: SYMLINK {filename}")
        sys.exit(1)

    path = resolve_safe_path(filename)


    if not is_allowed(filename, "write"):
        print(f"DENY: WRITE {filename}")
        sys.exit(1)

    target = f"/workspace/{filename}"

    result = _docker_sandbox_write(filename, content)

    if result.returncode != 0:
        print("DENY: sandbox execution failed")
        sys.exit(1)

    print(f"ALLOW: WRITE {filename}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 secure_sandbox.py read <filename>")
        print("  python3 secure_sandbox.py write <filename> <content>")
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]

    if action == "read" and len(sys.argv) == 3:
        read_file(filename)

    elif action == "write" and len(sys.argv) >= 4:
        content = " ".join(sys.argv[3:])
        write_file(filename, content)

    else:
        print("Invalid command")
        sys.exit(1)