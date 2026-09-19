import json
import subprocess
import sys
import os

POLICY_FILE = "policy.json"
SANDBOX_DIR = "./sandbox"

CPU_LIMIT = "0.25"
MEMORY_LIMIT = "64m"


def load_policy():
    with open(POLICY_FILE, "r") as f:
        return json.load(f)


def is_allowed(filename, action):
    policy = load_policy()

    permissions = policy.get("permissions", {})
    file_permission = permissions.get(filename)

    if file_permission is None:
        return False

    return file_permission.get(action) is True


def read_file(filename):

    path = os.path.join(SANDBOX_DIR, filename)

    if os.path.islink(path):
        print(f"DENY: SYMLINK {filename}")
        sys.exit(1)

    if not is_allowed(filename, "read"):
        print(f"DENY: READ {filename}")
        sys.exit(1)


    result = subprocess.run(
        [
            "docker",
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
            "-v",
            f"{SANDBOX_DIR}:/workspace:ro",
            "alpine:3.22",
            "cat",
            f"/workspace/{filename}",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("DENY: sandbox execution failed")
        sys.exit(1)

    print(f"ALLOW: READ {filename}")
    print(result.stdout, end="")


def write_file(filename, content):

    if filename != os.path.basename(filename) or "/" in filename or "\\" in filename:
        print(f"DENY: INVALID FILENAME {filename}")
        sys.exit(1)

    path = os.path.join(SANDBOX_DIR, filename)

    if os.path.islink(path):
        print(f"DENY: SYMLINK {filename}")
        sys.exit(1)

    if not is_allowed(filename, "write"):
        print(f"DENY: WRITE {filename}")
        sys.exit(1)

    target = f"/workspace/{filename}"

    result = subprocess.run(
        [
            "docker",
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
            "-i",
            "-v",
            f"{SANDBOX_DIR}:/workspace:rw",
            "alpine:3.22",
            "tee",
            target,
        ],
        input=content,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("DENY: sandbox execution failed")
        print(result.stderr, end="")
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