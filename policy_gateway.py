import json
import os
import sys


POLICY_FILE = "policy.json"


def load_policy():
    with open(POLICY_FILE, "r") as f:
        return json.load(f)


def check_access(filename, action):
    policy = load_policy()

    permissions = policy.get("permissions", {})
    file_permission = permissions.get(filename)

    if file_permission is None:
        return False, "DENY"

    if file_permission.get(action) is True:
        return True, "ALLOW"

    return False, "DENY"


def read_file(filename):
    allowed, result = check_access(filename, "read")

    print(f"{result}: READ {filename}")

    if not allowed:
        sys.exit(1)

    with open(filename, "r") as f:
        content = f.read()

    print(content)


def write_file(filename, content):
    allowed, result = check_access(filename, "write")

    print(f"{result}: WRITE {filename}")

    if not allowed:
        sys.exit(1)

    with open(filename, "w") as f:
        f.write(content)

    print("File written successfully.")


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 policy_gateway.py read <filename>")
        print("  python3 policy_gateway.py write <filename> <content>")
        sys.exit(1)

    action = sys.argv[1]
    filename = os.path.basename(sys.argv[2])

    if action == "read":
        if len(sys.argv) != 3:
            print("Usage: python3 policy_gateway.py read <filename>")
            sys.exit(1)

        read_file(filename)

    elif action == "write":
        if len(sys.argv) != 4:
            print("Usage: python3 policy_gateway.py write <filename> <content>")
            sys.exit(1)

        content = sys.argv[3]
        write_file(filename, content)

    else:
        print(f"DENY: unsupported action '{action}'")
        sys.exit(1)


if __name__ == "__main__":
    main()