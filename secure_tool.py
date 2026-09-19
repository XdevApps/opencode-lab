import sys
import subprocess


def secure_read(filename):
    result = subprocess.run(
        ["python3", "policy_gateway.py", "read", filename],
        capture_output=True,
        text=True
    )

    print(result.stdout, end="")

    if result.returncode != 0:
        print("ACCESS BLOCKED")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "read":
        print("Usage: python3 secure_tool.py read <filename>")
        sys.exit(1)

    secure_read(sys.argv[2])
