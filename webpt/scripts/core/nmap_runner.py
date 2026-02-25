import subprocess


def run_nmap_all_ports(host: str, timeout_s: int = 1800) -> dict:
    # -p- all TCP ports, -sT for VM friendliness, -sV service detect, -Pn no ping dependency
    cmd = ["nmap", "-sT", "-sV", "-p-", "--reason", "-Pn", host]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return {"command": " ".join(cmd), "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
