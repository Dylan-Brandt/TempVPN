#!/usr/bin/env python3
import boto3
import subprocess
import time
import os
import sys
import botocore.exceptions

REGION = "us-east-2"
STACK_NAME = "wireguard-vpn"
PROFILE = "vpn-controller"

WIREGUARD_CONFIG_PATH="C:\\Program Files\\WireGuard\\Data\\Configurations"
WIREGUARD_EXE = "C:\\Program Files\\WireGuard\\wireguard.exe"

def run_cmd(cmd: list):
    """Run a system command and return stdout/stderr/rc."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1


def uninstall_wireguard_tunnel(client_name: str):
    print(f"[+] Removing WireGuard tunnel for: {client_name}")

    out, err, code = run_cmd([WIREGUARD_EXE, "/uninstalltunnelservice", client_name])

    if code == 0:
        print("[✓] Tunnel removed from WireGuard.")
    else:
        print(f"[!] WireGuard removal error: {err}")
        print("[!] Continuing cleanup anyway.")

def delete_cloudformation_stack(stack_name: str):
    print(f"[+] Deleting CloudFormation stack: {stack_name}")

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    cf = session.client("cloudformation")

    cf.delete_stack(StackName=stack_name)

    print("[+] Waiting for stack deletion to complete...")
    waiter = cf.get_waiter("stack_delete_complete")

    try:
        waiter.wait(StackName=stack_name)
        print("[✓] Stack deletion successful.")
    except botocore.exceptions.WaiterError as e:
        print(f"[!] Error waiting for stack deletion: {e}")
        sys.exit(1)


def delete_ssm_parameter(param_name: str):
    print(f"[+] Deleting SSM parameter: {param_name}")

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    ssm = session.client("ssm")

    try:
        ssm.delete_parameter(Name=param_name)
        print("[✓] SSM parameter deleted.")
    except ssm.exceptions.ParameterNotFound:
        print("[!] Parameter not found — skipping.")
    except Exception as e:
        print(f"[!] Error deleting parameter: {e}")
        sys.exit(1)


def delete_local_config(config_path: str, client_name: str):
    if os.path.exists(config_path):
        print(f"[+] Deleting local config file: {config_path}")
        try:
            os.remove(config_path)
            print("[✓] Local config removed.")
        except Exception as e:
            print(f"[!] Error deleting file: {e}")
    else:
        print("[!] No local config file to delete.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python disconnect_vpn.py <client-name>")
        sys.exit(1)

    client_name = sys.argv[1]

    config_filename = f"{client_name}.conf"
    config_path = os.path.abspath(config_filename)
    param_name = f"/wireguard/{client_name}.conf"

    uninstall_wireguard_tunnel(client_name)
    delete_local_config(config_path, client_name)
    delete_ssm_parameter(param_name)
    delete_cloudformation_stack(STACK_NAME)

    print("\n[✓] VPN successfully disconnected and cleaned up.")


if __name__ == "__main__":
    main()
