#!/usr/bin/env python3
import boto3
import requests
import subprocess
import time
import argparse
import os
import sys
from botocore.exceptions import ClientError

AWS_REGION = "us-east-2"
PROFILE = "vpn-controller"
STACK_NAME = "wireguard-vpn"
IMAGE_ID = "ami-0a2e16d72500b3a73"
INSTANCE_TYPE = "t3.micro"

session = boto3.Session(profile_name=PROFILE, region_name=AWS_REGION)
cf = session.client("cloudformation")
ssm = session.client("ssm")

def get_public_ip():
    """
    Retrieves the public IP address using checkip.amazonaws.com.
    """
    url = "https://checkip.amazonaws.com"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            public_ip = response.text.strip()
            return public_ip
        else:
            return f"Error: Request failed with status code {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# --------------------------------------------------------------------
# 1. CREATE VPN SERVER
# --------------------------------------------------------------------
def create_vpn_server(client_name: str, client_ip: str):
    print(f"[+] Creating VPN server for client: {client_name}")

    parameters = [
        {"ParameterKey": "AppName", "ParameterValue": "wireguard"},
        {"ParameterKey": "HomeCIDR", "ParameterValue": f"{get_public_ip()}/32"},
        {"ParameterKey": "ClientName", "ParameterValue": client_name},
        {"ParameterKey": "InstanceType", "ParameterValue": INSTANCE_TYPE},
        {"ParameterKey": "ImageId", "ParameterValue": IMAGE_ID},
    ]

    print("[+] Creating CloudFormation stack...")
    try:
        cf.create_stack(
            StackName=STACK_NAME,
            TemplateBody=open("../vpn-template.yaml", "r").read(),
            Parameters=parameters,
            Capabilities=["CAPABILITY_NAMED_IAM"]
        )
    except ClientError as e:
        if "AlreadyExistsException" in str(e):
            print("[!] Stack already exists. Continuing...")
        else:
            print("[-] Failed to create stack:", e)
            sys.exit(1)

    print("[+] Waiting for CloudFormation to finish...")

    while True:
        try:
            res = cf.describe_stacks(StackName=STACK_NAME)
            status = res["Stacks"][0]["StackStatus"]
            print(f"    Stack status: {status}")

            if status == "CREATE_COMPLETE":
                print("[+] VPN server provisioning complete!")
                break
            elif "FAILED" in status or "ROLLBACK" in status:
                print("[-] Stack creation failed.")
                sys.exit(1)

        except ClientError as e:
            print("[-] Error describing stack:", e)
            sys.exit(1)

        time.sleep(5)



# --------------------------------------------------------------------
# 2. FETCH CLIENT CONFIG
# --------------------------------------------------------------------
def fetch_client_config(client_name: str) -> str:
    param_name = f"/wireguard/{client_name}.conf"
    print(f"[+] Fetching WireGuard config from SSM: {param_name}")

    while True:
        try:
            response = ssm.get_parameter(
                Name=param_name,
                WithDecryption=True
            )
            config = response["Parameter"]["Value"]
            if config:
                print("[+] Successfully retrieved WireGuard config.")
                return config

        except ssm.exceptions.ParameterNotFound:
            print("[~] Config not found yet. Retrying...")
        except ClientError as e:
            print(f"[!] AWS Error fetching config: {e}")

        time.sleep(3)



# --------------------------------------------------------------------
# 3. ACTIVATE VPN TUNNEL (Windows WireGuard)
# --------------------------------------------------------------------
def activate_vpn_tunnel(client_name: str, config_content: str):
    config_path = os.path.abspath(f"{client_name}.conf")
    print(f"[+] Writing WireGuard config to: {config_path}")

    with open(config_path, "w", newline="\n") as f:
        f.write(config_content)
        f.write("\n")

    wireguard_path = r"C:\\Program Files\\WireGuard\\wireguard.exe"

    if not os.path.exists(wireguard_path):
        print(f"[-] WireGuard not found at {wireguard_path}")
        print("[!] Make sure you installed WireGuard for Windows.")
        sys.exit(1)

    print("[+] Installing WireGuard tunnel service...")

    cmd = [
        wireguard_path,
        "/installtunnelservice",
        config_path
    ]

    try:
        subprocess.run(cmd, check=True)
        print("[+] WireGuard tunnel activated successfully!")
    except subprocess.CalledProcessError as e:
        print("[-] Failed to activate WireGuard:")
        print(e)
        sys.exit(1)



# --------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Provision WireGuard VPN Server")
    parser.add_argument("client_name", help="Name of WireGuard client")
    client_ip = get_public_ip()
    args = parser.parse_args()

    # Step 1: Create server
    create_vpn_server(args.client_name, client_ip)

    # Step 2: Fetch config
    config = fetch_client_config(args.client_name)

    # Step 3: Activate tunnel
    activate_vpn_tunnel(args.client_name, config)
