# Personal VPN Setup Using AWS EC2 and Wireguard

The goal of this project is to create a cheap, fast, and reliable personal VPN server hosted on AWS. To make it cheap, AWS CloudFormation stacks will be used to automatically create and decomission the VPN server and dedicated IP address for each new connection, thus avoiding the cost of keeping the server always on (t3.micro = ~$7.50/month), and the cost of an elastic ip not in use (~$3.50/month). To make it fast, a separate CloudFormation stack will be used for static resources such as VPC, and an Amazon Machine Image (AMI) will be pre-baked to reduce server startup times by installing all required dependencies on the server. Another advantage of using CloudFormation stacks is that the resources can easily be created/destroyed in any region available on AWS. When all is done the vpn server will cost roughly $0.0104 per hour in use.

## 1. Install Prerequisites
- [AWS CLI](https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-install.html)
- [Wireguard](https://www.wireguard.com/install/)
- [Packer](https://developer.hashicorp.com/packer/install)

## 2. Create IAM User To Manage VPN Resources
Accessing an IAM User means storing a permanent set of credentials. This means IAM Users should generally be avoided, and given minimal permissions when necessary. For this application an IAM User is used to deploy AWS resources such as VPC, EC2 instances, IAM Role, etc from the client device. The following permissions are added to the user so that it may create a cloudformation stack with all required resources. For added security, optionally restrict these actions to a home network.

- Create IAM User named "vpn-controller"
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudFormationWritePerms",
            "Effect": "Allow",
            "Action": [
                "cloudformation:CreateStack",
                "cloudformation:DeleteStack",
                "cloudformation:UpdateStack"
            ],
            "Resource": [
                "arn:aws:cloudformation:*:<your-aws-account>:stack/wireguard-vpc/*",
                "arn:aws:cloudformation:*:<your-aws-account>:stack/wireguard-vpn/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        },
        {
            "Sid": "EC2WritePerms",
            "Effect": "Allow",
            "Action": [
                "ec2:CreateVpc",
                "ec2:CreateInternetGateway",
                "ec2:CreateRoute",
                "ec2:CreateRouteTable",
                "ec2:CreateSubnet",
                "ec2:CreateSecurityGroup",
                "ec2:CreateTags",
                "ec2:CreateKeyPair",
                "ec2:ModifyVpcAttribute",
                "ec2:ModifySubnetAttribute",
                "ec2:AttachInternetGateway",
                "ec2:AssociateRouteTable",
                "ec2:AllocateAddress",
                "ec2:AssociateAddress",
                "ec2:RunInstances",
                "ec2:StopInstances",
                "ec2:TerminateInstances",
                "ec2:ReleaseAddress",
                "ec2:DisassociateAddress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:DetachInternetGateway",
                "ec2:DisassociateRouteTable",
                "ec2:DeleteKeyPair",
                "ec2:DeleteVpc",
                "ec2:DeleteInternetGateway",
                "ec2:DeleteRoute",
                "ec2:DeleteRouteTable",
                "ec2:DeleteSubnet",
                "ec2:DeleteSecurityGroup",
                "ec2:DeleteTags"
            ],
            "Resource": [
                "arn:aws:ec2:*:<your-aws-account>:vpc/*",
                "arn:aws:ec2:*:<your-aws-account>:subnet/*",
                "arn:aws:ec2:*:<your-aws-account>:internet-gateway/*",
                "arn:aws:ec2:*:<your-aws-account>:instance/*",
                "arn:aws:ec2:*:<your-aws-account>:security-group/*",
                "arn:aws:ec2:*:<your-aws-account>:route-table/*",
                "arn:aws:ec2:*:<your-aws-account>:elastic-ip/*",
                "arn:aws:ec2:*:<your-aws-account>:key-pair/*",
                "arn:aws:ec2:*:<your-aws-account>:network-interface/*",
                "arn:aws:ec2:*:<your-aws-account>:volume/*",
                "arn:aws:ec2:*::image/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        },
        {
            "Sid": "IAMWritePermissions",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:CreatePolicy",
                "iam:CreateInstanceProfile",
                "iam:TagRole",
                "iam:PutRolePolicy",
                "iam:AttachRolePolicy",
                "iam:AddRoleToInstanceProfile",
                "iam:PassRole",
                "iam:DetachRolePolicy",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:DeleteRole",
                "iam:DeleteRolePolicy",
                "iam:DeleteInstanceProfile"
            ],
            "Resource": [
                "arn:aws:iam::<your-aws-account>:role/wireguard-vpc-InstanceRole*",
                "arn:aws:iam::<your-aws-account>:instance-profile/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        },
        {
            "Sid": "ManageVPN",
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        },
        {
            "Sid": "SSMPermissions",
            "Effect": "Allow",
            "Action": [
                "ssm:PutParameter",
                "ssm:DeleteParameter",
                "ssm:GetParameter",
                "ssm:GetParameters"
            ],
            "Resource": [
                "arn:aws:ssm:*:<your-aws-account>:parameter/wireguard/*",
                "arn:aws:ssm:*:<your-aws-account>:parameter/ec2/keypair/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        },
        {
            "Sid": "AllowDecryptSSMKeys",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "arn:aws:kms:*:<your-aws-account>:key/*",
                "arn:aws:kms:*:<your-aws-account>:alias/aws/ssm"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "<your-home-ip>"
                    ]
                }
            }
        }
    ]
}
```
- Create AWS Access/Secret Keys and store at "C:\Users\<your-username>\.aws\credentials" under "vpn-controller" profile

## 3. Create Cloudformation Stack For Static Resources
Some of the resources such as the VPC and instance role that are used by the VPN server are free and can be persisted between connections to the VPN. To save time in connecting to the VPN, create these resources in a separate CloudFormation stack. Once created, they can be referenced by the dynamic resources that are setup for each fresh VPN connection. 

- CloudFormation Template (vpc-template.yaml)
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: VPC and associated resources to be used by VPN server

Parameters:
  AppName:
    Type: String
    Description: Application name

Resources:
    # --- VPC & Networking ---
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.10.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-vpc"

  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-internetgateway"

  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref VPC
      InternetGatewayId: !Ref InternetGateway

  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.10.1.0/24
      MapPublicIpOnLaunch: true
      AvailabilityZone: !Select [0, !GetAZs ""]
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-subnet"

  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-routetable"

  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref RouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway

  SubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref RouteTable
  
    # --- IAM Role for EC2 ---
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
      Policies:
        - PolicyName: !Sub "${AppName}-ssmwrite"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - ssm:PutParameter
                Resource: !Sub arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/${AppName}/*
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-instancerole"

  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles: [!Ref InstanceRole]


Outputs:
    VPC:
      Description: VPC for VPN
      Value: !Ref VPC
      Export:
        Name: !Sub "${AppName}-vpc"
    Subnet:
      Description: Public Subnet
      Value: !Ref PublicSubnet
      Export: 
        Name: !Sub "${AppName}-subnet"
    InstanceProfile:
      Description: IAM profile to be used in vpn server
      Value: !Ref InstanceProfile
      Export:
        Name: !Sub "${AppName}-instance-profile"
```

- CloudFormation parameters
```json
[
    {
        "ParameterKey": "AppName",
        "ParameterValue": "wireguard"
    }
]
```

- To create the static resources for the VPN server, run the command:  
`aws cloudformation create-stack --region us-east-2 --template-body file://vpc-template.yaml --stack-name wireguard-vpn --parameters file://vpc-parameters-wireguard.json --capabilities CAPABILITY_NAMED_IAM --profile vpn-controller`

## 4. Pre Bake EC2 Image
To further speed up the server start up times, an Amazon Machine Image (AMI) can be created with all upgrades and required server dependencies pre installed. Packer achieves this by creating an EC2, running the specified commands, and then taking a snapshot of the instance state and saving it to AWS EBS where the AMI id can be retrieved and quickly deployed as a new instance.

- First create the packer config file packer-wireguard.pkr.hcl
```hcl
packer {
  required_plugins {
    amazon-ebs = {
      version = ">= 1.8.0"
      source = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "ami_name" {
  type    = string
  default = "wireguard-prebaked-{{timestamp}}"
}

source "amazon-ebs" "ubuntu" {
  region               = var.aws_region
  instance_type        = "t3.micro"
  ssh_username         = "ubuntu"
  ami_name             = var.ami_name
  ami_description      = "Pre-baked WireGuard VPN AMI with dependencies installed"

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu"]

  provisioner "shell" {
    inline = [
      "sudo apt update",
      "sudo apt-get update -yq",
      "sudo apt-get upgrade -yq",
      "sudo apt-get install -yq wireguard iptables jq awscli"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo apt-get autoremove -yq",
      "sudo apt-get clean -yq"
    ]
  }
}
```

- To pre-bake the AMI, run the commands  
`set AWS_PROFILE="vpn-controller"`  
`packer init -upgrade .\packer-wireguard.pkr.hcl`  
`packer build packer-wireguard.pkr.hcl`  

- Finally, capture the output AMI (ami-...) to use in future vpn servers
- To ensure the dependencies stay up to date, it is recommended to repeat this process every so often and bake a new AMI.

## 5. Create CloudFormation Stack for Dynamic VPN Server
Whenever a VPN connection is needed the actual server, and elastic IP address can be dynamically created prior to obtaining a connection. While EC2 instances incur no cost while the instances are stopped, the elastic IP address has a cost when not in use by the server. By creating these resources dynamically this cost can be avoided.

The static resources created in the previous stack such as VPC, Subnet, and Security Group can be imported to this template to speed up the deployment.

With all the dependencies pre installed in the AMI, a UserData script is used to run the required commands to complete Wireguard setup and initialize the VPN server. Once the script completes the setup, the Wireguard client config is uploaded to AWS SSM where it can be fetched on the client machine and configured in the local Wireguard application.

Optionally include a key pair to SSH into the server. This key pair can be fetched from AWS SSM from a local machine.

- CloudFormation template (vpn-template.yaml)
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Wireguard VPN for home network

Parameters:
  AppName:
    Type: String
    Description: Application name
  HomeCIDR:
    Type: String
    Description: Home network ip as /32 CIDR
  ClientName:
    Type: String
    Description: Client name for the VPN tunnel
  InstanceType:
    Type: String
    Default: t3.micro
    Description: EC2 instance type
  ImageId:
    Type: AWS::EC2::Image::Id
    Description: AMI for EC2 instance

Resources:

  # --- Security Group ---
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow VPN traffic and SSH from HomeCIDR
      VpcId:
        Fn::ImportValue:
          Fn::Sub: "${AppName}-vpc"
      SecurityGroupIngress:
        - IpProtocol: udp
          FromPort: 51820 # Default WireGuard port
          ToPort: 51820
          CidrIp: !Ref HomeCIDR
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Ref HomeCIDR
      SecurityGroupEgress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-sg"

  # --- Elastic IP ---
  EIP:
    Type: AWS::EC2::EIP
    Properties:
      Domain: vpc
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-eip"

  # --- KeyPair --- (Optional SSH into server)
  KeyPair:
    Type: AWS::EC2::KeyPair
    Properties:
      KeyFormat: pem
      KeyName: !Sub "${AppName}-keypair"
      KeyType: rsa

  # --- EC2 Instance ---
  VPNInstance:
    Type: AWS::EC2::Instance
    DependsOn: KeyPair
    Properties:
      InstanceType: !Ref InstanceType
      PublicIp: !Ref EIP
      SubnetId:
        Fn::ImportValue:
          Fn::Sub: "${AppName}-subnet"
      SecurityGroupIds: [!Ref SecurityGroup]
      KeyName: !Sub "${AppName}-keypair"
      IamInstanceProfile:
        Fn::ImportValue:
          Fn::Sub: "${AppName}-instance-profile"
      ImageId: !Ref ImageId
      Tags:
        - Key: Name
          Value: !Sub "${AppName}-instance"
      UserData:
        Fn::Base64: !Join
          - ''
          - - !Sub |
              #!/bin/bash
              set -eux

              # Metadata from CloudFormation
              APP_NAME=${AppName}
              SSM_PATH_PREFIX=${AppName}
              AWS_REGION=${AWS::Region}
              CLIENT_NAME=${ClientName}
              PUBLIC_IP=${EIP}
            - |
              echo "=== Setting up WireGuard directories ==="
              WG_DIR=/etc/wireguard
              WG_INTERFACE=wg0
              mkdir -p $WG_DIR
              chmod 700 $WG_DIR
              cd $WG_DIR

              echo "=== Generating keys ==="
              # Generate server private key
              SERVER_PRIVATE_KEY=$(wg genkey)
              SERVER_PUBLIC_KEY=$(wg pubkey <<< "$SERVER_PRIVATE_KEY")
              CLIENT_PRIVATE_KEY=$(wg genkey)
              CLIENT_PUBLIC_KEY=$(wg pubkey <<< "$CLIENT_PRIVATE_KEY")

              SERVER_IP="10.8.0.1"
              CLIENT_IP="10.8.0.2"
              SERVER_PORT=51820

              echo "=== Detecting main network interface ==="
              NIC=$(ip route get 8.8.8.8 | awk '{print $5; exit}')

              echo "=== Creating WireGuard server config ==="
              cat > $WG_DIR/$WG_INTERFACE.conf <<EOF
              [Interface]
              Address = $SERVER_IP/24
              SaveConfig = true
              ListenPort = $SERVER_PORT
              PrivateKey = $SERVER_PRIVATE_KEY
              PostUp = iptables -t nat -A POSTROUTING -o $NIC -j MASQUERADE
              PostDown = iptables -t nat -D POSTROUTING -o $NIC -j MASQUERADE

              [Peer]
              PublicKey = $CLIENT_PUBLIC_KEY
              AllowedIPs = $CLIENT_IP/32
              EOF

              echo "=== Enabling IP forwarding ==="
              sysctl -w net.ipv4.ip_forward=1
              echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf

              echo "=== Enabling and starting WireGuard service ==="
              systemctl enable wg-quick@$WG_INTERFACE
              systemctl start wg-quick@$WG_INTERFACE

              echo "=== Creating client configuration ==="
              CLIENT_CONF="/root/$CLIENT_NAME.conf"
              # PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

              cat > $CLIENT_CONF <<EOF
              [Interface]
              PrivateKey = $CLIENT_PRIVATE_KEY
              Address = $CLIENT_IP/24
              DNS = 1.1.1.1

              [Peer]
              PublicKey = $SERVER_PUBLIC_KEY
              Endpoint = $PUBLIC_IP:$SERVER_PORT
              AllowedIPs = 0.0.0.0/0, ::/0
              PersistentKeepalive = 25
              EOF

              echo "=== Uploading client config to SSM Parameter Store ==="
              PARAM_NAME="/$SSM_PATH_PREFIX/$CLIENT_NAME.conf"
              aws ssm put-parameter \
                --name "$PARAM_NAME" \
                --value "$(cat $CLIENT_CONF)" \
                --type SecureString \
                --overwrite \
                --region "$AWS_REGION"

              echo "Client configuration stored in SSM as: $PARAM_NAME"

              echo "=== WireGuard setup complete ==="


  # --- Associate Elastic IP ---
  EIPAssoc:
    Type: AWS::EC2::EIPAssociation
    Properties:
      AllocationId: !GetAtt EIP.AllocationId
      InstanceId: !Ref VPNInstance

Outputs:
  InstanceId:
    Description: EC2 Instance ID
    Value: !Ref VPNInstance
  ElasticIP:
    Description: Public IP of the instance
    Value: !Ref EIP
  AppName:
    Description: Application identifier for this stack
    Value: !Ref AppName
```

- CloudFormation parameters
```json
[
    {
        "ParameterKey": "AppName",
        "ParameterValue": "wireguard"
    },
    {
        "ParameterKey": "HomeCIDR",
        "ParameterValue": "<your-home-ip>/32"
    },
    {
        "ParameterKey": "ClientName",
        "ParameterValue": "<your-client-name>"
    },
    {
        "ParameterKey": "InstanceType",
        "ParameterValue": "t3.micro"
    },
    {
        "ParameterKey": "ImageId",
        "ParameterValue": "<your-ami-id>"
    }
]
```

- To create the VPN server, run the command:  
`aws cloudformation create-stack --region us-east-2 --template-body file://vpc-template.yaml --stack-name wireguard-vpn --parameters file://vpc-parameters-wireguard.json --profile vpn-controller`

## 6. Fetch Wireguard client configuration on local machine
Once the VPN server stack is deployed and UserData scripts are complete, fetch the client configuration from AWS SSM. This configuration is loaded into the Wireguard application on the local machine. It specifies the public key for data encryption as well as the IP of the VPN server. Note, you will not be able to fetch the config from SSM until the UserData script is complete, and checking the status requires ssh into the server. But it should only take a few minutes, so you can try fetching the config a few times until successful.

- Run the command  
`aws ssm get-parameter --name "/wireguard/<your-ClientName>-conf>" --with-decryption --query 'Parameter.Value' --region us-east-2 --profile vpn-controller --output text > <your-ClientName>.conf`

- Load this configuration into the Wireguard application
- Activate the VPN server

## 7. Delete the VPN Server and EIP
- Disconnect from the VPN server in the Wireguard application
- To delete the VPN instance and associated resources, run the commands:  
`aws cloudformation delete-stack --region us-east-2 --stack-name wireguard-vpn --profile vpn-controller`  
`aws ssm delete-parameter --name "/wireguard/<your-ClientName>.conf" --region us-east-2 --profile vpn-controller`  

## Create Python scripts to quickly manage vpn connections

- requirements.txt
```text
boto3==1.41.4
botocore==1.41.4
certifi==2025.11.12
charset-normalizer==3.4.4
colorama==0.4.6
docutils==0.19
idna==3.11
jmespath==1.0.1
pyasn1==0.6.1
python-dateutil==2.9.0.post0
PyYAML==6.0.3
requests==2.32.5
rsa==4.7.2
s3transfer==0.15.0
six==1.17.0
urllib3==2.5.0
```

- connect.py
```python
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
IMAGE_ID = "ami-..."
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
```

- disconnect.py
```python
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
```

- Connecting/disconnecting from the server is now as simple as running the commands:  
`python connect.py`  
`python disconnect.py`

