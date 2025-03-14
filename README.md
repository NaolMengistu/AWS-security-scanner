# AWS Cloud Security Compliance Checker

## **Overview**

Welcome to the **AWS Cloud Security Compliance Checker**! This project is designed to help financial institutions (and anyone using AWS) identify security misconfigurations and ensure compliance with the **Digital Operational Resilience Act (DORA)**. The tool scans key AWS services, including Amazon S3, EC2 Security Groups, IAM Policies, and VPC Configurations, for potential vulnerabilities. The results are presented via an interactive **Streamlit dashboard**, and you can also generate a **PDF compliance report** with remediation recommendations.

---

## Project Components

- **`checker.py`**: The main Python script that uses the `boto3` SDK to connect to AWS and check for misconfigurations.
- **`streamlit.py`**: A web dashboard built with Streamlit that displays scan results and allows you to download PDF reports.
- **`.env` file**: Contains AWS resource identifiers (e.g., VPC ID, subnet IDs) kept secure and not uploaded to GitHub.
- **PDF Reporting**: The tool generates a PDF report summarizing detected misconfigurations and mapped DORA requirements.

---

## **AWS Environment Setup**

To make this tool work, I set up a specific AWS environment. Here’s the rundown of what I created and why:

### **1. AWS Services Created**

I spun up a few AWS resources to test the checker:

- **Amazon S3 Bucket**: A bucket created to test for misconfigurations like public access, missing encryption, and disabled logging.
- **Amazon EC2 Instance**: An instance with an associated security group configured with open ports (e.g., SSH on port 22 and RDP on port 3389) to simulate exposure risks.
- **AWS IAM Users/Roles**: Users and roles created to test for overly permissive policies and missing Multi-Factor Authentication (MFA).
- **Amazon VPC**: A VPC configured with subnets, route tables, and network ACLs; deliberately set with vulnerabilities (e.g., default routes to an Internet Gateway, permissive ACL rules, and no VPC Flow Logs) to test network security.

### **2. Deliberately Introduced Vulnerabilities**

To really put the tool through its paces, I intentionally added some security flaws:

- **S3 Buckets:**
    - Public access enabled.
    - No encryption configured.
    - Logging disabled.
- **EC2 Security Groups:**
    - Inbound rules allow SSH (port 22) and RDP (port 3389) from any IP (`0.0.0.0/0`).
    - Added unrestricted ingress rules (`0.0.0.0/0`, not a good idea in real life!).
- **IAM Policies:**
    - Roles with policies that use wildcards (e.g., `"Action": "*", "Resource": "*"`) representing overly broad permissions.
    - Some IAM users are set up without MFA.
- **VPC Configurations:**
    - Route tables include a default route to an Internet Gateway.
    - Network ACLs are configured to allow all traffic (`0.0.0.0/0`).
    - Subnets are set to automatically assign public IP addresses.
    - VPC Flow Logs are not enabled.

These intentional flaws help demonstrate the tool's ability to detect and report security misconfigurations.

---

## **Setting Up Your Development Environment in VS Code**

### **1. Install Visual Studio Code**

If you don’t have VS Code, download and install it from [here](https://code.visualstudio.com/). 

### **2. Clone the Repository**

Open the VS Code terminal (press <kbd>Ctrl</kbd>+<kbd>`</kbd> or navigate to **View > Terminal**) and run:

```
git clone <https://github.com/NaolMengistu/AWS-security-checker.git>
cd aws-security-scanner

```

### **3. Set Up a Virtual Environment**

Create a virtual environment to manage dependencies:

```
python -m venv venv
```

Now, activate it:

- **macOS/Linux**:

```
source venv/bin/activate
```

- **Windows**:

```
venv\Scripts\activate
```

You should see `(venv)` in your terminal, indicating that the environment is active.

### **4. Install Dependencies**

Install all required packages using

```
pip install -r requirements.txt
```

This installs boto3, streamlit, and few packages used.

---

## **Configuring Your AWS Environment**

The tool needs to talk to AWS, so let’s set up your credentials and environment.

### 1. Install and Configure the AWS CLI

If you don’t have the AWS CLI yet, download it from [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html). Once it’s installed, configure your credentials by running:

```
aws configure
```

You’ll need to provide:

- **AWS Access Key ID**
- **AWS Secret Access Key**
- **Default region name** (e.g., `eu-north-1`)
- **Default output format**: Just hit Enter for JSON (the default).

This sets up your local machine to talk to AWS securely.

### 2. Create AWS Resources

Set up your AWS resources as follows:

- **S3 Bucket**: Create a bucket (e.g., `my-security-test-bucket`) and deliberately configure it with public access, no encryption, and disabled logging.
- **EC2 Instance**: Launch an instance (t2.micro is sufficient) with a security group that has open ports for SSH (22) and RDP (3389) with ingress rules set to `0.0.0.0/0`.
- **IAM Users/Roles**: Create a user or role with overly permissive policies (using `"Action": "*", "Resource": "*"`). Omit MFA for some users.
- **VPC**: Set up a VPC with a public subnet (auto-assign public IP enabled), an Internet Gateway attached, a route table with a default route to the IGW, and a permissive Network ACL. Do not enable VPC Flow Logs.

Keep a note of all resource IDs (e.g., VPC ID, subnet IDs, route table ID, IGW ID, ACL ID).

---

## **Set Up Environment Variables**

I don’t want my AWS resource IDs hardcoded, so I use a `.env` file.

### **1. Create the .env File**

In your project folder, create the file:

```
touch .env
```

Open it in VS Code and add:

```
AWS_VPC_ID=vpc-xxxxxxxxxxxxxxxxx
AWS_PUBLIC_SUBNET_ID=subnet-xxxxxxxxxxxxxxxxx
AWS_PRIVATE_SUBNET_ID=subnet-xxxxxxxxxxxxxxxxx
AWS_ROUTE_TABLE_ID=rtb-xxxxxxxxxxxxxxxxx
AWS_IGW_ID=igw-xxxxxxxxxxxxxxxxx
AWS_PERMISSIVE_ACL_ID=acl-xxxxxxxxxxxxxxxxx
```

Replace the `x`s with your actual AWS resource IDs from the setup above. This keeps everything tidy and secure.

---

## **Running the Compliance Checker**

### 1. Run the Security Scan

Execute the scanner:

```
python checker.py
```

The script will output a JSON-formatted list of detected misconfigurations.

### 2. Launch the Streamlit Dashboard

Start the Streamlit web dashboard with:

```
streamlit run streamlit.py
```

It’ll start a local server and give you a URL (like `http://localhost:8501`). Open that in your browser, and you’ll see the results in a nice interactive table!

---

## **How the Code Works**

### Code Functionality

- **AWS Resource Scanning**:
    
    The custom Python script uses the `boto3` SDK to connect to AWS services and retrieve configurations from S3, EC2, IAM, and VPC.
    
- **Security Misconfiguration Checks**:
    
    The script checks for:
    
    - **S3 Buckets**: Public access settings, missing encryption, and logging configuration.
    - **EC2 Security Groups**: Open ports (SSH, RDP, HTTP), ICMP access, and wide-open rules.
    - **IAM Policies & User Activity**: Wildcard permissions in policies, inactive users, and lack of MFA.
    - **VPC Configurations**: Default routes to an Internet Gateway, permissive ACL rules, public subnets, and missing VPC Flow Logs.
- **Compliance Mapping**:
    
    Each detected misconfiguration is mapped to a corresponding DORA compliance article (e.g., Article 9 for secure cloud configurations, Article 5 for ICT risk management). The mapping process does not categorize risks by severity; it strictly associates misconfigurations with the appropriate DORA requirements.
    
- **Report Generation**:
    
    The tool compiles the findings into a JSON output. The Streamlit dashboard then displays these results interactively and provides an option to download a detailed PDF report.
    

### Streamlit Integration

- **Dashboard Features**:
The Streamlit dashboard shows results in a user-friendly table, lets users filter results by AWS service, and includes a button to download a PDF report.
- **Interactivity**:
Users can re-run the compliance checks and view updated results directly from the dashboard.

---

## **Project Structure**

```
aws-security-checker/
│-- .gitignore        # Keeps sensitive files out of Git
│-- .env              # AWS resource IDs (not in this repo)
│-- requirements.txt  # List of Python dependencies
│-- README.md         # Project documentation (this file)
│-- checker.py        # The scanner script
│-- streamlit.py      # The dashboard code
│-- venv/             # Virtual env (not in this repo)
│-- __pycache__/      # Compiled Python files (ignored)
```

---

## **Credits**

Developed by: @NaolMengistu, @AliFerzali