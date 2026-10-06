# Automated SSH Threat Hunting Tool

A Bash script I built to help investigate suspicious SSH login activity on a Linux system.

## Overview

This tool looks through SSH authentication logs and checks for unusual login activity, especially repeated failed login attempts.

It uses a configurable threshold to determine when failed SSH attempts should be treated as suspicious and then produces a report based on the activity found.

## Features

- Checks SSH authentication logs
- Detects repeated failed login attempts
- Identifies successful SSH logins
- Uses a configurable threshold for suspicious activity
- Assigns a severity level based on the activity detected
- Generates an investigation report

## Technologies

- Bash
- Linux
- SSH
- Linux authentication logs

## How It Works

1. Reads the SSH authentication log
2. Looks for relevant authentication events
3. Counts failed login attempts
4. Compares the number of failures against the configured threshold
5. Determines the severity of the activity
6. Generates a report of the findings

## Usage

Make the script executable:

```bash
chmod +x automated_ssh_threat_hunting_tool.sh

Run the tool:
./automated_ssh_threat_hunting_tool.sh

Security Purpose

I built this project as a practical way to work with Linux authentication logs and practice basic threat-hunting and security monitoring.

Disclaimer

This tool is for authorized security monitoring, investigation, and educational purposes only.
