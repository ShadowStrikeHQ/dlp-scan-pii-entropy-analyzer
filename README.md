# dlp-scan-PII-Entropy-Analyzer
Analyzes text files for high entropy strings that might indicate leaked cryptographic keys or other sensitive data based on Shannon Entropy. - Focused on Scans local directories and files for sensitive data patterns (e.g., credit card numbers, API keys, PII) using regular expressions and file type identification. Generates reports detailing detected leaks and their severity, optionally allowing for data masking or deletion (with proper confirmation).

## Install
`git clone https://github.com/ShadowStrikeHQ/dlp-scan-pii-entropy-analyzer`

## Usage
`./dlp-scan-pii-entropy-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--report`: Path to save the report.
- `--mask`: Mask detected sensitive data in report.
- `--delete`: No description provided
- `--entropy_threshold`: Entropy threshold for considering a string as high entropy.

## License
Copyright (c) ShadowStrikeHQ
