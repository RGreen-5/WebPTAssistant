# WebPT Assistant

WebPT Assistant is a modular web application penetration testing tool that automates key parts of a lightweight web assessment workflow. It combines network enumeration, web scanning, lightweight SQL injection detection, enrichment, AI-assisted summarisation, and report generation into a single pipeline.

## Features

- Nmap service and port enumeration
- OWASP ZAP spidering and active scanning
- Lightweight custom SQL injection detection
- Finding normalisation and grouping
- ExploitDB/Searchsploit enrichment
- Optional MISP enrichment
- AI-generated executive summaries
- Markdown report output
- Analyst review request export

## Project Structure

```text
webpt/
├── output/
├── scripts/
├── setup.sh
├── run_docker.sh
├── helpme.txt
└── webpt
Prerequisites

Make sure the following are installed on your system:

Python 3
pip
Docker
Nmap

You also need OWASP ZAP running for the scanner to work.

Setup Instructions
1. Clone the repository
git clone https://github.com/RGreen-5/WebPTAssistant.git
cd WebPTAssistant/webpt
2. Make the scripts executable
chmod +x setup.sh
chmod +x run_docker.sh
chmod +x webpt
3. Install dependencies

Run:
./setup.sh

This installs the Python packages and other dependencies required by the tool.

Starting the Environment
4. Start ZAP and the Docker test environment

Run:

./run_docker.sh

This is used to start the required Docker containers for testing.

If you only need ZAP and already have your target running separately, make sure ZAP is available on:

http://127.0.0.1:8080
Running the Tool
5. Launch a scan

Basic usage:

"./webpt"
"target: http://TARGET/"

After a scan completes, output files are written to the output/ directory.

Typical files include:
nmap_raw.json
zap_raw.json
custom_sqli_alerts.json
zap_message_analysis.json
analyst_review_candidates.json
zap_groups.json
report.md
Viewing Results
Main report

The final report is saved to:
output/report.md

If SQL injection signals are detected, they are saved to:
output/custom_sqli_alerts.json

Normalised findings are saved to:
output/zap_groups.json

Run everything in order:
git clone https://github.com/RGreen-5/WebPTAssistant.git
cd WebPTAssistant/webpt
chmod +x setup.sh run_docker.sh webpt
sudo bash setup.sh
./run_docker.sh
./webpt scan --target http://172.17.0.4/

Notes
Use a reachable target URL.
In Docker environments, container IPs may work better than 127.0.0.1 depending on how the containers are networked.
OWASP ZAP must be running before starting a scan.
This tool is intended for authorised testing and controlled lab environments only.

Author
Robert Green
