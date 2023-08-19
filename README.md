# XSSecurePro

**XSSecurePro** is a Python tool designed for learning purposes to scan websites for potential Cross-Site Scripting (XSS) vulnerabilities. It uses asyncio, aiohttp, BeautifulSoup, and Selenium to crawl a given website and analyze its pages for potential XSS vulnerabilities. This tool allows you to specify custom payloads and authentication cookies to scan authenticated areas of a website.

## Features

- **Website Scanning**: XSSecurePro can crawl a website and analyze its pages for potential XSS vulnerabilities.

- **Custom Payloads**: You can provide custom XSS payloads for testing.

- **Authentication Support**: If a website requires authentication, you can provide an authentication cookie to scan authenticated areas.

- **Custom HTTP Headers**: You have the option to specify custom HTTP headers for requests to the website.

- **Logging**: The tool provides logging to track the scanning process and results.

## Getting Started

### Prerequisites
Before using XSSecurePro, make sure you have the following prerequisites installed:

- Python 3.x
- Required Python packages (install them using `pip install aiohttp beautifulsoup4 selenium`)

### Installation
Clone this repository to your local machine:

      ```bash
     git clone https://github.com/yourusername/XSSecurePro.git
     cd XSSecurePro

#Usage

To use XSSecurePro, follow these steps:

1. Run the script:

    ```bash

    python xss_secure_pro.py

2.  You'll be prompted to enter the following information:
        - Target URL: Enter the URL of the website you want to scan for XSS vulnerabilities.
        - Custom Payloads: Enter custom XSS payloads separated by commas.
        - Authentication Cookie (if applicable): Provide an authentication cookie if you want to scan authenticated areas.
        - Custom Headers (if needed): Optionally, provide custom HTTP headers in the format key1:value1,key2:value2.

3. The tool will start scanning the website for potential XSS vulnerabilities. It will crawl the site up to a specified depth and analyze each page for vulnerable scripts and payloads.

4.  After scanning is complete, the tool will provide a summary of the results, including the number of scanned pages, potential XSS vulnerabilities found, and any vulnerable payloads detected.

#Configuration

You can configure the tool by modifying the following variables in the script:

  max_depth: The maximum depth for crawling the website. By default, it is set to 3, meaning the tool will crawl up to three levels deep.
    logging.basicConfig: Configure the logging settings, including the log file name and log level.

#Results

The tool will provide a summary of the scan results, including:

  1. The total number of pages scanned.
  2.  The number of potential XSS vulnerabilities found.
  3.  URLs where potential vulnerabilities were detected.
  4.  Vulnerable payloads that triggered the detection.

The tool will also save the page source of any pages with potential vulnerabilities in files named "vulnerable_URL.html" for further analysis.


