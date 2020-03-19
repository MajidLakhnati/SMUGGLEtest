
# SMUGGLEtest

## Related Work
This program is based on the work of [James Kettle](https://skeletonscribe.net/). If you are interested in HTTP desync attacks and HTTP Request Smuggling specifically, I highly advise you to check out the [HRS Blogposts](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) on the PortSwigger web site if you have not read them yet.

## Description
SMUGGLEtest is a Python 3 CLI program that automates the detection of **HTTP Request Smuggling** vulnerabilities.
It bundles the detection of different HRS vulnerabilities on arbitrary web sites in a single Python 3 tool. This tool is suitable for scanning a single web site as well as mass scanning.
SMUGGLEtest is able to scan for basic **Content-Length.Transfer-Encoding (CL.TE)** and **Transfer-Encoding.Content-Length (TE.CL)** vulnerabilities, and more complex **Transfer-Encoding.Transfer-Encoding (TE.TE)** vulnerabilities, where a desynchronization technique is mandatory. The program utilizes a diversity of these desynchronization techniques and it attempts to find new desync techniques by combinining existing ones.

## Prerequisites

SMUGGLEtest only works with ```Python 3``` and has the following dependency:

* ```requests```

If you have do not have the library [Python Requests](https://requests.readthedocs.io/en/master/) installed yet:

```pip3 install requests```

## Usage

SMUGGLEtest is able to scan a single URL, end point or domain as well as multiple URLs, end points and domains, listed in an input file.

```
usage: SMUGGLEtest.py [-h] [-u URL] [-i INFILE]

-------------------HOTKEYS-------------------

CTRL+C = Stop SMUGGLEtest

-------------------USAGE-------------------

Single URL: python3 SMUGGLEtest.py -u http://example.com
Input file: python3 SMUGGLEtest.py -i example.txt

-------------------ARGUMENTS-------------------

optional arguments:
  -h, --help  show this help message and exit
  -u URL      target URL
  -i INFILE   File with domain or URL list
```

### Single URL

```python3 SMUGGLEtest.py -u https://example.com```

### Multiple URLs

```python3 SMUGGLEtest.py -i example.txt```

## Example Output

![Example output](https://github.com/MajidLakhnati/SMUGGLEtest/blob/master/tetenewresult1.png)

When SMUGGLEtest succesfully detects a HRS vulnerability, it provides the user with following information:

*  **Vulnerability**: The type of the vulnerability that SMUGGLEtest detected.
*  **URL**: The URL for which SMUGGLEtest found a vulnerability.
*  **Description**: A brief description on how SMUGGLEtest managed to detect the vulnerability.
*  **Complexity**: This states if the found vulnerability is of either **basic** or **advanced** complexity. SMUGGLEtest considers every vulnerability, where a obfuscation of the Transfer-Encoding header is necessary, respectively a desync technique is mandatory, as an  **advanced** vuln.
*  **Transfer-Encoding Header**: When SMUGGLEtest finds a vulnerability, it specifies the TE header that was used to detect the desynchronization.
*  **Exploitation:** The program advises the user to further inform him-/herself on how to exploit the vulnerability.


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details.

## Background
SMUGGLEtest was developed and implemented as part of my bachelor thesis at the [Chair of Network and Data Security](https://www.nds.ruhr-uni-bochum.de/chair/news/) at the Ruhr-University Bochum. This thesis will later on be linked in this README for everyone that is interested in the technical background and implementation of the program.

## Acknowledgments
The program was developed with the help of the [Chair of Network and Data Security](https://www.nds.ruhr-uni-bochum.de/chair/news/) and most importantly, the advisor of my bachelor thesis, [Jens Müller](https://twitter.com/jensvoid?lang=de).
