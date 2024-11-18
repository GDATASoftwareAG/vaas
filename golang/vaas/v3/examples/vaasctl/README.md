# VaaS Command Line Interface (CLI)

This Go programm is an example implementation of a Command Line Interface (CLI) for the G DATA VaaS API. This program allows users to scan URLs, SHA256 hashes and files.

## Installation

1. Clone the repository: `git clone https://github.com/GDATASoftwareAG/vaas.git`
2. Change directory into the `vaas/golang/vaas/cmd/vaasctl` directory
3. Build the program: `go build`
4. Run the program: `./vaas` 

<b>Note:</b> Before running the program, please make sure to fill out the required credentials in the environment or `.env` file.

## Usage

### Command Line Arguments

The following command line arguments are supported:

+ `-s`: Check one ore multiple SHA256 hashes.
+ `-f`: Check one or multiple files.
+ `-u`: Check one or multiple URLs.

### Example Usage

To check a file: 

``` bash
./vaas -f file_to_check
```

To check multiple files:

``` bash
./vaas -f file1_to_check file2_to_check file3_to_check
```

To check a URL: 

``` bash
./vaas -u url_to_check
```

To check multiple URLs:

``` bash
./vaas -f url1_to_check url2_to_check url3_to_check
```

To check a SHA256 hash: 

``` bash
./vaas -f sha256_to_check
```

To check multiple SHA256 hashes:

``` bash
./vaas -f sha2561_to_check sha2562_to_check sha2563_to_check
```