# CertCrawler :lock::snake: #

This script utilizes cert transparency logs to identify subdomains, identify if they are live, and identify the corresponding organizational ownership.

Checking crt.sh for certificates issued matching the target domain, we pull the corresponding "Matching Identities". Once Matching Identities have been identified we make a connection over HTTPS to pull the domain's corresponding certificate information. This cert information may contain an optional field "Organization Unit" and "Organization Unit Name" which can be used to identify domain ownership.

## Getting Started ##

`CertCrawler` requires **3.7+**. Python 2 is not supported.

To run the tool locally from the repository, first
install the requirements:
```bash
pip install -r requirements.txt
```

### Usage and examples ###

```bash
python CertCrawler.py -d example.com
python CertCrawler.py -d .gov -t 10
python CertCrawler.py -d example.com -o sample_domains_output -f json
python CertCrawler.py -d example.com -o sample_domains_output -f csv
python CertCrawler.py -d example.com -o sample_domains_output --log-level info
python CertCrawler.py -d example.com -t 10 -o sample_domains_output -f json --log-level debug
python CertCrawler.py -i domains -t 1

```

#### Options ####

```bash
-h --help                              Show this message.
-d DOMAIN                              Pull domains from crt.sh
-o OUTPUT_FILE                         File you want to write output to
-f OUTPUT_FILE_TYPE                    File type for output. Valid output values "csv" and "json". [default: csv]
-i INPUT_FILE                          Load subdomains from file
-t TIMEOUT                             Set timeout for network requests [default:5]
--log-level=LEVEL                      If specified, then the log level will be set to
                                       the specified value.  Valid values are "debug", "info",
                                       "warning", "error", and "critical". [default: critical]
```

## Public domain ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
