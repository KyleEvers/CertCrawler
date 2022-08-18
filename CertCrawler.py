#!/usr/bin/env python3
"""
This script utilizes cert transparency logs to identify subdomains, identify if
they are live, and identify the corresponding organizational ownership

EXIT STATUS
    This utility exits with one of the following values:
    0   Recon completed successfully.
    >0  An error occurred.

Usage:
  CertCrawler (-d DOMAIN | -i INPUT_FILE)[-t TIMEOUT][-o OUTPUT_FILE][--log-level=LEVEL][-f OUTPUT_FILE_TYPE]
  CertCrawler (-h | --help)

Options:
  -h --help                              Show this message.
  -d DOMAIN                              Pull domains from crt.sh
  -o OUTPUT_FILE                         File you want to write output to
  -f OUTPUT_FILE_TYPE                    File type for output. Valid output values "csv", "json", and "all". [default: csv]
  -i INPUT_FILE                          Load subdomains from file
  -t TIMEOUT                             Set timeout for network requests [default:5]
  --log-level=LEVEL                      If specified, then the log level will be set to
                                         the specified value.  Valid values are "debug", "info",
                                         "warning", "error", and "critical". [default: critical]
"""


# Standard Python Libraries
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import logging
import os
import requests
import socket
import ssl
import sys
from typing import Any, Dict, List

# Third-Party Libraries
import docopt
from schema import And, Or, Schema, SchemaError, Use
from tqdm import tqdm

# TODO make param with default value
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
CSV_HEADING = "Domain,Cert Common Name,Organization Name,Organization Unit Name,Certificate Start,Expiration,Alive"


@dataclass
class Domain:
    domain: str
    cert_common_name: str = None
    start: str = None
    expiration: str = None
    organization_name: str = None
    organizational_unit_name: str = None
    # alive is false if connection was Reset, Refused, or Timed Out
    alive: bool = False

    def __str__(self):
        return f"{self.domain},{self.cert_common_name},{self.organization_name},{self.organizational_unit_name},{self.start},{self.expiration},{self.alive}"


# Get certificate matching identities based on a root domain
def pull_certs(domain: str) -> Dict[str, Any]:
    URL = f"https://crt.sh/?Identity={domain}&output=json&exclude=expired"
    # This can take a LONG time if you a querying a root domain so let's give it some time
    request = requests.get(URL, headers={'User-Agent': USER_AGENT}, timeout=60)
    domains = {}
    if request.ok:
        try:
            response = request.content.decode('utf-8')
            data = json.loads(response)
            for cert_entry in data:
                for domain in cert_entry['name_value'].splitlines():
                    domains[domain] = Domain(domain, cert_entry['common_name'], cert_entry['not_before'], cert_entry['not_after'])
            logging.info(f"Identified {len(domains)} domains..")
            return domains
        except Exception as e:
            print("Error %s" % (e))
    elif request.status_code == requests.codes.forbidden:
        logging.critical(f"You are being blocked from crt.sh {URL}: {request}")
        sys.exit(1)
    else:
        logging.critical(f"Unable to connect to crt.sh {URL}: {request}")
        sys.exit(1)


def get_cert_info(domains: Dict[str, Any], timeout: int, scanned: List[str]) -> Dict[str, Any]:
    subjectaltname = {}
    for domain in tqdm(domains):
        # Dont connect to wildcard certs
        if '*' not in domain:
            cert = attempt_https_connection(domain, timeout)
            if cert:
                subject = dict(subject_field[0] for subject_field in cert['subject'])
                if 'organizationName' in subject:
                    setattr(domains[domain], 'organization_name', subject['organizationName'].replace(",", ""))
                if 'organizationalUnitName' in subject:
                    setattr(domains[domain], 'organizational_unit_name', subject['organizationalUnitName'].replace(",", ""))
                setattr(domains[domain], 'alive', True)
                setattr(domains[domain], 'start', date_time_conversion(cert['notBefore']))
                setattr(domains[domain], 'expiration', date_time_conversion(cert['notAfter']))
                if "subjectAltName" in cert:
                    for dns_entry in cert["subjectAltName"]:
                        # Subject altnames are in format ("DNS":"example.com")
                        altname = dns_entry[1]
                        if altname not in domains and altname not in scanned:
                            subjectaltname[altname] = Domain(altname, subject['commonName'])
    # Oh boy! Undefined depth Recursion! Let's keep track of visited domains
    if subjectaltname:
        # TODO update to python 3.9 union domains | get_cert_info(subjectaltname, timeout, (scanned + list(domains.keys())))
        logging.info(f"Identified {len(subjectaltname)} Subject Alternative Name domains..")
        # We set domains to the union of scraped domains and domains within the subjectAltName
        domains = {**domains, **get_cert_info(subjectaltname, timeout, (scanned + list(domains.keys())))}
    return domains


# Attempt to make connection to domain over 443 to pull certificate information
def attempt_https_connection(domain: str, timeout: int) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            # TODO ignore CERTIFICATE_VERIFY_FAILED
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert
    # errno 8
    except socket.gaierror as e:
        logging.debug(f"{domain}: No DNS record: {e}")
    # errno 54/60/61 Connection
    except socket.error as e:
        logging.debug(f"{domain}: Connection Reset, Refused, or Timed Out: {e}")
    # If certificate does not match hostname
    except ssl.CertificateError as e:
        logging.debug(f"{domain}: Certificate Error: {e}")
    # I know, general exceptions bring great shame, but network connections can be weird
    except Exception as e:
        logging.critical(f"{domain}: General Error: {e}")


# Convert date time to match crt.sh format of %Y-%m-%dT%H:%M:%S
def date_time_conversion(timestamp: str) -> str:
    input_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    output_date_fmt = '%Y-%m-%dT%H:%M:%S'
    temp = datetime.strptime(timestamp, input_date_fmt)
    return temp.strftime(output_date_fmt)


# Read domains in from file
def get_domains_from_file(file: str) -> List[str]:
    domains = {}
    domains_file = open(file, "r")
    domains_input = domains_file.readlines()
    # Remove all newlines
    for domain in domains_input:
        domains[domain.strip()] = Domain(domain.strip())
    return domains


# Print results to stdout
def print_output(results: Dict[str, Any]) -> None:
    print(CSV_HEADING)
    for domain in results:
        print(results[domain])


# Write results to CSV file
def write_output_to_csv(results: Dict[str, Any], output: str) -> None:
    with open(f"{output}.csv", "w") as f:
        f.write(f"{CSV_HEADING}\n")
        for domain in results:
            f.write(f"{results[domain]}\n")


# Write results to JSON
def write_output_to_json(results: Dict[str, Any], output: str) -> None:
    with open(f"{output}.json", "w") as f:
        json.dump([asdict(results[domain])
                   for domain in results], f, indent=4, sort_keys=True)


def main() -> None:
    ascii_art = """           ██████╗███████╗██████╗ ████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
          ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
          ██║     █████╗  ██████╔╝   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
          ██║     ██╔══╝  ██╔══██╗   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
          ╚██████╗███████╗██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
           ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝"""
    print(ascii_art)
    args: Dict[str, str] = docopt.docopt(__doc__)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning",
                                "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "-f": And(
                str,
                Use(str.lower),
                lambda n: n in ("csv", "json", "all"),
                error="Possible values for output file type are csv and json",
            ),
            "-i": Or(
                None,
                And(
                    str,
                    lambda file: os.path.isfile(file),
                    error="Input file doesn't exist!",
                ),
            ),
            "-o": Or(None, str),
            "-d": Or(None, str),
            "-t": Or(None, Use(int)),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    target_domain: str = validated_args["-d"]
    output: str = validated_args["-o"]
    output_file_type: str = validated_args["-f"]
    input_file: str = validated_args["-i"]
    timeout: str = validated_args["-t"]
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s",
        level=log_level.upper())

    if input_file:
        domains = get_domains_from_file(input_file)
    else:
        domains = pull_certs(target_domain)

    results = get_cert_info(domains, timeout, [])

    if output:
        if output_file_type == "csv" or output_file_type == "all":
            write_output_to_csv(results, output)
        if output_file_type == "json" or output_file_type == "all":
            write_output_to_json(results, output)
    else:
        print_output(results)

    # Stop logging and clean up
    logging.shutdown()

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>


if __name__ == "__main__":
    main()
