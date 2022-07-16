import json
import logging
import os
import random
import sys

from builtins import OSError
from time import gmtime
from time import sleep

import boto3
import botocore
import json_log_formatter
import requests

# Config env var setup

# https://api.slack.com/incoming-webhooks
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
# Create an S3 bucket and put the name here - used to store the certificate IDs
S3_BUCKET = os.getenv("S3_BUCKET")
S3 = boto3.resource("s3") if S3_BUCKET else None
# Comma separated list of domains to monitor
MONITOR_DOMAINS = os.getenv("MONITOR_DOMAINS")
# https://sslmate.com/account/api_credentials
HEADERS = {"Authorization": "Bearer " + (os.getenv("CERTSPOTTER_API_TOKEN") or "")}
# Local filesystem, if used
FILESYSTEM_PATH = os.getenv("FILESYSTEM_PATH")
# How long to wait between executions
SLEEP_DELAY = int(os.getenv("SLEEP_DELAY") or 10 ^ 6)
# Debug will output extra logs for troubleshooting
DEBUG = os.getenv("DEBUG") == "true"
# Either json or syslog log formatting
LOG_FORMAT = os.getenv("LOG_FORMAT") or ""
# Excluded domains will not fire Slack alerts on
EXCLUDED_DOMAINS = ["test.example.com"]

# Setup logging
log = logging.getLogger(__name__)
if LOG_FORMAT.lower() == "json":
    formatter = json_log_formatter.VerboseJSONFormatter()
    json_handler = logging.StreamHandler()
    json_handler.setFormatter(formatter)
    log.addHandler(json_handler)
elif LOG_FORMAT.lower() == "syslog":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s.%(msecs)03dZ [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.Formatter.converter = gmtime

# Set log level based on DEBUG env var
if DEBUG:
    log.setLevel(logging.DEBUG)
else:
    log.setLevel(logging.INFO)


def check_if_domain_monitored(domain):
    # Checks to see if the domain is already being monitored - i.e., does the certificate ID already exist in
    # storage? If so, we can simply make a request for certs *after* that ID. Otherwise, we need to make an initial
    # request and start monitoring from this point onwards
    if S3_BUCKET:
        try:
            S3.Object(S3_BUCKET, domain).load()
            log.info("S3 object exists for this domain: " + domain)
            return True
        except botocore.exceptions.ClientError as e:
            # PS. For some reason, running this in Lambda returns a 403 forbidden when checking if object exists.
            # Running locally returns a 404. /shrug
            if e.response["Error"]["Code"] == "403":
                log.info(
                    "S3 object does not exist for the domain "
                    + domain
                    + " which probably means it's not being monitored"
                )
                store_latest_cert_id(domain)
    elif FILESYSTEM_PATH:
        if os.path.exists(os.path.join(FILESYSTEM_PATH, domain)):
            return True
        else:
            store_latest_cert_id(domain)


def store_latest_cert_id(domain):
    latest_cert_id = ""
    while True:
        query_certspotter_api(domain, latest_cert_id)
        response = requests.get(
            "https://api.certspotter.com/v1/issuances?domain="
            + domain
            + "&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer&after="
            + latest_cert_id,
            headers=HEADERS,
        ).json()
        if response:
            if DEBUG:
                log.debug(response)
            try:
                latest_cert_id = response[-1]["id"]
            except KeyError:
                log.error("Requests have been rate limited")
                return
        else:
            if S3_BUCKET:
                object = S3.Object(S3_BUCKET, domain)
                object.put(Body=json.dumps(latest_cert_id))
                log.info(
                    "S3 object with the latest cert ID should now exist for the domain "
                    + domain
                )
                break
            elif FILESYSTEM_PATH:
                with open(os.path.join(FILESYSTEM_PATH, domain), "w") as f:
                    f.write(latest_cert_id)
                log.info(
                    "File with the latest cert ID created for the domain "
                    + domain
                    + " with latest cert id as "
                    + latest_cert_id
                )
                break


def notify_slack_channel(
    colour: str, dns_names: str, issuer: str, not_before: str, cert_id: int
):
    payload = {
        "attachments": [
            {
                "fallback": f":rotating_light: New certificate issued! ID: {cert_id}:rotating_light:",
                "pretext": f":rotating_light: New certificate issued! ID: {cert_id}:rotating_light:",
            },
            {
                "title": "Certificate Valid from: ",
                "text": str(not_before),
                "color": colour,
            },
            {"title": "DNS Names: ", "text": str(dns_names), "color": colour},
            {"title": "Issuer: ", "text": str(issuer), "color": colour},
        ]
    }
    log.info(payload)
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json=payload)
        except requests.exceptions.RequestException as e:
            log.error(e)


def query_certspotter_api(domain, certificate_id):
    try:
        response = requests.get(
            "https://api.certspotter.com/v1/issuances?domain="
            + domain
            + "&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer&after="
            + certificate_id,
            headers=HEADERS,
        )
        return response
    except requests.exceptions.ConnectionError:
        log.error("Certspotter API unreachable")
        return None


def main():
    # startup check on required env vars
    log.info("Starting up cert monitor...")
    if not (S3_BUCKET or FILESYSTEM_PATH):
        log.error("S3 target nor filesystem path were set. Check your configs.")
        sys.exit(1)
    if not MONITOR_DOMAINS:
        log.error("No monitoring domains were provided. Check your configs.")
        sys.exit(1)
    if not SLACK_WEBHOOK:
        log.warning("No Slack webhook provided, writing payload to stdout.")
    if LOG_FORMAT.lower() not in ["syslog", "json"]:
        log.error("Invalid log format selected. Check your configs.")
        sys.exit(1)
    if FILESYSTEM_PATH:
        if not os.path.exists(FILESYSTEM_PATH):
            os.mkdir(FILESYSTEM_PATH)

    domains = MONITOR_DOMAINS.split(",")
    while True:
        random.shuffle(domains)
        for domain in domains:
            if check_if_domain_monitored(domain):
                if S3_BUCKET:
                    content_object = S3.Object(S3_BUCKET, domain)
                    file_content = content_object.get()["Body"].read().decode("utf-8")
                    certificate_id = json.loads(file_content)
                elif FILESYSTEM_PATH:
                    with open(os.path.join(FILESYSTEM_PATH, domain), "r") as f:
                        certificate_id = f.readline()
                response = query_certspotter_api(domain, certificate_id)
                response_json = response.json()
                if DEBUG:
                    log.debug(f"response: {response_json}")
                if response.status_code == 429:
                    log.error("Requests have been rate limited")
                    break
                elif response.status_code == 200 and not len(response_json):
                    log.info(f"No new certificates have been issued for {domain}")
                elif response.status_code == 200 and len(response_json):
                    for issued_cert in response_json:
                        if not any(
                            item in EXCLUDED_DOMAINS
                            for item in issued_cert["dns_names"]
                        ):
                            notify_slack_channel(
                                "#FF0000",
                                str(issued_cert["dns_names"]),
                                str(issued_cert["issuer"]),
                                str(issued_cert["not_before"]),
                                int(issued_cert["id"]),
                            )
                        else:
                            log.info(
                                f"Excluded domain in response: {domain} response: {response_json}"
                            )
                    if S3_BUCKET:
                        object = S3.Object(S3_BUCKET, domain)
                        object.put(Body=json.dumps(response_json[-1]["id"]))
                    elif FILESYSTEM_PATH:
                        try:
                            with open(os.path.join(FILESYSTEM_PATH, domain), "w") as f:
                                f.write(response_json[-1]["id"])
                        except OSError:
                            log.error("File I/O error", exc_info=1)
                            sys.exit(1)
        sleep(SLEEP_DELAY)


if __name__ == "__main__":
    main()
