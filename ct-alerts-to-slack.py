import boto3
import botocore
import json
from botocore.vendored import requests

S3 = boto3.resource('s3')
SLACK_WEBHOOK = ''  # https://api.slack.com/incoming-webhooks
S3_BUCKET = ''  # Create an S3 bucket and put the name here - used to store the certificate IDs
MONITOR_DOMAINS = ['']  # Comma separated list of domains to monitor
HEADERS = {'Authorization': 'Bearer '}  # https://sslmate.com/account/api_credentials


def check_if_domain_monitored(domain):
    """
    Checks to see if the domain is already being monitored - i.e., does the certificate ID already exist in the
    S3 bucket? If so, we can simply make a request for certs *after* that ID. Otherwise, we need to make an initial
    request and start monitoring from this point onwards
    PS. For some reason, running this in Lambda returns a 403 forbidden when checking if object exists.
    Running locally returns a 404. /shrug
    """
    try:
        S3.Object(S3_BUCKET, domain).load()
        print("S3 object exists for this domain: " + domain)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "403":
            print("S3 object does not exist for the domain " + domain +
                  " which probably means it's not being monitored")
            store_latest_cert_id_in_s3(domain)


def store_latest_cert_id_in_s3(domain):
    latest_cert_id = ''
    while True:
        request = requests.get(
            "https://api.certspotter.com/v1/issuances?domain=" + domain +
            "&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer&after=" + latest_cert_id,
            headers=HEADERS).json()
        if request:
            latest_cert_id = request[-1]['id']
        else:
            object = S3.Object(S3_BUCKET, domain)
            object.put(Body=json.dumps(latest_cert_id))
            print("S3 object with the latest cert ID should now exist for the domain " + domain)
            break


def notify_slack_channel(colour: str, dns_names: str, issuer: str, not_before: str):
    payload = {"attachments": [{
        "fallback": ":rotating_light: New certificate issued! :rotating_light:",
        "pretext": ":rotating_light: New certificate issued! :rotating_light:"},
        {"title": "Certificate Valid from: ", "text": str(not_before), "color": colour},
        {"title": "DNS Names: ", "text": str(dns_names), "color": colour},
        {"title": "Issuer: ", "text": str(issuer), "color": colour}
    ]}
    try:
        requests.post(SLACK_WEBHOOK, json=payload)
    except requests.exceptions.RequestException as e:
        print(e)


def handler(event, context):
    for domain in MONITOR_DOMAINS:
        if check_if_domain_monitored(domain):
            content_object = S3.Object(S3_BUCKET, domain)
            file_content = content_object.get()['Body'].read().decode('utf-8')
            certificate_transparency_id = json.loads(file_content)
            request = requests.get(
                "https://api.certspotter.com/v1/issuances?domain=" + domain +
                "&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer&after=" +
                certificate_transparency_id, headers=HEADERS).json()
            if request:
                for issued_cert in request:
                    notify_slack_channel('#FF0000',
                    str(issued_cert['dns_names']),
                    str(issued_cert['issuer']),
                    str(issued_cert['not_before'])
                    )
                object = S3.Object(S3_BUCKET, domain)
                object.put(Body=json.dumps(request[-1]['id']))
