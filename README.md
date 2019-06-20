# Certificate Transparency to Slack

This is a Python script that scrapes the [Cert Spotter API](https://sslmate.com/certspotter/) for newly issued certificates for domains you are monitoring and dumps them to a Slack channel.

There are a number of use cases for why you might want to do this:

  * Blue/Security teams should be pro-actively monitoring their domains for (i) misissuance of certificates and (ii) new infrastructure and services being spun up which may be inappropriately exposed to the public internet
  * Red-teamers and Bug Bounty hunters alike can also use this to be alerted when certificates have been issued which could indicate new targets to perform recon and assessments on

The script has been written, and is intended to run in AWS Lambda.

Note: Please feel free to contribute and make pull requests as I know there will be more efficient ways to do this

## How does it work?

The script does the following:

  * Checks whether this is the first time the domain is being monitored (i.e., does an S3 object for the domain already exist?)
  * If this domain has not been monitored before then the script will call out to the Cert Spotter API, grab the latest issued certificate ID and store it in an S3 object. We start monitoring from this point on.
  * If this domain has already been monitored then the script pulls the certificate ID out of the S3 object and checks to see if any certificates have been issued since that certificate ID
  * Dump any new certificates to Slack

I have compared this script with Facebook's CT monitoring service, Cert Spotter (e-mail service) and several others - this tool always alerts me the fastest.

Here's a diagram which shows both scenarios (top: new domain and bottom: subsequent runs)

![how-it-works-diagram](screenshots/how-it-works.png?raw=true "how-it-works-diagram")

## What do I need?

You'll need the following:

  * S3 bucket - doesn't matter what you call it but it will be referenced in the script
  * [Cert Spotter API Credentials](https://sslmate.com/account/api_credentials) - there is a free tier which allows 100 full-domain queries/hour
  * [Slack Incoming Webhook](https://api.slack.com/incoming-webhooks) - really easy to create an app and link it to a #channel of your choice
  * Domains you want to monitor!
  * Update the script with the above information
  * Update the .yml if you intend to use it
  
## Screenshots

![Alt text](screenshots/slack-alert.png?raw=true "slack-alert")

## Join the conversation

A public Slack Workspace exists for a [previous project of mine](https://github.com/emtunc/SlackPirate)  - I'm still on there so anyone can join to discuss new features, changes, feature requests or simply ask for help. Here's the invite link: 

https://join.slack.com/t/slackpirate/shared_invite/enQtNTIyNjMxNDUyMzc0LTkzY2RkNGRlYTFiNWQ4OTYxMjYyZDRjZTAxZmEyNzAwZWVkYmVmZjk2MzJmYWQ5ODI4MmYxNmQyNDk2OTQ3MTQ
