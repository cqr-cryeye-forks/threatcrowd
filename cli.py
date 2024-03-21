import json
from argparse import ArgumentParser

import requests

requests.packages.urllib3.disable_warnings()


def cli(parser: ArgumentParser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-d", "--domain",
        type=str,
    )
    group.add_argument(
        "-i", "--ip",
        type=str,
    )
    group.add_argument(
        "-e", "--email",
        type=str,
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="output.json"
    )
    return parser.parse_args()


def formate_domain_data(data: dict):
    return {
        "d_resolutions": data.get("resolutions", []),
        "d_emails": [{"email": email} for email in data.get("emails", []) if email],
        "d_subdomains": [{"subdomains": subdomain} for subdomain in data.get("subdomains", []) if subdomain],
    }


def formate_email_data(data: dict):
    return {
        "e_domains": [{"domain": domain} for domain in data.get("domains", []) if domain]
    }


def formate_ip_data(data: dict):
    return {
        "i_resolutions": data.get("resolutions", []),
    }


def get_threatcrowd_information(type_: str, target: str) -> dict:
    resp = requests.get(
        f"https://ci-www.threatcrowd.org/searchApi/v2/{type_}/report/",
        params={type_: target},
        verify=False
    )
    print(resp.url, resp.status_code)
    if resp.status_code != 200:
        print(resp.content)
    else:
        try:
            return resp.json()
        except Exception as e:
            print(e)

    print("Failed.")
    return {}


def main():
    parser = ArgumentParser()
    args = cli(parser)
    if args.domain:
        data = get_threatcrowd_information(type_="domain", target=args.domain)
        data = formate_domain_data(data)
    elif args.email:
        data = get_threatcrowd_information(type_="email", target=args.email)
        data = formate_email_data(data)
    else:
        data = get_threatcrowd_information(type_="ip", target=args.ip)
        data = formate_ip_data(data)

    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2)


if __name__ == '__main__':
    main()
