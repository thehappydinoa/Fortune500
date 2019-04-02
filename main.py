#!/usr/bin/env python3
from urllib.parse import urlsplit

import dns.resolver
import requests
from bs4 import BeautifulSoup


def threat_crowd(domain):
    response = requests.get(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(domain))
    return set(response.json().get("subdomains"))


def virus_total(domain):
    response = requests.get(
        "https://www.virustotal.com/en/domain/{}/information/".format(domain))
    soup = BeautifulSoup(response.content, features="html.parser")
    subdomains_html = soup.find(id="observed-subdomains")
    if subdomains_html:
        subdomain_html = subdomains_html.find_all("div")
        return set([str(domain.find("a").contents) for domain in subdomain_html])
    return set()


def crt_sh(domain):
    response = requests.get("https://crt.sh/?q=%25.{}".format(domain))
    soup = BeautifulSoup(response.content, features="html.parser")
    if not soup.find("i"):
        tables = soup.find_all("table")
        cert_table = tables[1].find("table")
        trs = cert_table.find_all("tr")
        subdomains = set()
        for tr in trs:
            identity = tr.find_all("td")
            if identity:
                domain = identity[4].contents[0]
                if not "*" in domain:
                    subdomains.add(domain)
        return subdomains
    return set()


class Domain(object):
    """Domain class"""

    def __init__(self, name):
        self.name = name.lower().replace("www.", "")
        self.subdomains = set()
        self.valid = False
        self.mail_server = False

        self.subdomain_finders = [threat_crowd, virus_total, crt_sh]

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def is_valid(self):
        # Check if valid
        if not self.valid:
            Resolver = dns.resolver.Resolver()
            Resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
            try:
                ip = Resolver.query(self.name, "A")[0].to_text()
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                ip = None
            self.valid = bool(ip)
        return self.valid

    def is_mail_server(self):
        # Check if main server
        if not self.mail_server:
            try:
                records = dns.resolver.query(self.name, "MX")
                mx_records = [Domain(str(record.exchange))
                              for record in records]
                self.subdomains.union(set(mx_records))
                self.mail_server = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self.mail_server = False
        return self.mail_server

    def find_subdomains(self):
        # Finds for subdomains
        if not self.subdomains:
            for subdomain_finder in self.subdomain_finders:
                try:
                    subdomains = subdomain_finder(self.name)
                    if subdomains:
                        self.subdomains.union(subdomains)
                except Exception:
                    continue
        return self.subdomains


def get_domain(url):
    return urlsplit(url).netloc


def find_mail_servers(domains):
    mail_servers = set()

    try:
        for domain in domains:
            print("Checking {}...".format(domain))
            if domain.is_valid():
                if domain.is_mail_server():
                    print("{} is a valid mail server".format(domain))
                    mail_servers.add(domain)
                else:
                    print("Searching {} for subdomains...".format(domain))
                    subdomains = domain.find_subdomains()
                    if subdomains:
                        mail_servers.union(find_mail_servers(subdomains))
            else:
                print("{} is not valid".format(domain))
    except KeyboardInterrupt:
        print("Finishing Up...")

    return mail_servers


def main():
    FORTUNE_500_JSON = "https://opendata.arcgis.com/datasets/a4d813c396934fc09d0b801a0c491852_0.geojson"

    response = requests.get(FORTUNE_500_JSON).json()
    domains = [Domain(get_domain(d.get("properties").get("WEBSITE")))
               for d in response.get("features")]

    # with open("input.txt", "r") as input:
    #     domains = [Domain(d.strip()) for d in input.readlines()]

    if not domains:
        print("No Domains Found")
        exit(1)

    mail_servers = find_mail_servers(domains)
    print(mail_servers)

    with open("output.txt", "a") as output:
        for mail_server in mail_servers:
            output.write(str(mail_server) + "\n")


if __name__ == "__main__":
    main()
