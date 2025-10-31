import os
import requests
import re
import fnmatch
import json

def sync():
    traefik_ip = os.environ.get("TRAEFIK_IP")
    traefik_api_url = os.environ.get("TRAEFIK_API_URL")
    adguard_url = os.environ.get("ADGUARD_URL")
    adguard_username = os.environ.get("ADGUARD_USERNAME")
    adguard_password = os.environ.get("ADGUARD_PASSWORD")
    ignore_ssl_warnings = os.environ.get("IGNORE_SSL_WARNINGS")
    allow_dns_delete = os.environ.get("ALLOW_DNS_DELETE")
    dns_delete_domain = os.environ.get("DNS_DELETE_DOMAIN")

    if None in [traefik_ip, traefik_api_url, adguard_url, adguard_username, adguard_password]:
        raise ValueError("One or more required environment variables are not set.")

    print(f"The value of ADGUARD_URL is: {adguard_url}")
    print(f"The value of TRAEFIK_API_URL is: {traefik_api_url}")

    # --- get Traefik routers and extract host() domains ---
    traefik_routers_response = requests.get(f"{traefik_api_url}http/routers")
    if traefik_routers_response.status_code != 200:
        raise ValueError(f"Failed to request Traefik API. Status code: {traefik_routers_response.status_code}")

    traefik_domains = []
    for router in traefik_routers_response.json():
        if "rule" in router and "Host(" in router["rule"]:
            match = re.search(r"Host\(`([^`]+)`\)", router["rule"])
            if match:
                traefik_domains.append(match.group(1))

    if not traefik_domains:
        print("No DNS names found in Traefik routers.")
        return

    # --- AdGuard session & auth ---
    session = requests.Session()
    if ignore_ssl_warnings:
        requests.packages.urllib3.disable_warnings()
        session.verify = False

    # Login to AdGuard (creates cookie 'agh_session' on success)
    login_payload = {"name": adguard_username, "password": adguard_password}
    login_resp = session.post(f"{adguard_url.rstrip('/')}/control/login", json=login_payload)
    if login_resp.status_code != 200:
        raise ValueError(f"Failed to login to AdGuard API. Status code: {login_resp.status_code}, content: {login_resp.text}")

    # Get current DNS rewrites
    list_resp = session.get(f"{adguard_url.rstrip('/')}/control/rewrite/list")
    if list_resp.status_code != 200:
        raise ValueError(f"Failed to get AdGuard rewrite list. Status code: {list_resp.status_code}, content: {list_resp.text}")

    try:
        rewrites = list_resp.json()
    except ValueError:
        raise ValueError(f"AdGuard rewrite list did not return JSON. Response text: {list_resp.text}")

    # Build mapping: domain -> set of answers (strings)
    adguard_rewrites = {}
    # The rewrite list items historically contain 'domain' and 'answer' fields.
    for entry in rewrites:
        domain = entry.get("domain")
        answer = entry.get("answer")
        if domain is None or answer is None:
            # be tolerant of slightly different schemas:
            # some older variants use 'domain'/'answer', some use 'domain'/'answers' or similar
            # if entry contains 'answers' list, flatten it
            if domain and isinstance(entry.get("answers"), list):
                answers = [str(a) for a in entry.get("answers")]
            else:
                continue
        else:
            answers = [str(answer)]
        adguard_rewrites.setdefault(domain, set()).update(answers)

    entries_to_update = []  # (domain, old_answers_set)
    hosts_to_add = []
    entries_to_delete = []

    # Compare Traefik domains with AdGuard rewrites
    for dns_name in traefik_domains:
        if dns_name in adguard_rewrites:
            answers = adguard_rewrites[dns_name]
            if traefik_ip not in answers or len(answers) > 1:
                # We will delete any answers != traefik_ip, then add traefik_ip if absent.
                entries_to_update.append((dns_name, answers))
        else:
            hosts_to_add.append(dns_name)

    # Find adguard domains that are not present in traefik_domains -> candidate delete
    for domain, answers in adguard_rewrites.items():
        if domain not in traefik_domains:
            if dns_delete_domain and fnmatch.fnmatch(domain, dns_delete_domain):
                print(f"Entry {domain} matches {dns_delete_domain} and is marked for deletion.")
                entries_to_delete.append((domain, answers))
            else:
                print(f"Entry {domain} does not match {dns_delete_domain} and is skipped.")

    # Helper functions for add/delete
    def add_rewrite(domain, answer):
        payload = {"domain": domain, "answer": answer}
        resp = session.post(f"{adguard_url.rstrip('/')}/control/rewrite/add", json=payload)
        if resp.status_code in (200, 201):
            print(f"Added AdGuard rewrite {domain} -> {answer}")
            return True
        else:
            print(f"Failed to add {domain} -> {answer}. Status code: {resp.status_code}, content: {resp.text}")
            return False

    def delete_rewrite(domain, answer):
        payload = {"domain": domain, "answer": answer}
        # API expects POST /control/rewrite/delete
        resp = session.post(f"{adguard_url.rstrip('/')}/control/rewrite/delete", json=payload)
        if resp.status_code == 200:
            print(f"Deleted AdGuard rewrite {domain} -> {answer}")
            return True
        else:
            print(f"Failed to delete {domain} -> {answer}. Status code: {resp.status_code}, content: {resp.text}")
            return False

    # Perform updates: delete old answers (not equal to traefik_ip) then ensure traefik_ip present
    for domain, answers in entries_to_update:
        # delete old answers that are not the desired IP
        for old_ans in list(answers):
            if old_ans != traefik_ip:
                delete_rewrite(domain, old_ans)
        # ensure desired A is present (add if needed)
        # After deletes, check if traefik_ip exists in current adguard_rewrites (we can't re-query easily here,
        # so attempt to add but ignore failures where it already exists)
        add_rewrite(domain, traefik_ip)

    # Add hosts
    for host in hosts_to_add:
        add_rewrite(host, traefik_ip)

    # Delete obsolete entries if allowed
    if allow_dns_delete:
        for domain, answers in entries_to_delete:
            for answer in list(answers):
                delete_rewrite(domain, answer)
    else:
        if entries_to_delete:
            print("ALLOW_DNS_DELETE not set; obsolete entries were detected but not deleted.")

if __name__ == "__main__":
    sync()
