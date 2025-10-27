import const
import requests
import validators
import ipaddress
import tldextract
from urllib.parse import urlparse
from typing import Dict, List, Tuple


def load_popular_domains() -> List[str]:
    try:
        response = requests.get(const.KNOWN_GOOD_DOMAINS_ENDPOINT)
        if response.status_code == 200:
            domains = response.text.strip().split('\n')
            return domains
        else:
            print("No popular domains found, Using local domains list")
            return const.KNOWN_GOOD_URLS

    except Exception as e:
        print(f"Error loading domains {e}")
        return const.KNOWN_GOOD_URLS


popular_domains = load_popular_domains()
suspected_keywords = const.SUSPECTED_KEYWORDS
legitimate_TLDs = const.LEGITIMATE_TLDS


def load_emails(filename: str) -> str:
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()
            return content.lower()
    except Exception as e:
        print(f'File "{filename}" not found.')
        print("Please try another email")
        return ""


def check_keywords(text: str) -> Tuple[List, int]:
    security_score = 0
    keywords_found = []
    for score, keywords in suspected_keywords.items():
        for keyword in keywords:
            if keyword in text:
                count = text.count(keyword)
                security_score += score * count
                keywords_found.append(f'{keyword} appears {count} times')
    return keywords_found, security_score


def extract_emails(text: str) -> List[str]:
    words = text.split()
    emails = []
    for word in words:
        clean_word = word.strip('.,;!?()[]{}').lower()
        if validators.email(clean_word):
            emails.append(clean_word)
    return emails


def extract_urls(text: str) -> List[str]:
    words = text.split()
    urls = []
    for word in words:
        clean_word = word.strip('.,;!?()[]{}')
        if validators.url(clean_word):
            urls.append(clean_word)
    return urls


def check_urls(urls: list[str]) -> Tuple[List[Dict], int]:
    suspected_urls = []
    urls_score = 0

    for url in urls:
        score = 0
        issues = []
        try:
            parted = urlparse(url)
            domain = parted.netloc.lower()

            score, issues = domain_analyze(domain)

            if score > 0:
                suspected_urls.append({
                    'url': url,
                    'score': score,
                    'issues': issues
                })

            urls_score += score

        except Exception as e:
            suspected_urls.append({
                'url': url,
                'score': 7,
                'issues': ['Malformed URL, could not be analyzed']
            })
            urls_score += 7

    return suspected_urls, urls_score


def check_email(emails: list[str]) -> Tuple[List[Dict], int]:
    suspected_emails = []
    emails_score = 0

    for email in emails:
        score = 0
        issues = []

        if '@' in email:
            full_domain = email.split('@')[1].lower()
            if is_suspicious_email_pattern(email):
                score += 3
                issues.append('Suspicious email sender name')

            domain_score, domain_issues = domain_analyze(full_domain)

            score += domain_score
            issues.extend(domain_issues)

        if score > 0:
            suspected_emails.append({
                'email': email,
                'score': score,
                'issues': issues
            })
        emails_score += score

    return suspected_emails, emails_score


def is_suspicious_email_pattern(email: str) -> bool:
    suspicious_names = const.SUSPECTED_SENDER_NAMES
    if '@' in email:
        local_part = email.split('@')[0]
        if local_part in suspicious_names:
            return True
        else:
            return False



def domain_analyze(domain: str) -> Tuple[int, List[str]]:
    score = 0
    issues = []

    try:
        ipaddress.ip_address(domain.split(':')[0])
        score += 30
        issues.append(f'IMPORTANT: {domain} Uses IP address instead of domain name')
        return score, issues
    except ValueError:
        pass

        if domain not in popular_domains:
            score += 5
            issues.append(f'Unknown domain: {domain} ')

    extracted = tldextract.extract(domain)

    if f".{extracted.suffix}" not in const.LEGITIMATE_TLDS:
        score += 5
        issues.append(f'Domain ends with: {extracted.suffix} - Not Legitimate TLD')

    if extracted.subdomain and len(extracted.subdomain.split('.')) >= 2:
        score += 2
        issues.append('More than 2 subdomains, might be phishing')

    return score, issues




