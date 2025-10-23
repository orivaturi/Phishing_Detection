import re
import sys
import ipaddress
import validators
import tldextract
import requests
from urllib.parse import urlparse
from typing import Dict, List, Tuple

class EmailPhishingScanner:
    def __init__(self):
        self.SuspectedKeywords = {
            3: ['urgent', 'now', 'immediately', 'immediate',
                'expired', 'expiring', 'running', 'running out',
                'verify', 'verifying', 'verified', 'verification'],
            4: ['required', 'log in', 'sign in', 'confirm', 'confirmation',
                'action required', 'suspend', 'suspended', 'locked'],
            5: ['payment', 'security alert', 'id:']
        }


        self.popular_domains = self.load_popular_domains()


        self.LegitimateTLDS = [
            '.com', '.co.il', '.org', '.io', '.net', '.edu', '.gov.il'
        ]

    def load_popular_domains(self) -> set:
        try:
            url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                domains = set(response.text.strip().split('\n'))
                print(f'Total possible domains: {len(domains)}')
                return domains
            else:
                print("No popular domains found, Using local domains list")
                return self.get_minimal_domains()

        except Exception as e:
            print(f'Error loading domains: {e}')
            return self.get_minimal_domains()

    def get_minimal_domains(self) -> set:
        return{
            'upwind.io', 'google.com', 'microsoft.com', 'apple.com', 'company.com',
            'github.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'paypal.com', 'dhl.com', 'amazon.com'
            }

    def extract_urls(self, text: str) -> List[str]:
        words = text.split()
        urls = []

        for word in words:
            clean_word = word.strip('.,;!?()[]{}')
            if validators.url(clean_word):
                urls.append(clean_word)

        return urls

    def extract_emails(self, text: str) -> List[str]:
        words = text.split()
        emails = []

        for word in words:
            clean_word = word.strip('.,;!?()[]{}').lower()
            if validators.email(clean_word):
                emails.append(clean_word)

        return emails

    def load_email (self, filename: str) -> str:
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
                return content.lower()
        except FileNotFoundError:
            print(f'File "{filename}" not found.')
            sys.exit(1)
        except Exception as e:
            print(f"Error reading {filename}")
            sys.exit(1)

    def check_keywords(self, text: str) -> Tuple[List, int]:
        security_score = 0
        keywordsFound = []

        for score, keywords in self.SuspectedKeywords.items():
            for keyword in keywords:
                if keyword in text:
                    count = text.count(keyword)
                    security_score += score*count
                    keywordsFound.append(f'{keyword} appears {count} times')
        return keywordsFound, security_score

    def domain_check (self, domain:str) -> Tuple[int , list[str]]:
        score = 0
        issues = []
        try:
            ipaddress.ip_address(domain.split(':')[0])
            score += 25
            issues.append(f'IMPORTANT: {domain} Uses IP address instead of domain name')
        except ValueError:
            pass

        extracted = tldextract.extract(domain)
        main_domain = f"{extracted.domain}.{extracted.suffix}"

        if main_domain not in self.popular_domains:
            score += 5
            issues.append(f'Unknown domain: {main_domain}')


        if f".{extracted.suffix}" not in self.LegitimateTLDS:
            score += 4
            issues.append(f'Domain ends with .{extracted.suffix} - Not Legitimate TLD')

        if extracted.subdomain and len(extracted.subdomain.split('.')) > 1:
            score += 2
            issues.append('More than 3 subdomains, might be phishing')

        return score, issues



    def check_urls(self, urls: list[str]) -> Tuple[List[Dict], int]:
        suspected_urls = []
        urls_score = 0

        for url in urls:
            score = 0
            issues = []
            try:
                parted = urlparse(url)
                domain = parted.netloc.lower()

                score, issues = self.domain_check(domain)

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
                    'issues': 'Malformed URL, could not be analyzed'
                })
                urls_score += 7

        return suspected_urls, urls_score


    def check_email (self, emails: list[str]) -> Tuple[List[Dict], int]:
        suspected_emails = []
        emails_score = 0

        for email in emails:
            score = 0
            issues = []

            if '@' in email:
                domain = email.split('@')[1].lower()


                if re.search(r'noreply.*admin|security.*team|support.*urgent', email):
                    score += 3
                    issues.append('Suspicious email pattern')

                domain_score, domain_issues = self.domain_check(domain)

                score += domain_score
                issues+= domain_issues

            if score > 0:
                suspected_emails.append({
                    'email': email,
                    'score': score,
                    'issues': issues
                })
            emails_score += score

        return suspected_emails, emails_score


def main():
    if len(sys.argv) != 2:
        print('File Input Error')
        sys.exit(1)

    filename = sys.argv[1]

    Scanner = EmailPhishingScanner()

    email_str = Scanner.load_email(filename)

    urls = Scanner.extract_urls(email_str)
    emails = Scanner.extract_emails(email_str)

    keywords_found, security_score = Scanner.check_keywords(email_str)
    suspected_urls, urls_score = Scanner.check_urls(urls)
    suspected_emails, emails_score = Scanner.check_email(emails)

    total_security_score = security_score+ urls_score+ emails_score



    print('***** EMAIL ANALYSIS*****\n\n')

    print(f'Received E-mail contained total of {len(urls)} URLs and {len(emails)} email addresses.')
    print(f'There were {len(keywords_found)} suspicious words found.')

    if keywords_found:
        print(f'The following keywords were found:')
        for keyword in keywords_found:
            print(f' - {keyword}')

    if suspected_urls:
        print(f'The following URLs were found:')
        for url in suspected_urls:
            print(f' • {url["url"]}: with a score of {url["score"]}')
            for issue in url['issues']:
                print(f' - {issue}')
        print(f'The total score for URLs is {urls_score}')

    if suspected_emails:
        print(f'The following emails were found:')
        for email in suspected_emails:
            print(f' • {email["email"]}: with a score of {email["score"]}')
            for issue in email['issues']:
                print(f' - {issue}')
        print(f'The total score for emails is {emails_score}')

    print(f'TOTAL SECURITY SCORE: {total_security_score}')

    if total_security_score >= 20:
        print("HIGH RISK: Contact Security teams, Email is suspected as phishing!")
    elif total_security_score >= 10:
        print('MEDIUM RISK: Refer the Email with extra caution.')
    elif total_security_score > 0:
        print('LOW RISK: Some concerns, but probably valid.')
    else:
        print('✅ Appears to be a legitimate email.')


if __name__ == '__main__':
    main()
