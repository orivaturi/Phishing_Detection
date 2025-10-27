import funcs
import sys


def main():
    if len(sys.argv) != 2:
        print('File Input Error')
        sys.exit(1)

    filename = sys.argv[1]
    received_email = funcs.load_emails(filename)
    urls = funcs.extract_urls(received_email)
    emails = funcs.extract_emails(received_email)

    keywords_found, security_score = funcs.check_keywords(received_email)
    suspected_urls, urls_score = funcs.check_urls(urls)
    suspected_emails, emails_score = funcs.check_email(emails)

    total_security_score = security_score + urls_score + emails_score

    print()
    print('***** EMAIL ANALYSIS*****\n')
    print(f'User received E-mail contained total of {len(urls)} URLs and {len(emails)} email addresses.\n')
    print(f'There were {len(keywords_found)} suspicious words found.')
    if keywords_found:
        print(f'The following keywords were found:')
        for keyword in keywords_found:
            print(f' - {keyword}')
        print()
    if suspected_urls:
        print(f'The following URLs were found:')
        print()
        for url in suspected_urls:
            print(f' • {url["url"]}: with a score of {url["score"]}')
            for issue in url['issues']:
                print(f' - {issue}')
            print()
        print(f'The total score for URLs is {urls_score}\n')
    if suspected_emails:
        print(f'The following emails were found:')
        print()
        for email in suspected_emails:
            print(f' • {email["email"]}: with a score of {email["score"]}')
            for issue in email['issues']:
                print(f' - {issue}')
            print()
        print(f'The total score for emails is {emails_score}\n')
    print()
    print(f'TOTAL SECURITY SCORE: {total_security_score}')
    if total_security_score >= 20:
        print('HIGH RISK: Contact Security teams, Email is suspected as phishing!\n')
    elif total_security_score >= 10:
        print('MEDIUM RISK: Refer the Email with extra caution.\n')
    elif total_security_score > 0:
        print('LOW RISK: Some concerns, but probably valid.\n')
    else:
        print('All good, it appears to be a legitimate email.\n')


if __name__ == '__main__':
    main()