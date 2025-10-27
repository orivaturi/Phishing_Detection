SUSPECTED_KEYWORDS = {
            3: ['urgent', 'now', 'immediately', 'immediate',
                'expired', 'expiring', 'running', 'running out',
                'verify', 'verifying', 'verified', 'verification'],
            4: ['required', 'log in', 'sign in', 'confirm', 'confirmation',
                'action required', 'suspend', 'suspended', 'locked'],
            5: ['payment', 'security alert', 'id:']
        }

LEGITIMATE_TLDS = [
    '.com', '.co.il', '.org', '.io', '.net', '.edu', '.gov.il'
]

KNOWN_GOOD_DOMAINS_ENDPOINT = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"

KNOWN_GOOD_URLS = [
    'upwind.io', 'google.com', 'microsoft.com', 'apple.com', 'company.com',
    'github.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'paypal.com', 'dhl.com', 'amazon.com'
]

SUSPECTED_SENDER_NAMES = [
            'noreply', 'no-reply', 'donotreply', 'admin', 'administrator',
            'security', 'support', 'help', 'service', 'urgent'
        ]


SAMPLE_EMAIL = """Subject: URGENT: Your Account Will Be Suspended - Immediate Action Required

From: donotreply@rnicrosoft.urgent-support.com
To: user@example.com

Your Pay-Pal account will be suspended unless you verify immediately.
Click here: http://173.0.48.230/login
Contact us: suport@rnicrosoft.com
"""
