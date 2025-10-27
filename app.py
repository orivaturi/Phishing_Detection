
from flask import Flask, request, render_template
import funcs
import const


app = Flask(__name__)


sample_mail = const.SAMPLE_EMAIL


@app.route('/', methods=['GET', 'POST'])
def homepage():
    email_content = ""
    results = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'sample':
            email_content = sample_mail

        elif action == 'analyze':
            if 'email_file' in request.files:
                file = request.files['email_file']
                if file and file.filename.endswith('.txt'):
                    email_content = file.read().decode('utf-8')
                else:
                    email_content = request.form.get('email_content', '')
            else:
                email_content = request.form.get('email_content', '')

            if email_content.strip():
                urls = funcs.extract_urls(email_content)
                emails = funcs.extract_emails(email_content)

                keywords_found, security_score = funcs.check_keywords(email_content)
                suspected_urls, urls_score = funcs.check_urls(urls)
                suspected_emails, emails_score = funcs.check_email(emails)

                total_security_score = security_score + urls_score + emails_score

                results = {
                    'total_score': total_security_score,
                    'keywords_found': keywords_found,
                    'suspected_urls': suspected_urls,
                    'suspected_emails': suspected_emails
                }

    return render_template('phishing_template.html', email_content=email_content, results=results)


if __name__ == '__main__':
    app.run(debug=True, port=5091)

