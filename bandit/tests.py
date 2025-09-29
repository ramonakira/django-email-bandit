from django.core import mail

from django.conf import settings
from django.core.mail import EmailMessage
from django.test import TestCase, override_settings


@override_settings(BANDIT_EMAIL="bandit@example.com")
@override_settings(ADMINS=(("Admin", "admin@example.com"),))
class BaseBackendTestCase(TestCase): ...


@override_settings(EMAIL_BACKEND="bandit.test_backends.TestingHijackSMTPBackend")
class HijackBackendTestCase(BaseBackendTestCase):
    def assert_emails_are_hijacked(self, emails):
        for email in emails:
            email.send()

        self.assertEqual(len(mail.outbox), len(emails))

        if isinstance(settings.BANDIT_EMAIL, list):
            expected = settings.BANDIT_EMAIL
        else:
            expected = ["bandit@example.com"]

        self.assertEqual(mail.outbox[0].to, expected)

    def test_basic_hijack(self):
        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["to@example.com"],
            )
        ]
        self.assert_emails_are_hijacked(emails)

    @override_settings(
        BANDIT_EMAIL=[
            "bandit@example.com",
            "accomplice@example.com",
            "Hijacker <hijacker@example.com>",
        ]
    )
    def test_send_to_multiple_bandits(self):
        emails = [
            EmailMessage("Subject", "Content", "from@example.com", ["to@example.com"])
        ]
        self.assert_emails_are_hijacked(emails)

    def test_hijack_cc(self):
        """Emails with unapproved recipient in CC should be redirected to send to BANDIT_EMAIL."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                to=["admin@example.com"],
                cc=["to@example.com"],
            )
        ]
        self.assert_emails_are_hijacked(emails)

    def test_hijack_bcc(self):
        """Emails with unapproved recipient in BCC should be redirected to send to BANDIT_EMAIL."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                to=["admin@example.com"],
                bcc=["to@example.com"],
            )
        ]
        self.assert_emails_are_hijacked(emails)

    def test_send_to_mixed(self):
        """Emails with mixed recipients will be hijacked."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                ["to@example.com", "admin@example.com"],
            )
        ]
        self.assert_emails_are_hijacked(emails)

    def test_send_to_admins(self):
        """Admin emails should not be hijacked."""
        emails = [
            EmailMessage(
                "Subject", "Content", "from@example.com", ["admin@example.com"]
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        for sent_email in mail.outbox:
            self.assertEqual(
                sent_email.to,
                [
                    "admin@example.com",
                ],
            )

    def test_send_multiple(self):
        """Emails with mixed recipients will be hijacked."""
        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["to@example.com"],
            ),
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["admin@example.com"],
            ),
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        self.assertTrue("This email was hijacked" in mail.outbox[0].body)

        self.assertFalse("This email was hijacked" in mail.outbox[1].body)

    def test_whitelist_domain(self):
        """Emails send to whitelisted domains should not be hijacked"""
        addresses = [
            "foo@whitelisted.test.com",
            "<bar@whitelisted.test.com>",
            "Foo Bar <baz@whitelisted.test.com>",
        ]

        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=addresses,
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        for sent_mail in mail.outbox:
            self.assertEqual(sent_mail.to, addresses)

    @override_settings(BANDIT_REGEX_WHITELIST=["ba.*it@bandit\\.com", "joe@.*\\.org"])
    def test_whitelist_email_regex(self):
        """Emails send to whitelisted by regex should not be hijacked"""
        addresses = ["bandit@bandit.com", "<joe@bandit.org>", "Foo Bar <joe@joe.org>"]

        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=addresses,
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        for sent_mail in mail.outbox:
            self.assertEqual(sent_mail.to, addresses)

    @override_settings(BANDIT_REGEX_WHITELIST=["ba.*it@bandit\\.com", "joe@.*\\.org"])
    def test_whitelist_email_regex_not_passing(self):
        """Emails that don't match whitelist regex should be hijacked"""
        addresses = ["joe@bandit.com", "<joe@bandit.com>", "Foo Bar <joe@bandit.com>"]

        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=addresses,
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        for sent_mail in mail.outbox:
            self.assertEqual(sent_mail.to, ["bandit@example.com"])


@override_settings(EMAIL_BACKEND="bandit.test_backends.TestingLogOnlySMTPBackend")
class LogOnlyBackendTestCase(BaseBackendTestCase):
    def assert_emails_are_only_logged(self, emails):
        for email in emails:
            email.send()

        self.assertEqual(len(mail.outbox), 0)

    def test_basic_logonly(self):
        """Emails should only be logged."""
        emails = [
            EmailMessage("Subject", "Content", "from@example.com", ["to@example.com"])
        ]
        self.assert_emails_are_only_logged(emails)

    @override_settings(
        BANDIT_EMAIL=[
            "bandit@example.com",
            "accomplice@example.com",
            "Hijacker <hijacker@example.com>",
        ]
    )
    def test_send_to_multiple_bandits(self):
        """Even with multiple bandit emails the email are only logged."""
        emails = [
            EmailMessage("Subject", "Content", "from@example.com", ["to@example.com"])
        ]
        self.assert_emails_are_only_logged(emails)

    def test_hijack_cc(self):
        """Emails with unapproved recipient in CC should only be logged."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                to=["admin@example.com"],
                cc=["to@example.com"],
            )
        ]
        self.assert_emails_are_only_logged(emails)

    def test_hijack_bcc(self):
        """Emails with unapproved recipient in BCC should only be logged."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                to=["admin@example.com"],
                bcc=["to@example.com"],
            )
        ]
        self.assert_emails_are_only_logged(emails)

    def test_send_to_mixed(self):
        """Emails with mixed recipients will only be logged."""
        emails = [
            EmailMessage(
                "Subject",
                "Content",
                "from@example.com",
                ["to@example.com", "admin@example.com"],
            )
        ]
        self.assert_emails_are_only_logged(emails)

    def test_send_to_admins(self):
        """Admin emails should still be sent."""
        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["admin@example.com"],
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        self.assertEqual(mail.outbox[0].to, ["admin@example.com"])

    def test_send_multiple(self):
        """Only the email to the admin should be sent (the other should be logged)."""
        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["to@example.com"],
            ),
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=["admin@example.com"],
            ),
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(mail.outbox), 1)

    def test_whitelist_domain(self):
        """Emails send to whitelisted domains are still sent"""
        addresses = [
            "foo@whitelisted.test.com",
            "<bar@whitelisted.test.com>",
            "Foo Bar <baz@whitelisted.test.com>",
        ]

        emails = [
            EmailMessage(
                subject="Subject",
                body="Content",
                from_email="from@example.com",
                to=addresses,
            )
        ]

        for email in emails:
            email.send()

        self.assertEqual(len(emails), len(mail.outbox))

        for sent_mail in mail.outbox:
            self.assertEqual(sent_mail.to, addresses)
