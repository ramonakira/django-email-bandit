from django.core.mail.backends import locmem

from bandit.backends.base import HijackBackendMixin, LogOnlyBackendMixin


class TestingHijackSMTPBackend(HijackBackendMixin, locmem.EmailBackend): ...


class TestingLogOnlySMTPBackend(LogOnlyBackendMixin, locmem.EmailBackend): ...
