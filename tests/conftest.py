"""Shared test configuration.

Local fixtures use 127.0.0.1. The deployed verifier blocks private hosts by
default; only test processes opt in before any config module is imported.
"""
import os

os.environ.setdefault("VERIFY_ALLOW_PRIVATE_HOSTS", "1")
