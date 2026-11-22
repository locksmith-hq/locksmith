"""Cognito pre-sign-up trigger: only emails on the closed list may create an account.

Federated sign-in (Google) auto-creates a pool user, so the pool's admin-create-only
setting does not stop strangers; this does. Fails closed: empty list rejects everyone.
"""
import os


def allowed():
    return {e.strip().lower() for e in os.environ.get("ALLOWED_EMAILS", "").split(",") if e.strip()}


def handler(event, context):
    attrs = event["request"]["userAttributes"]
    email = (attrs.get("email") or "").strip().lower()
    if email not in allowed() or attrs.get("email_verified") != "true":
        raise Exception("Sign-in is not allowed for this account")
    event["response"]["autoConfirmUser"] = True
    event["response"]["autoVerifyEmail"] = True
    return event
