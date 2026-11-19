"""Offline trust-policy test for the GitHub OIDC apply role (task 4.2).

Renders infra/tofu/base/policies/*.tftpl with the variable defaults from
infra/tofu/base/oidc.tf (placeholders are plain ${name}) and asserts the trust is
exact: aud sts.amazonaws.com, sub for locksmith-hq/locksmith only, no wildcard,
and that the role's permissions explicitly deny the guardrail services.
"""
import json
import pathlib
import re
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1] / "base"
OIDC = (BASE / "oidc.tf").read_text()
PROVIDER = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"


def default_of(name):
    m = re.search(r'variable "%s" \{.*?default\s*=\s*"([^"]*)"' % name, OIDC, re.S)
    assert m, name
    return m.group(1)


def render(fname, **vars_):
    text = (BASE / "policies" / fname).read_text()
    text = re.sub(r"\$\{(\w+)\}", lambda m: vars_[m.group(1)], text)
    return json.loads(text)


REPO = default_of("github_repo")
ENV = default_of("github_apply_environment")
TRUST = render("github-apply-trust.json.tftpl", oidc_provider_arn=PROVIDER, github_repo=REPO, github_environment=ENV)
PERMS = render("github-apply-permissions.json.tftpl", region="us-east-1")


class TrustPolicyTest(unittest.TestCase):
    def test_single_web_identity_statement(self):
        self.assertEqual(len(TRUST["Statement"]), 1)
        st = TRUST["Statement"][0]
        self.assertEqual(st["Effect"], "Allow")
        self.assertEqual(st["Action"], "sts:AssumeRoleWithWebIdentity")
        self.assertEqual(st["Principal"], {"Federated": PROVIDER})

    def test_sub_is_exact_no_wildcard(self):
        cond = TRUST["Statement"][0]["Condition"]
        self.assertEqual(list(cond), ["StringEquals"], "only exact-match operators")
        sub = cond["StringEquals"]["token.actions.githubusercontent.com:sub"]
        self.assertEqual(sub, "repo:locksmith-hq/locksmith:environment:aws-base-apply")
        self.assertIsInstance(sub, str)
        self.assertNotRegex(sub, r"[*?]")
        self.assertEqual(REPO, "locksmith-hq/locksmith")

    def test_aud_is_sts(self):
        aud = TRUST["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"]
        self.assertEqual(aud, "sts.amazonaws.com")

    def test_no_like_conditions_or_wildcard_principal(self):
        raw = json.dumps(TRUST)
        self.assertNotIn("StringLike", raw)
        self.assertNotIn('"*"', raw)

    def test_provider_audience_and_url(self):
        self.assertIn('client_id_list = ["sts.amazonaws.com"]', OIDC)
        self.assertIn('url            = "https://token.actions.githubusercontent.com"', OIDC)

    def test_variables_reject_wildcards(self):
        self.assertIn("can(regex(", OIDC)
        self.assertEqual(OIDC.count("validation {"), 2)

    def test_ci_role_cannot_touch_guardrails(self):
        denies = [s for s in PERMS["Statement"] if s["Effect"] == "Deny"]
        denied = {a for s in denies for a in s["Action"]}
        for a in ("organizations:*", "budgets:*", "ce:*", "account:*", "sso:*"):
            self.assertIn(a, denied)
        for a in ("iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:DeleteOpenIDConnectProvider"):
            self.assertIn(a, denied)
        allowed = {a for s in PERMS["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
        for a in allowed:
            self.assertFalse(a.split(":")[0] in {"organizations", "budgets", "ce", "account", "sso"}, a)
            self.assertNotEqual(a, "*")
            self.assertNotEqual(a, "iam:*")

    def test_ci_role_can_refresh_its_own_iam_resources(self):
        allowed = {a for s in PERMS["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
        for a in ("iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:GetOpenIDConnectProvider", "iam:ListOpenIDConnectProviderTags"):
            self.assertIn(a, allowed)


if __name__ == "__main__":
    unittest.main()
