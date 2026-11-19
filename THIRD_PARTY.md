# Third-party material

Locksmith is licensed under AGPL-3.0 (server components, see `LICENSE`) and Apache-2.0 (SDKs, CLI, plugins, schemas, see `LICENSE-APACHE`). This file lists data vendored into the repository. Dependencies are tracked separately by `cargo deny check licenses` and `npm`.

| Material | Location | Source | Licence |
|---|---|---|---|
| AWS service model (operation names, endpoint prefixes) | `crates/ls-proxy/src/aws/data/aws-model.json` | Derived from botocore service models shipped with aws-cli 2.15.6; regenerate with `scripts/gen-aws-model.py` | Apache-2.0, Copyright Amazon.com, Inc. or its affiliates |
| AWS Signature Version 4 test suite | `crates/ls-proxy/tests/fixtures/sigv4/` | awslabs/aws-c-auth signing test suite (header-based cases only); see the `NOTICE` file in that directory | Apache-2.0 (see `NOTICE`) |
