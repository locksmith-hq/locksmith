// Hand-written fixtures for the types in this package (not generated). Names, ARNs and ids only:
// a binding view never carries a secret, so neither do its fixtures.
import type { BindingView } from "./BindingView";

/** Mock data for the Bindings page until the read-only binding list endpoint exists (D2-2). */
export const bindingFixtures: BindingView[] = [
  { kind: "http", secret_id: "00000000-0000-4000-8000-000000000020", origin: "https://api.stripe.com", header: "Authorization" },
  {
    kind: "aws",
    secret_id: "00000000-0000-4000-8000-000000000021",
    role_arn: "arn:aws:iam::123456789012:role/locksmith-dev",
    region: "us-east-1",
    allowed_actions: ["s3:GetObject", "s3:ListBucket"],
    vend: true,
    max_duration_secs: 900,
  },
  {
    kind: "aws",
    secret_id: "00000000-0000-4000-8000-000000000022",
    role_arn: "arn:aws:iam::123456789012:role/locksmith-readonly",
    region: "eu-west-1",
    allowed_actions: [],
    vend: false,
    max_duration_secs: 3600,
  },
];
