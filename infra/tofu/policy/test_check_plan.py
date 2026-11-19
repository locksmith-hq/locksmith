import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).parent
SCRIPT = HERE / "check_plan.py"


def plan(*resources):
    return {"planned_values": {"root_module": {"resources": list(resources)}}}


def res(t, **values):
    return {"type": t, "address": f"{t}.x", "values": values}


def run(p):
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump(p, f)
        f.flush()
        return subprocess.run([sys.executable, str(SCRIPT), f.name], capture_output=True, text=True)


class PolicyTest(unittest.TestCase):
    def test_clean_plan_passes(self):
        r = run(plan(res("aws_s3_bucket"), res("aws_cloudwatch_log_group", retention_in_days=1),
                     res("aws_rds_cluster_instance", instance_class="db.serverless")))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_planted_alb_fails(self):
        r = run(plan(res("aws_lb", load_balancer_type="application")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("load balancer", r.stderr)

    def test_each_banned_resource_fails(self):
        for p in (res("aws_nat_gateway"), res("aws_secretsmanager_secret"), res("aws_route53_zone"),
                  res("aws_vpc_endpoint", vpc_endpoint_type="Interface"),
                  res("aws_cloudwatch_log_group", retention_in_days=7),
                  res("aws_cloudwatch_log_group"),
                  res("aws_instance", instance_type="m5.4xlarge")):
            self.assertEqual(run(plan(p)).returncode, 1, p)

    def test_gateway_endpoint_and_nested_module(self):
        self.assertEqual(run(plan(res("aws_vpc_endpoint", vpc_endpoint_type="Gateway"))).returncode, 0)
        nested = {"planned_values": {"root_module": {"child_modules": [{"resources": [res("aws_nat_gateway")]}]}}}
        self.assertEqual(run(nested).returncode, 1)


if __name__ == "__main__":
    unittest.main()
