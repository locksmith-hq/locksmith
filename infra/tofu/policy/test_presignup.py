import importlib.util, os, pathlib, unittest, zipfile

L = pathlib.Path(__file__).resolve().parents[1] / "base" / "lambda"
spec = importlib.util.spec_from_file_location("presignup", L / "presignup.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def ev(email, verified="true"):
    return {"request": {"userAttributes": {"email": email, "email_verified": verified}}, "response": {}}


class PreSignUp(unittest.TestCase):
    def setUp(self):
        os.environ["ALLOWED_EMAILS"] = "Me@Example.com, you@example.com"

    def test_allowed_email_passes_case_insensitively(self):
        self.assertTrue(m.handler(ev("ME@example.com"), None)["response"]["autoConfirmUser"])

    def test_stranger_and_unverified_are_rejected(self):
        with self.assertRaises(Exception):
            m.handler(ev("evil@example.com"), None)
        with self.assertRaises(Exception):
            m.handler(ev("me@example.com", "false"), None)

    def test_empty_list_rejects_everyone(self):
        os.environ["ALLOWED_EMAILS"] = ""
        with self.assertRaises(Exception):
            m.handler(ev("me@example.com"), None)

    def test_committed_zip_matches_source(self):
        with zipfile.ZipFile(L / "presignup.zip") as z:
            self.assertEqual(z.namelist(), ["presignup.py"])
            self.assertEqual(z.read("presignup.py"), (L / "presignup.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
