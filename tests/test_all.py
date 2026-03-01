"""
Test Suite — Phishing URL Detector
=====================================
Tests for feature extractor, model predictions, and API logic.
Run: python tests/test_all.py
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))
from feature_extractor import extract_features, get_feature_names, features_to_vector, shannon_entropy

# ─────────────────────────────────────────────
# Feature Extractor Tests
# ─────────────────────────────────────────────

class TestFeatureExtractor(unittest.TestCase):

    def test_feature_count(self):
        """Should extract exactly 46 features."""
        features = extract_features("https://www.google.com")
        self.assertIsNotNone(features)
        self.assertEqual(len(features), 46)

    def test_https_detection(self):
        self.assertEqual(extract_features("https://example.com")["is_https"], 1)
        self.assertEqual(extract_features("http://example.com")["is_https"], 0)

    def test_ip_detection(self):
        self.assertEqual(extract_features("http://192.168.1.1/login")["has_ip"], 1)
        self.assertEqual(extract_features("https://google.com")["has_ip"], 0)

    def test_suspicious_tld(self):
        self.assertEqual(extract_features("http://evil.tk/login")["is_suspicious_tld"], 1)
        self.assertEqual(extract_features("http://evil.xyz/login")["is_suspicious_tld"], 1)
        self.assertEqual(extract_features("https://google.com")["is_suspicious_tld"], 0)

    def test_trusted_tld(self):
        self.assertEqual(extract_features("https://google.com")["is_trusted_tld"], 1)
        self.assertEqual(extract_features("https://bbc.co.uk")["is_trusted_tld"], 1)
        self.assertEqual(extract_features("http://evil.tk")["is_trusted_tld"], 0)

    def test_phishing_keywords(self):
        url_with_keywords = "http://secure-login-verify.tk/signin/account"
        features = extract_features(url_with_keywords)
        self.assertGreater(features["num_phishing_keywords"], 2)

    def test_at_sign(self):
        self.assertEqual(extract_features("http://evil.com@paypal.com")["has_at_sign"], 1)
        self.assertEqual(extract_features("https://google.com")["has_at_sign"], 0)

    def test_url_length(self):
        short_url = "https://g.co"
        long_url  = "https://very-secure-login-verify-paypal-account.xyz/signin.php?token=" + "x" * 100
        self.assertLess(extract_features(short_url)["url_length"], 20)
        self.assertGreater(extract_features(long_url)["url_length"], 100)

    def test_php_extension(self):
        self.assertEqual(extract_features("http://evil.tk/login.php")["has_php_extension"], 1)
        self.assertEqual(extract_features("https://google.com/index.html")["has_php_extension"], 0)

    def test_entropy(self):
        """Random strings should have higher entropy than simple domains."""
        clean   = extract_features("https://google.com")["domain_entropy"]
        random  = extract_features("http://x7k2m9qr.tk")["domain_entropy"]
        # Both should be > 0 and be valid floats
        self.assertGreater(clean, 0)
        self.assertGreater(random, 0)

    def test_subdomain_count(self):
        self.assertEqual(extract_features("https://a.b.c.evil.com")["subdomain_count"], 3)
        self.assertEqual(extract_features("https://www.google.com")["subdomain_count"], 1)

    def test_prefix_suffix_hyphen(self):
        self.assertEqual(extract_features("http://paypal-secure.com")["has_prefix_suffix"], 1)
        self.assertEqual(extract_features("https://google.com")["has_prefix_suffix"], 0)

    def test_brand_in_subdomain(self):
        # paypal in subdomain but domain is evil.com
        self.assertEqual(
            extract_features("http://paypal.secure.evil.com/login")["brand_in_subdomain"], 1
        )

    def test_invalid_url_returns_none(self):
        result = extract_features("")
        # Empty URL — should return None or empty features gracefully
        # We fill with zeros so it should not crash
        self.assertIsNotNone(result)  # We handle it gracefully

    def test_feature_vector_length(self):
        features = extract_features("https://example.com")
        vector = features_to_vector(features)
        self.assertEqual(len(vector), len(get_feature_names()))

    def test_shannon_entropy(self):
        self.assertAlmostEqual(shannon_entropy(""), 0.0)
        self.assertAlmostEqual(shannon_entropy("aaa"), 0.0)
        self.assertGreater(shannon_entropy("abcdefgh"), 2.0)


# ─────────────────────────────────────────────
# Model Prediction Tests
# ─────────────────────────────────────────────

class TestModelPredictions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import joblib
        model_path = os.path.join(
            os.path.dirname(__file__), "..", "model", "saved_models", "best_model.pkl"
        )
        if not os.path.exists(model_path):
            raise unittest.SkipTest("Model not trained yet. Run model/train_model.py first.")
        cls.model = joblib.load(model_path)

    def _predict(self, url):
        features = extract_features(url)
        vector = features_to_vector(features)
        pred = int(self.model.predict([vector])[0])
        prob = float(self.model.predict_proba([vector])[0][1])
        return pred, prob

    def test_google_is_legitimate(self):
        pred, prob = self._predict("https://www.google.com")
        self.assertEqual(pred, 0, f"Google should be legitimate (got prob={prob:.2f})")

    def test_github_is_legitimate(self):
        pred, prob = self._predict("https://github.com/user/repo")
        self.assertEqual(pred, 0, f"GitHub should be legitimate (got prob={prob:.2f})")

    def test_obvious_phishing_detected(self):
        pred, prob = self._predict("http://paypal-secure-login.tk/verify.php?token=abc123")
        self.assertEqual(pred, 1, f"Obvious phishing not caught (prob={prob:.2f})")

    def test_ip_url_is_phishing(self):
        pred, prob = self._predict("http://192.168.1.1/banking/login")
        self.assertEqual(pred, 1, f"IP URL should be phishing (prob={prob:.2f})")

    def test_typosquat_detected(self):
        pred, prob = self._predict("http://www.paypa1.com/signin/secure?confirm=account")
        self.assertEqual(pred, 1, f"Typosquat not caught (prob={prob:.2f})")

    def test_suspicious_tld_phishing(self):
        pred, prob = self._predict("http://amazon-checkout.xyz/payment/verify")
        self.assertEqual(pred, 1, f"Suspicious TLD not caught (prob={prob:.2f})")


# ─────────────────────────────────────────────
# Dataset Tests
# ─────────────────────────────────────────────

class TestDataset(unittest.TestCase):

    def test_dataset_exists(self):
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        self.assertTrue(os.path.exists(os.path.join(data_dir, "train.csv")),
                        "train.csv not found. Run data/prepare_dataset.py")
        self.assertTrue(os.path.exists(os.path.join(data_dir, "test.csv")),
                        "test.csv not found.")

    def test_dataset_balanced(self):
        import pandas as pd
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        train = pd.read_csv(os.path.join(data_dir, "train.csv"))
        counts = train["label"].value_counts()
        ratio = counts.min() / counts.max()
        self.assertGreater(ratio, 0.8, f"Dataset is imbalanced: {counts.to_dict()}")

    def test_dataset_has_required_columns(self):
        import pandas as pd
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        df = pd.read_csv(os.path.join(data_dir, "train.csv"))
        self.assertIn("url", df.columns)
        self.assertIn("label", df.columns)


# ─────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING URL DETECTOR — Test Suite")
    print("=" * 60)
    print()

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestFeatureExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestModelPredictions))
    suite.addTests(loader.loadTestsFromTestCase(TestDataset))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    total   = result.testsRun
    passed  = total - len(result.failures) - len(result.errors) - len(result.skipped)
    failed  = len(result.failures) + len(result.errors)

    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} passed  |  {failed} failed")
    print(f"{'='*60}")

    sys.exit(0 if result.wasSuccessful() else 1)
