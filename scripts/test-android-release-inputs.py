#!/usr/bin/env python3
"""Exercise resource and signing boundaries without starting any build tool."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "android_inputs", Path(__file__).with_name("build-android-release-inputs.py"))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class AndroidInputBoundary(unittest.TestCase):
    def test_growth_is_additional_to_physical_reserve(self):
        capacity = {"physicalFloorBytes": 20 * 1024**3,
                    "maximumOwnGrowthBudgetBytes": 16 * 1024**3,
                    "concurrentGrowthBudgetBytes": 2 * 1024**3}
        self.assertEqual(producer.required_free_bytes(capacity), 38 * 1024**3)

    def test_lower_floor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "20 GiB"):
            producer.required_free_bytes({"physicalFloorBytes": 8 * 1024**3,
                                          "maximumOwnGrowthBudgetBytes": 16 * 1024**3,
                                          "concurrentGrowthBudgetBytes": 0})

    def test_each_signing_input_is_rejected_individually(self):
        for name in producer.SIGNING_VARIABLES:
            with self.subTest(variable=name), self.assertRaisesRegex(ValueError, "signing credentials"):
                producer.unsigned_environment({name: "fixture-not-a-key"})
        producer.unsigned_environment({})


if __name__ == "__main__":
    unittest.main()
