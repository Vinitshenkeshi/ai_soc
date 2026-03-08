"""
CICIDS2017 ML Inference Service - Deployment Verification Script

Comprehensive deployment verification including Docker build, container health,
API functionality, and performance benchmarks.

Author: HOLLOWED_EYES
Mission: OPERATION ML-BASELINE
Date: 2025-12-01
"""

import os
import sys
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    print("[ERROR] requests library not found. Install with: pip install requests")
    sys.exit(1)


class DeploymentVerifier:
    """Comprehensive deployment verification suite"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.test_results = []

    def print_header(self, title: str):
        """Print formatted section header"""
        print("\n" + "="*80)
        print(title)
        print("="*80)

    def print_test(self, name: str, status: str, details: str = ""):
        """Print test result"""
        status_icon = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"{status_icon} {name}")
        if details:
            print(f"      {details}")

        self.test_results.append({
            "name": name,
            "status": status,
            "details": details
        })

    def verify_models_directory(self) -> bool:
        """Verify models directory and files exist"""
        self.print_header("1. MODELS DIRECTORY VERIFICATION")

        models_path = Path("../models")

        if not models_path.exists():
            self.print_test("Models directory", "FAIL", f"Not found: {models_path}")
            return False

        self.print_test("Models directory", "PASS", str(models_path.absolute()))

        required_files = [
            'random_forest_ids.pkl',
            'xgboost_ids.pkl',
            'decision_tree_ids.pkl',
            'scaler.pkl',
            'label_encoder.pkl',
            'feature_names.pkl'
        ]

        all_present = True
        for file_name in required_files:
            file_path = models_path / file_name
            if file_path.exists():
                size_mb = file_path.stat().st_size / (1024 * 1024)
                self.print_test(f"  {file_name}", "PASS", f"{size_mb:.2f} MB")
            else:
                self.print_test(f"  {file_name}", "FAIL", "Not found")
                all_present = False

        return all_present

    def verify_docker_build(self) -> bool:
        """Verify Docker image can be built"""
        self.print_header("2. DOCKER BUILD VERIFICATION")

        print("\nBuilding Docker image...")
        print("Command: docker build -t ids-inference:test .")

        try:
            result = subprocess.run(
                ["docker", "build", "-t", "ids-inference:test", "."],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )

            if result.returncode == 0:
                self.print_test("Docker build", "PASS", "Image built successfully")
                return True
            else:
                self.print_test("Docker build", "FAIL", result.stderr[:200])
                return False

        except subprocess.TimeoutExpired:
            self.print_test("Docker build", "FAIL", "Build timeout (>5 minutes)")
            return False
        except FileNotFoundError:
            self.print_test("Docker build", "FAIL", "Docker not found in PATH")
            return False
        except Exception as e:
            self.print_test("Docker build", "FAIL", str(e))
            return False

    def verify_service_health(self) -> bool:
        """Verify service is running and healthy"""
        self.print_header("3. SERVICE HEALTH VERIFICATION")

        max_retries = 10
        retry_delay = 2

        print(f"\nWaiting for service to be ready (max {max_retries * retry_delay}s)...")

        for attempt in range(max_retries):
            try:
                response = requests.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    self.print_test(
                        "Health endpoint",
                        "PASS",
                        f"Status: {data.get('status')}, Models: {data.get('models_loaded')}"
                    )
                    return True
            except requests.exceptions.ConnectionError:
                print(f"  Attempt {attempt + 1}/{max_retries}: Service not ready, retrying...")
                time.sleep(retry_delay)
            except Exception as e:
                self.print_test("Health endpoint", "FAIL", str(e))
                return False

        self.print_test("Health endpoint", "FAIL", "Service did not become ready")
        return False

    def verify_api_endpoints(self) -> bool:
        """Verify all API endpoints are functional"""
        self.print_header("4. API ENDPOINTS VERIFICATION")

        all_passed = True

        # Test 1: Root endpoint
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.print_test(
                    "GET /",
                    "PASS",
                    f"Service: {data.get('service')}, Version: {data.get('version')}"
                )
            else:
                self.print_test("GET /", "FAIL", f"Status code: {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("GET /", "FAIL", str(e))
            all_passed = False

        # Test 2: Models endpoint
        try:
            response = requests.get(f"{self.base_url}/models", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.print_test(
                    "GET /models",
                    "PASS",
                    f"Total models: {data.get('total_models')}"
                )
            else:
                self.print_test("GET /models", "FAIL", f"Status code: {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("GET /models", "FAIL", str(e))
            all_passed = False

        # Test 3: Prediction endpoint
        try:
            payload = {
                "features": [0.0] * 78,
                "model_name": "random_forest"
            }
            response = requests.post(
                f"{self.base_url}/predict",
                json=payload,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                self.print_test(
                    "POST /predict",
                    "PASS",
                    f"Prediction: {data.get('prediction')}, Confidence: {data.get('confidence'):.4f}"
                )
            else:
                self.print_test("POST /predict", "FAIL", f"Status code: {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("POST /predict", "FAIL", str(e))
            all_passed = False

        # Test 4: Batch prediction endpoint
        try:
            payload = [
                {"features": [0.0] * 78, "model_name": "random_forest"},
                {"features": [1.0] * 78, "model_name": "xgboost"}
            ]
            response = requests.post(
                f"{self.base_url}/predict/batch",
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self.print_test(
                    "POST /predict/batch",
                    "PASS",
                    f"Predictions: {data.get('total_predictions')}, Avg time: {data.get('avg_time_per_prediction_ms'):.2f}ms"
                )
            else:
                self.print_test("POST /predict/batch", "FAIL", f"Status code: {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("POST /predict/batch", "FAIL", str(e))
            all_passed = False

        return all_passed

    def verify_error_handling(self) -> bool:
        """Verify error handling works correctly"""
        self.print_header("5. ERROR HANDLING VERIFICATION")

        all_passed = True

        # Test 1: Invalid model name
        try:
            payload = {
                "features": [0.0] * 78,
                "model_name": "invalid_model"
            }
            response = requests.post(
                f"{self.base_url}/predict",
                json=payload,
                timeout=5
            )
            if response.status_code == 400:
                self.print_test("Invalid model name", "PASS", "Returns 400 Bad Request")
            else:
                self.print_test("Invalid model name", "FAIL", f"Expected 400, got {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("Invalid model name", "FAIL", str(e))
            all_passed = False

        # Test 2: Wrong feature count
        try:
            payload = {
                "features": [0.0] * 50,  # Should be 78
                "model_name": "random_forest"
            }
            response = requests.post(
                f"{self.base_url}/predict",
                json=payload,
                timeout=5
            )
            if response.status_code in [400, 422]:
                self.print_test("Wrong feature count", "PASS", f"Returns {response.status_code}")
            else:
                self.print_test("Wrong feature count", "FAIL", f"Expected 400/422, got {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("Wrong feature count", "FAIL", str(e))
            all_passed = False

        # Test 3: Missing features field
        try:
            payload = {
                "model_name": "random_forest"
                # Missing 'features' field
            }
            response = requests.post(
                f"{self.base_url}/predict",
                json=payload,
                timeout=5
            )
            if response.status_code == 422:
                self.print_test("Missing features field", "PASS", "Returns 422 Validation Error")
            else:
                self.print_test("Missing features field", "FAIL", f"Expected 422, got {response.status_code}")
                all_passed = False
        except Exception as e:
            self.print_test("Missing features field", "FAIL", str(e))
            all_passed = False

        return all_passed

    def verify_performance(self) -> bool:
        """Verify performance meets requirements"""
        self.print_header("6. PERFORMANCE VERIFICATION")

        try:
            payload = {
                "features": [0.0] * 78,
                "model_name": "random_forest"
            }

            latencies = []
            num_requests = 20

            print(f"\nExecuting {num_requests} prediction requests...")

            for i in range(num_requests):
                start = time.time()
                response = requests.post(
                    f"{self.base_url}/predict",
                    json=payload,
                    timeout=5
                )
                latency_ms = (time.time() - start) * 1000
                latencies.append(latency_ms)

                if response.status_code != 200:
                    self.print_test("Performance test", "FAIL", f"Request {i} failed")
                    return False

            import statistics
            avg_latency = statistics.mean(latencies)
            median_latency = statistics.median(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
            max_latency = max(latencies)

            print(f"\nLatency Statistics:")
            print(f"  Average:  {avg_latency:.2f}ms")
            print(f"  Median:   {median_latency:.2f}ms")
            print(f"  P95:      {p95_latency:.2f}ms")
            print(f"  Max:      {max_latency:.2f}ms")

            # Verify latency requirement (<100ms)
            if avg_latency < 100:
                self.print_test(
                    "Latency requirement (<100ms)",
                    "PASS",
                    f"Average: {avg_latency:.2f}ms"
                )
                return True
            else:
                self.print_test(
                    "Latency requirement (<100ms)",
                    "FAIL",
                    f"Average: {avg_latency:.2f}ms exceeds 100ms"
                )
                return False

        except Exception as e:
            self.print_test("Performance test", "FAIL", str(e))
            return False

    def print_summary(self):
        """Print verification summary"""
        self.print_header("VERIFICATION SUMMARY")

        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["status"] == "PASS")
        failed_tests = total_tests - passed_tests

        print(f"\nTotal Tests:  {total_tests}")
        print(f"Passed:       {passed_tests}")
        print(f"Failed:       {failed_tests}")
        print(f"Success Rate: {(passed_tests / total_tests * 100):.1f}%")

        if failed_tests > 0:
            print("\n[FAILED] Deployment verification failed")
            print("\nFailed tests:")
            for result in self.test_results:
                if result["status"] == "FAIL":
                    print(f"  - {result['name']}: {result['details']}")
            return False
        else:
            print("\n[SUCCESS] All deployment verification tests passed")
            return True


def main():
    """Main verification workflow"""
    print("\n" + "="*80)
    print("ML INFERENCE SERVICE - DEPLOYMENT VERIFICATION")
    print("="*80)
    print("\nMission: OPERATION ML-BASELINE")
    print("Agent: HOLLOWED_EYES")
    print("Date: 2025-12-01")

    verifier = DeploymentVerifier()

    # Run verification steps
    steps = [
        ("Models Directory", verifier.verify_models_directory),
        ("Service Health", verifier.verify_service_health),
        ("API Endpoints", verifier.verify_api_endpoints),
        ("Error Handling", verifier.verify_error_handling),
        ("Performance", verifier.verify_performance),
    ]

    for step_name, step_func in steps:
        success = step_func()
        if not success:
            print(f"\n[CRITICAL] {step_name} verification failed")
            print("Aborting remaining tests")
            break

    # Print summary
    success = verifier.print_summary()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
