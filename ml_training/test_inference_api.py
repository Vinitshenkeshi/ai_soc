"""
CICIDS2017 IDS - Inference API Test Suite

Comprehensive production readiness verification for ML inference service.
Tests model loading, API endpoints, error handling, and performance.

Author: HOLLOWED_EYES
Mission: OPERATION ML-BASELINE - Production Readiness
Date: 2025-12-01
"""

import os
import sys
import json
import time
import pickle
import asyncio
from pathlib import Path
from typing import Dict, List

import pytest
import numpy as np
from fastapi.testclient import TestClient

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from inference_api import app, load_models, models, scaler, label_encoder, feature_names


class TestInferenceAPI:
    """Production readiness tests for inference API"""

    @pytest.fixture(scope="class")
    def client(self):
        """Create test client"""
        return TestClient(app)

    @pytest.fixture(scope="class", autouse=True)
    def setup_models(self):
        """Setup models before tests"""
        # Check if models exist
        model_path = Path(os.getenv("MODEL_PATH", "../models"))

        if not model_path.exists():
            pytest.skip(f"Models directory not found: {model_path}")

        required_files = [
            'random_forest_ids.pkl',
            'xgboost_ids.pkl',
            'decision_tree_ids.pkl',
            'scaler.pkl',
            'label_encoder.pkl',
            'feature_names.pkl'
        ]

        missing_files = [f for f in required_files if not (model_path / f).exists()]

        if missing_files:
            pytest.skip(f"Missing model files: {missing_files}")

        # Load models
        try:
            load_models()
        except Exception as e:
            pytest.skip(f"Failed to load models: {e}")

    def test_root_endpoint(self, client):
        """Test API root endpoint"""
        response = client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert data["service"] == "CICIDS2017 Intrusion Detection API"
        assert data["version"] == "1.0.0"
        assert data["status"] == "operational"
        assert "models_loaded" in data
        assert len(data["models_loaded"]) > 0

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert data["models_loaded"] >= 1
        assert len(data["available_models"]) >= 1

    def test_list_models(self, client):
        """Test models listing endpoint"""
        response = client.get("/models")
        assert response.status_code == 200

        data = response.json()
        assert "total_models" in data
        assert data["total_models"] >= 1
        assert "models" in data
        assert "feature_count" in data
        assert "label_classes" in data

        # Verify model structure
        for model_name, model_info in data["models"].items():
            assert "name" in model_info
            assert "type" in model_info
            assert "loaded" in model_info
            assert model_info["loaded"] is True

    def test_predict_valid_request(self, client):
        """Test prediction with valid request"""
        # Create dummy features
        features = [0.0] * 78

        request_data = {
            "features": features,
            "model_name": "random_forest"
        }

        response = client.post("/predict", json=request_data)
        assert response.status_code == 200

        data = response.json()
        assert "prediction" in data
        assert "confidence" in data
        assert "probabilities" in data
        assert "model_used" in data
        assert "inference_time_ms" in data
        assert "timestamp" in data

        # Validate prediction format
        assert data["prediction"] in ["BENIGN", "ATTACK"]
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["model_used"] == "random_forest"
        assert data["inference_time_ms"] >= 0

    def test_predict_all_models(self, client):
        """Test prediction with all available models"""
        features = [0.0] * 78

        model_names = ["random_forest", "xgboost", "decision_tree"]

        for model_name in model_names:
            if model_name not in models:
                continue

            request_data = {
                "features": features,
                "model_name": model_name
            }

            response = client.post("/predict", json=request_data)
            assert response.status_code == 200

            data = response.json()
            assert data["model_used"] == model_name

    def test_predict_invalid_model(self, client):
        """Test prediction with invalid model name"""
        features = [0.0] * 78

        request_data = {
            "features": features,
            "model_name": "invalid_model"
        }

        response = client.post("/predict", json=request_data)
        assert response.status_code == 400

        data = response.json()
        assert "detail" in data

    def test_predict_wrong_feature_count(self, client):
        """Test prediction with wrong number of features"""
        # Wrong number of features
        features = [0.0] * 50  # Should be 78

        request_data = {
            "features": features,
            "model_name": "random_forest"
        }

        response = client.post("/predict", json=request_data)
        assert response.status_code == 400

    def test_predict_missing_features(self, client):
        """Test prediction with missing features"""
        request_data = {
            "model_name": "random_forest"
            # Missing 'features' field
        }

        response = client.post("/predict", json=request_data)
        assert response.status_code == 422  # Validation error

    def test_batch_predict_valid(self, client):
        """Test batch prediction with valid data"""
        flows = [
            {
                "features": [0.0] * 78,
                "model_name": "random_forest"
            },
            {
                "features": [1.0] * 78,
                "model_name": "xgboost"
            }
        ]

        response = client.post("/predict/batch", json=flows)
        assert response.status_code == 200

        data = response.json()
        assert "total_predictions" in data
        assert "total_time_ms" in data
        assert "avg_time_per_prediction_ms" in data
        assert "results" in data

        assert data["total_predictions"] == len(flows)
        assert len(data["results"]) == len(flows)

    def test_batch_predict_too_large(self, client):
        """Test batch prediction with too many flows"""
        # Exceed batch size limit of 1000
        flows = [
            {
                "features": [0.0] * 78,
                "model_name": "random_forest"
            }
        ] * 1001

        response = client.post("/predict/batch", json=flows)
        assert response.status_code == 400

    def test_inference_latency(self, client):
        """Test inference latency meets requirements (<100ms)"""
        features = [0.0] * 78

        request_data = {
            "features": features,
            "model_name": "random_forest"
        }

        # Run multiple predictions and measure time
        latencies = []
        for _ in range(10):
            start = time.time()
            response = client.post("/predict", json=request_data)
            latency_ms = (time.time() - start) * 1000
            latencies.append(latency_ms)

            assert response.status_code == 200

        avg_latency = np.mean(latencies)
        max_latency = np.max(latencies)

        print(f"\nLatency Stats:")
        print(f"  Average: {avg_latency:.2f}ms")
        print(f"  Max: {max_latency:.2f}ms")
        print(f"  Min: {np.min(latencies):.2f}ms")

        # Verify latency requirement
        assert avg_latency < 100, f"Average latency {avg_latency:.2f}ms exceeds 100ms requirement"

    def test_prediction_consistency(self, client):
        """Test that same input produces same output"""
        features = [0.5] * 78

        request_data = {
            "features": features,
            "model_name": "random_forest"
        }

        # Make multiple predictions with same input
        predictions = []
        for _ in range(5):
            response = client.post("/predict", json=request_data)
            assert response.status_code == 200

            data = response.json()
            predictions.append(data["prediction"])

        # All predictions should be the same
        assert len(set(predictions)) == 1, "Predictions are not consistent for same input"

    def test_model_artifacts_loaded(self):
        """Test that all required model artifacts are loaded"""
        assert models is not None
        assert len(models) > 0
        assert scaler is not None
        assert label_encoder is not None
        assert feature_names is not None

        # Verify model types
        for model_name, model in models.items():
            assert model is not None
            assert hasattr(model, 'predict')
            assert hasattr(model, 'predict_proba')

    def test_label_encoder_classes(self):
        """Test label encoder has correct classes"""
        assert label_encoder is not None
        classes = label_encoder.classes_

        # Should have at least BENIGN and ATTACK for binary classification
        assert len(classes) >= 2
        print(f"\nLabel Encoder Classes: {classes}")

    def test_feature_names_count(self):
        """Test correct number of features"""
        assert feature_names is not None
        assert len(feature_names) == 78, f"Expected 78 features, got {len(feature_names)}"


class TestDockerDeployment:
    """Tests for Docker deployment readiness"""

    def test_dockerfile_exists(self):
        """Test Dockerfile exists"""
        dockerfile_path = Path(__file__).parent / "Dockerfile"
        assert dockerfile_path.exists(), "Dockerfile not found"

    def test_dockerfile_content(self):
        """Test Dockerfile has required content"""
        dockerfile_path = Path(__file__).parent / "Dockerfile"

        if not dockerfile_path.exists():
            pytest.skip("Dockerfile not found")

        content = dockerfile_path.read_text()

        # Check for essential components
        assert "FROM python:" in content, "Missing Python base image"
        assert "WORKDIR" in content, "Missing WORKDIR"
        assert "COPY requirements.txt" in content, "Missing requirements.txt copy"
        assert "pip install" in content, "Missing pip install"
        assert "EXPOSE 8000" in content, "Missing port exposure"
        assert "uvicorn" in content, "Missing uvicorn command"
        assert "HEALTHCHECK" in content, "Missing health check"

    def test_requirements_file_exists(self):
        """Test requirements.txt exists"""
        req_path = Path(__file__).parent / "requirements.txt"
        assert req_path.exists(), "requirements.txt not found"

    def test_requirements_content(self):
        """Test requirements.txt has required packages"""
        req_path = Path(__file__).parent / "requirements.txt"

        if not req_path.exists():
            pytest.skip("requirements.txt not found")

        content = req_path.read_text()

        required_packages = [
            "fastapi",
            "uvicorn",
            "pydantic",
            "numpy",
            "pandas",
            "scikit-learn",
            "xgboost"
        ]

        for package in required_packages:
            assert package in content, f"Missing required package: {package}"


def run_manual_tests():
    """Manual tests for development verification"""
    print("\n" + "="*80)
    print("MANUAL VERIFICATION TESTS")
    print("="*80)

    # Test 1: Check models directory
    print("\n[TEST 1] Checking models directory...")
    model_path = Path("../models")

    if not model_path.exists():
        print(f"  [FAIL] Models directory not found: {model_path}")
        print(f"  ACTION: Run train_ids_model.py to generate models")
        return False
    else:
        print(f"  [PASS] Models directory exists")

    # Test 2: Check model files
    print("\n[TEST 2] Checking model files...")
    required_files = [
        'random_forest_ids.pkl',
        'xgboost_ids.pkl',
        'decision_tree_ids.pkl',
        'scaler.pkl',
        'label_encoder.pkl',
        'feature_names.pkl'
    ]

    missing_files = []
    for file_name in required_files:
        file_path = model_path / file_name
        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"  [OK] {file_name}: {size_mb:.2f} MB")
        else:
            print(f"  [MISSING] {file_name}")
            missing_files.append(file_name)

    if missing_files:
        print(f"\n  [FAIL] Missing files: {missing_files}")
        print(f"  ACTION: Run train_ids_model.py to generate missing models")
        return False

    # Test 3: Verify Dockerfile
    print("\n[TEST 3] Checking Dockerfile...")
    dockerfile_path = Path("Dockerfile")

    if not dockerfile_path.exists():
        print(f"  [FAIL] Dockerfile not found")
        return False
    else:
        print(f"  [PASS] Dockerfile exists")

    # Test 4: Verify requirements.txt
    print("\n[TEST 4] Checking requirements.txt...")
    req_path = Path("requirements.txt")

    if not req_path.exists():
        print(f"  [FAIL] requirements.txt not found")
        return False
    else:
        print(f"  [PASS] requirements.txt exists")

    print("\n" + "="*80)
    print("MANUAL VERIFICATION: COMPLETE")
    print("="*80)

    return True


if __name__ == "__main__":
    # Run manual tests first
    manual_success = run_manual_tests()

    if manual_success:
        print("\n[SUCCESS] All manual tests passed")
        print("\nTo run automated tests:")
        print("  pytest test_inference_api.py -v")
        print("\nTo run with coverage:")
        print("  pytest test_inference_api.py -v --cov=inference_api")
    else:
        print("\n[FAILED] Manual tests failed")
        print("Fix the issues above before running automated tests")
        sys.exit(1)
