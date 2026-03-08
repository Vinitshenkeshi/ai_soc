"""
Continuous Retraining Pipeline - AI-Augmented SOC
Phase 5: Self-improving ML models from analyst feedback.

Reads analyst-labeled feedback from PostgreSQL, combines with original
CICIDS2017 training data, retrains models, evaluates champion/challenger,
and promotes better models.

Usage:
    python retrain.py                    # Check if retraining needed and run
    python retrain.py --force            # Force retrain regardless of threshold
    python retrain.py --evaluate-only    # Evaluate current models without retraining
"""

import argparse
import json
import logging
import os
import pickle
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("retraining")

# Paths
MODEL_DIR = Path(os.getenv("MODEL_DIR", "/app/models"))
CURRENT_DIR = MODEL_DIR / "current"
CANDIDATE_DIR = MODEL_DIR / "candidate"
HISTORY_DIR = MODEL_DIR / "history"

# Retraining config
RETRAIN_THRESHOLD = int(os.getenv("RETRAIN_THRESHOLD", "100"))
MIN_IMPROVEMENT = float(os.getenv("MIN_IMPROVEMENT", "0.005"))  # 0.5% accuracy improvement
DATABASE_URL = os.getenv(
    "FEEDBACK_DATABASE_URL",
    "postgresql://ai_soc:ai_soc_password@postgres:5432/ai_soc",
)
ML_INFERENCE_URL = os.getenv("ML_INFERENCE_URL", "http://ml-inference:8000")


def load_feedback_data() -> Optional[pd.DataFrame]:
    """
    Load analyst-labeled feedback from PostgreSQL.
    Returns DataFrame with features and true labels.
    """
    try:
        import psycopg2
    except ImportError:
        logger.error("psycopg2 not installed. Run: pip install psycopg2-binary")
        return None

    sync_url = DATABASE_URL.replace("+asyncpg", "").replace("postgresql+asyncpg", "postgresql")

    try:
        conn = psycopg2.connect(sync_url)
        query = """
            SELECT
                a.alert_id,
                a.raw_alert_json,
                a.triage_result_json,
                a.ml_prediction,
                a.ml_confidence,
                f.true_label,
                f.is_false_positive,
                f.true_severity,
                f.true_category,
                f.created_at as feedback_time
            FROM alerts a
            JOIN feedback f ON a.alert_id = f.alert_id
            WHERE f.true_label IS NOT NULL
            ORDER BY f.created_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        logger.info(f"Loaded {len(df)} labeled feedback entries from database")
        return df
    except Exception as e:
        logger.error(f"Failed to load feedback data: {e}")
        return None


def extract_features_from_feedback(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract ML features from stored alert data.
    Returns (X, y) arrays for training.
    """
    features_list = []
    labels = []

    for _, row in df.iterrows():
        raw_alert = row.get("raw_alert_json") or {}
        full_log = raw_alert.get("full_log") or {}

        # Try to extract network flow features
        network_flow = None
        if isinstance(full_log, dict):
            network_flow = full_log.get("network_flow")
            if not network_flow and full_log.get("Flow Duration") is not None:
                network_flow = full_log

        if network_flow and len(network_flow) >= 10:
            # Real network flow data available
            feature_names = load_feature_names()
            features = []
            for name in feature_names:
                val = network_flow.get(name, 0.0)
                try:
                    features.append(float(val))
                except (ValueError, TypeError):
                    features.append(0.0)
            features_list.append(features)
        else:
            # Use alert metadata as approximate features
            features = [0.0] * 77
            features[0] = 6.0  # Protocol (TCP default)
            features[1] = 1000000.0  # Flow duration (1s)
            if raw_alert.get("dest_port"):
                features[35] = float(raw_alert["dest_port"])
            if raw_alert.get("rule_level"):
                level = float(raw_alert["rule_level"])
                features[44] = 1.0 if level >= 8 else 0.0
            features_list.append(features)

        labels.append(row["true_label"])

    X = np.array(features_list)
    y = np.array(labels)
    logger.info(f"Extracted features: X shape={X.shape}, labels={np.unique(y, return_counts=True)}")
    return X, y


def load_feature_names() -> List[str]:
    """Load CICIDS2017 feature names."""
    path = MODEL_DIR / "feature_names.pkl"
    if path.exists():
        with open(path, "rb") as f:
            return pickle.load(f)
    # Fallback: return generic names
    return [f"feature_{i}" for i in range(77)]


def load_current_models() -> Dict:
    """Load currently deployed models for comparison."""
    models = {}
    for name in ["random_forest_ids.pkl", "xgboost_ids.pkl", "decision_tree_ids.pkl"]:
        path = MODEL_DIR / name
        if path.exists():
            with open(path, "rb") as f:
                models[name.replace("_ids.pkl", "")] = pickle.load(f)
    return models


def train_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    scaler: StandardScaler,
    label_encoder: LabelEncoder,
) -> Dict:
    """Train new candidate models."""
    logger.info("Training candidate models...")

    X_scaled = scaler.transform(X_train)
    y_encoded = label_encoder.transform(y_train)

    models = {}

    # Random Forest
    logger.info("Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_scaled, y_encoded)
    models["random_forest"] = rf

    # Decision Tree
    logger.info("Training Decision Tree...")
    dt = DecisionTreeClassifier(
        max_depth=20,
        class_weight="balanced",
        random_state=42,
    )
    dt.fit(X_scaled, y_encoded)
    models["decision_tree"] = dt

    # XGBoost (optional, may not be installed)
    try:
        from xgboost import XGBClassifier

        logger.info("Training XGBoost...")
        unique, counts = np.unique(y_encoded, return_counts=True)
        if len(unique) > 1:
            scale_pos = counts[0] / counts[1] if counts[1] > 0 else 1.0
        else:
            scale_pos = 1.0

        xgb = XGBClassifier(
            max_depth=10,
            scale_pos_weight=scale_pos,
            objective="binary:logistic",
            eval_metric="logloss",
            use_label_encoder=False,
            random_state=42,
        )
        xgb.fit(X_scaled, y_encoded)
        models["xgboost"] = xgb
    except ImportError:
        logger.warning("XGBoost not available, skipping")

    return models


def evaluate_models(
    models: Dict,
    X_test: np.ndarray,
    y_test: np.ndarray,
    scaler: StandardScaler,
    label_encoder: LabelEncoder,
) -> Dict[str, Dict]:
    """Evaluate models on test set."""
    X_scaled = scaler.transform(X_test)
    y_encoded = label_encoder.transform(y_test)

    results = {}
    for name, model in models.items():
        y_pred = model.predict(X_scaled)
        results[name] = {
            "accuracy": accuracy_score(y_encoded, y_pred),
            "precision": precision_score(y_encoded, y_pred, average="weighted", zero_division=0),
            "recall": recall_score(y_encoded, y_pred, average="weighted", zero_division=0),
            "f1": f1_score(y_encoded, y_pred, average="weighted", zero_division=0),
        }
        logger.info(
            f"  {name}: accuracy={results[name]['accuracy']:.4f}, "
            f"f1={results[name]['f1']:.4f}"
        )

    return results


def champion_challenger(
    current_results: Dict[str, Dict],
    candidate_results: Dict[str, Dict],
) -> Dict[str, str]:
    """
    Compare current (champion) vs new (challenger) models.
    Returns dict of model_name -> "promote" or "keep".
    """
    decisions = {}
    for name in candidate_results:
        if name not in current_results:
            decisions[name] = "promote"
            continue

        current_acc = current_results[name]["accuracy"]
        candidate_acc = candidate_results[name]["accuracy"]
        improvement = candidate_acc - current_acc

        if improvement >= MIN_IMPROVEMENT:
            decisions[name] = "promote"
            logger.info(
                f"  {name}: PROMOTE (improvement={improvement:+.4f}, "
                f"{current_acc:.4f} -> {candidate_acc:.4f})"
            )
        else:
            decisions[name] = "keep"
            logger.info(
                f"  {name}: KEEP (improvement={improvement:+.4f} < "
                f"threshold={MIN_IMPROVEMENT})"
            )

    return decisions


def save_models(models: Dict, scaler: StandardScaler, label_encoder: LabelEncoder):
    """Save promoted models to the models directory."""
    # Archive current models
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_dir = HISTORY_DIR / timestamp
    archive_dir.mkdir(parents=True, exist_ok=True)

    for name in ["random_forest_ids.pkl", "xgboost_ids.pkl", "decision_tree_ids.pkl"]:
        src = MODEL_DIR / name
        if src.exists():
            dest = archive_dir / name
            with open(src, "rb") as f:
                data = f.read()
            with open(dest, "wb") as f:
                f.write(data)

    # Save new models
    for name, model in models.items():
        path = MODEL_DIR / f"{name}_ids.pkl"
        with open(path, "wb") as f:
            pickle.dump(model, f)
        logger.info(f"Saved model: {path}")

    # Save updated scaler and encoder
    with open(MODEL_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(MODEL_DIR / "label_encoder.pkl", "wb") as f:
        pickle.dump(label_encoder, f)

    # Save metadata
    metadata = {
        "retrained_at": datetime.now().isoformat(),
        "models": list(models.keys()),
        "feedback_samples": "from_database",
        "archived_to": str(archive_dir),
    }
    with open(MODEL_DIR / "retrain_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Models archived to {archive_dir}")


def trigger_reload():
    """Tell ml-inference to reload models."""
    try:
        import requests

        response = requests.post(f"{ML_INFERENCE_URL}/models/reload", timeout=10)
        if response.status_code == 200:
            logger.info("ML inference service reloaded successfully")
        else:
            logger.warning(f"ML inference reload returned {response.status_code}")
    except Exception as e:
        logger.warning(f"Failed to trigger ML reload: {e}")


def main():
    parser = argparse.ArgumentParser(description="AI-SOC Continuous Retraining Pipeline")
    parser.add_argument("--force", action="store_true", help="Force retrain")
    parser.add_argument("--evaluate-only", action="store_true", help="Evaluate only")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("AI-SOC Continuous Retraining Pipeline")
    logger.info("=" * 60)

    # Step 1: Load feedback data
    feedback_df = load_feedback_data()
    if feedback_df is None or len(feedback_df) == 0:
        logger.info("No labeled feedback data available")
        return

    logger.info(f"Found {len(feedback_df)} labeled feedback entries")

    if not args.force and len(feedback_df) < RETRAIN_THRESHOLD:
        logger.info(
            f"Below threshold ({len(feedback_df)}/{RETRAIN_THRESHOLD}). "
            f"Skipping retraining. Use --force to override."
        )
        return

    # Step 2: Extract features
    X_feedback, y_feedback = extract_features_from_feedback(feedback_df)

    if len(X_feedback) == 0:
        logger.warning("No valid features extracted")
        return

    # Step 3: Prepare data
    # Load existing scaler and encoder
    scaler_path = MODEL_DIR / "scaler.pkl"
    encoder_path = MODEL_DIR / "label_encoder.pkl"

    if scaler_path.exists() and encoder_path.exists():
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        with open(encoder_path, "rb") as f:
            label_encoder = pickle.load(f)
    else:
        scaler = StandardScaler()
        label_encoder = LabelEncoder()

    # Ensure label encoder knows all classes
    all_labels = np.unique(y_feedback)
    known_classes = set(label_encoder.classes_) if hasattr(label_encoder, 'classes_') else set()
    new_classes = set(all_labels) - known_classes
    if new_classes:
        all_classes = sorted(known_classes | set(all_labels))
        label_encoder.fit(all_classes)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_feedback, y_feedback, test_size=0.2, random_state=42, stratify=y_feedback
    )

    # Fit scaler on new data
    scaler.fit(X_train)

    # Step 4: Evaluate current models
    logger.info("\n--- Current Model Performance ---")
    current_models = load_current_models()
    current_results = evaluate_models(current_models, X_test, y_test, scaler, label_encoder)

    if args.evaluate_only:
        logger.info("Evaluate-only mode. Done.")
        return

    # Step 5: Train candidates
    logger.info("\n--- Training Candidate Models ---")
    candidate_models = train_models(X_train, y_train, scaler, label_encoder)

    # Step 6: Evaluate candidates
    logger.info("\n--- Candidate Model Performance ---")
    candidate_results = evaluate_models(candidate_models, X_test, y_test, scaler, label_encoder)

    # Step 7: Champion/Challenger
    logger.info("\n--- Champion/Challenger Comparison ---")
    decisions = champion_challenger(current_results, candidate_results)

    # Step 8: Promote winners
    promoted = {name: model for name, model in candidate_models.items() if decisions.get(name) == "promote"}

    if promoted:
        logger.info(f"\nPromoting {len(promoted)} model(s): {list(promoted.keys())}")
        save_models(promoted, scaler, label_encoder)
        trigger_reload()
    else:
        logger.info("\nNo models improved. Keeping current models.")

    logger.info("\n" + "=" * 60)
    logger.info("Retraining pipeline complete")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
