# CICIDS2017 ML Training Pipeline

**Maintainer:** Vinit Shenkeshi
**Original Author:** Abdul Bari
**Status:** Operational

## Overview

Production-grade machine learning pipeline for training intrusion detection models on the CICIDS2017 dataset. Implements binary classification (BENIGN vs ATTACK) with three baseline models optimized for real-time detection.

## Features

- **Multi-Model Training**: Random Forest, XGBoost, Decision Tree
- **Automated Preprocessing**: Handles missing values, infinite values, scaling, encoding
- **Class Imbalance Handling**: Balanced class weights for optimal detection
- **Comprehensive Evaluation**: Accuracy, precision, recall, F1, FPR, inference latency
- **Real-Time Inference API**: FastAPI endpoint for production deployment
- **Model Persistence**: Save/load trained models and preprocessing objects

## Architecture

```
ml_training/
|-- train_ids_model.py      # Complete training pipeline
|-- inference_api.py         # FastAPI inference endpoint
|-- requirements.txt         # Python dependencies
|__ README.md               # This file

models/                     # Trained models (generated)
|-- random_forest_ids.pkl
|-- xgboost_ids.pkl
|-- decision_tree_ids.pkl
|-- scaler.pkl
|-- label_encoder.pkl
|__ feature_names.pkl

evaluation/                 # Evaluation reports (generated)
|__ baseline_models_report.md
```

## Installation

### 