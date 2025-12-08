# backend/app/config.py
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"

FEATURE_CSV_PATH = DATA_DIR / "features.csv"
ISOFOREST_MODEL_PATH = MODELS_DIR / "isoforest.joblib"

SIM_TICK_SECONDS = 1.0          # each device state update period
FEATURE_WINDOW_SEC = 30         # sliding window duration
FEATURE_STEP_SEC = 5            # feature extraction & scoring step

# simple rule thresholds
RULE_PKT_RATE_TH = 800.0
RULE_CONN_COUNT_TH = 200
RULE_UNIQUE_PORTS_TH = 40
