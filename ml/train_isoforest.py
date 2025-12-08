# ml/train_isoforest.py
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump

ROOT = Path(__file__).resolve().parents[1]
DATA_CSV = ROOT / "data" / "features.csv"
MODEL_PATH = ROOT / "models" / "isoforest.joblib"


def main():
    print(f"[INFO] reading data from: {DATA_CSV}")
    if not DATA_CSV.is_file():
        print("[ERROR] features.csv not found – run backend for few minutes first.")
        return

    df = pd.read_csv(DATA_CSV)
    if "label" not in df.columns:
        print("[ERROR] no 'label' column – cannot filter benign.")
        return

    benign = df[df["label"] == "benign"]
    print(f"[INFO] total rows: {len(df)}, benign rows: {len(benign)}")
    if len(benign) < 80:
        print("[ERROR] need at least 80 benign windows – run simulator longer.")
        return

    cols = [
        "avg_net_in",
        "avg_net_out",
        "max_cpu",
        "avg_cpu",
        "avg_conn_count",
        "avg_pkt_rate",
        "avg_unique_ports",
    ]
    for c in cols:
        if c not in benign.columns:
            print(f"[ERROR] missing column {c}")
            return

    X = benign[cols].values

    print("[INFO] training IsolationForest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=42,
    )
    model.fit(X)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    dump(model, MODEL_PATH)
    print(f"[OK] model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
