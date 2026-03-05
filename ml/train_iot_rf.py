import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from joblib import dump

print("Loading generated IoT dataset...")

df = pd.read_csv("data/features.csv")

features = [
    "avg_net_in",
    "avg_net_out",
    "max_cpu",
    "avg_cpu",
    "avg_conn_count",
    "avg_pkt_rate",
    "avg_unique_ports"
]

X = df[features]
y = df["label"]

print("Dataset shape:", df.shape)
print("\nLabel distribution:")
print(y.value_counts())

# ------------------------
# Train / Test split
# ------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining RandomForest...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ------------------------
# Evaluate model
# ------------------------

pred = model.predict(X_test)

print("\nClassification Report:\n")
print(classification_report(y_test, pred))

# ------------------------
# Save model
# ------------------------

dump(model, "ml/iot_random_forest.joblib")

print("\nModel saved to backend/ml/iot_random_forest.joblib")