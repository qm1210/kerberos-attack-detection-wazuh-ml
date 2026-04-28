import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from xgboost import XGBClassifier
import joblib

# 1. Load dataset
df = pd.read_csv("kerberos_dataset.csv")

print("Dataset shape:", df.shape)
print(df["label"].value_counts())

# 2. Fill missing values
df = df.fillna("unknown")

# 3. Feature engineering
df["eventID"] = df["eventID"].astype(str)

df["is_rc4"] = df["ticketEncryptionType"].apply(
    lambda x: 1 if str(x).lower() == "0x17" else 0
)

df["is_no_preauth"] = df["preAuthType"].apply(
    lambda x: 1 if str(x) == "0" else 0
)

df["is_service_account"] = df["serviceName"].apply(
    lambda x: 1 if "svc_" in str(x).lower() else 0
)

# 4. Chọn feature
features = [
    "eventID",
    "targetUserName",
    "serviceName",
    "ticketEncryptionType",
    "ticketOptions",
    "preAuthType",
    "status",
    "ipAddress",
    "agent.name",
    "is_rc4",
    "is_no_preauth",
    "is_service_account"
]

X = df[features].copy()
y = df["label"].astype(int)

# 5. Encode categorical columns
encoders = {}

for col in X.columns:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    encoders[col] = le

# Ép chắc chắn về int
X = X.astype(int)

print("\nData types after encoding:")
print(X.dtypes)

# 6. Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# 7. Train XGBoost
model = XGBClassifier(
    n_estimators=150,
    max_depth=4,
    learning_rate=0.1,
    objective="multi:softprob",
    num_class=3,
    eval_metric="mlogloss",
    random_state=42
)

model.fit(X_train, y_train)

# 8. Evaluate
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["normal", "kerberoasting", "asrep"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# 9. Feature importance
importance = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
}).sort_values(by="importance", ascending=False)

print("\nFeature Importance:")
print(importance)

# 10. Save model
joblib.dump(model, "xgboost_kerberos_model.pkl")
joblib.dump(encoders, "label_encoders.pkl")
joblib.dump(features, "features.pkl")

print("\nSaved model: xgboost_kerberos_model.pkl")
print("Saved encoders: label_encoders.pkl")
print("Saved features: features.pkl")