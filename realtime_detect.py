import json
import time
from collections import defaultdict, deque

import pandas as pd
import joblib

LOG_FILE = "/var/ossec/logs/archives/archives.json"

model = joblib.load("xgboost_kerberos_model.pkl")
encoders = joblib.load("label_encoders.pkl")
features = joblib.load("features.pkl")

label_map = {
    0: "normal",
    1: "kerberoasting",
    2: "asrep"
}

# Phát hiện nhiều service account bị request trong thời gian ngắn
WINDOW_SECONDS = 60
SERVICE_THRESHOLD = 3
kerberoast_window = defaultdict(deque)


def extract_row(log):
    win = log.get("data", {}).get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})
    agent = log.get("agent", {})

    return {
        "eventID": str(system.get("eventID", "unknown")),
        "targetUserName": eventdata.get("targetUserName", "unknown"),
        "serviceName": eventdata.get("serviceName", "unknown"),
        "ticketEncryptionType": eventdata.get("ticketEncryptionType", "unknown"),
        "ticketOptions": eventdata.get("ticketOptions", "unknown"),
        "preAuthType": str(eventdata.get("preAuthType", "unknown")),
        "status": eventdata.get("status", "unknown"),
        "ipAddress": eventdata.get("ipAddress", "unknown"),
        "agent.name": agent.get("name", "unknown"),
    }


def check_kerberoast_burst(row):
    if row["eventID"] != "4769":
        return False, 0

    now = time.time()
    key = (row["ipAddress"], row["targetUserName"])

    kerberoast_window[key].append((now, row["serviceName"]))

    # Xóa log cũ ngoài cửa sổ thời gian
    while kerberoast_window[key] and now - kerberoast_window[key][0][0] > WINDOW_SECONDS:
        kerberoast_window[key].popleft()

    unique_services = set(service for _, service in kerberoast_window[key])

    if len(unique_services) >= SERVICE_THRESHOLD:
        return True, len(unique_services)

    return False, len(unique_services)


def predict(row):
    df = pd.DataFrame([row]).fillna("unknown")

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

    for col in features:
        if col not in df.columns:
            df[col] = "unknown"

    X = df[features].copy()

    for col in X.columns:
        if col in encoders:
            le = encoders[col]
            mapping = {label: idx for idx, label in enumerate(le.classes_)}

            X[col] = X[col].astype(str).apply(
                lambda v: mapping[v] if v in mapping else -1
            )

    X = X.astype(int)

    pred = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0]

    return pred, max(proba)


def follow_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # Chỉ đọc log mới sinh ra sau khi chạy script
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:
                log = json.loads(line)
            except Exception:
                continue

            row = extract_row(log)

            # Lọc sơ bộ giống dataset train
            if row["eventID"] not in ["4624", "4625", "4768", "4769", "4770"]:
                continue

            pred, confidence = predict(row)
            label = label_map[pred]

            is_burst, service_count = check_kerberoast_burst(row)

            if label != "normal":
                print("=" * 60)
                print(f"[ALERT] {label.upper()} | confidence={confidence:.4f}")

                if label == "kerberoasting" and is_burst:
                    print(
                        f"[HIGH] Kerberoasting burst detected: "
                        f"{service_count} different services requested within {WINDOW_SECONDS}s"
                    )

                print("eventID:", row["eventID"])
                print("user:", row["targetUserName"])
                print("service:", row["serviceName"])
                print("encryption:", row["ticketEncryptionType"])
                print("preAuthType:", row["preAuthType"])
                print("ip:", row["ipAddress"])
                print("agent:", row["agent.name"])


if __name__ == "__main__":
    print("[+] Realtime Kerberos ML Detector started...")
    print(f"[+] Burst rule: >= {SERVICE_THRESHOLD} services within {WINDOW_SECONDS}s")
    follow_file(LOG_FILE)