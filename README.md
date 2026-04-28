# Hệ thống phát hiện tấn công Kerberos sử dụng Machine Learning

## 📌 Tổng quan dự án

Hệ thống phát hiện tấn công Kerberos được xây dựng dựa trên việc kết hợp **SIEM (Wazuh)** và **mô hình học máy (XGBoost)** để phân loại các sự kiện Kerberos thành ba lớp:
- **Normal**: Hành vi bình thường
- **Kerberoasting**: Tấn công kerberoasting
- **AS-REP Roasting**: Tấn công AS-REP roasting

**Đặc điểm chính**:
- Phát hiện **gần thời gian thực** (real-time detection)
- Kết hợp **phân loại từng log** (mô hình ML) + **phát hiện hành vi theo chuỗi sự kiện** (behavioral detection)
- Hoạt động **độc lập với rule-based detection** của Wazuh
- Độ chính xác cao (confidence ≈ 0.999) trong thử nghiệm lab

---

## 🏗️ Quy trình tổng thể

```
Log Wazuh (archives.json)
        ↓
   Trích xuất dữ liệu
        ↓
   Feature Engineering
        ↓
   Encoding dữ liệu
        ↓
   Model Prediction (XGBoost)
        ↓
   Phát hiện hành vi theo chuỗi sự kiện
        ↓
   Cảnh báo (Alert)
```

---

## 📊 Tiền xử lý dữ liệu

### Đầu vào
Dữ liệu được đọc từ `kerberos_dataset.csv`, được xây dựng bằng cách gộp ba nhóm log:

1. **Log bình thường (Normal)**
   - Các hoạt động đăng nhập hợp lệ
   - Event ID: 4624, 4625, 4768, 4769, 4770, 4771 (không có dấu hiệu tấn công)

2. **Log Kerberoasting**
   - Event ID 4769 (yêu cầu service ticket)
   - Mã hóa RC4 (0x17)
   - Các tài khoản dịch vụ (svc_*)

3. **Log AS-REP Roasting**
   - Event ID 4768 (cấp phát TGT)
   - preAuthType = 0 (không yêu cầu pre-authentication)

### Bước xử lý

```python
# 1. Thay thế giá trị thiếu
df = df.fillna("unknown")

# 2. Chuẩn hóa kiểu dữ liệu
df["eventID"] = df["eventID"].astype(str)

# 3. Các feature được sử dụng đã được chuẩn hóa
```

---

## 🔧 Feature Engineering

### Đặc trưng gốc (Raw Features)
Được lấy trực tiếp từ log:
- `eventID` - ID sự kiện Windows
- `targetUserName` - Tên tài khoản đích
- `serviceName` - Tên service
- `ticketEncryptionType` - Loại mã hóa ticket
- `ticketOptions` - Tùy chọn ticket
- `preAuthType` - Loại pre-authentication
- `status` - Trạng thái sự kiện
- `ipAddress` - Địa chỉ IP nguồn
- `agent.name` - Tên agent Wazuh

### Đặc trưng xây dựng thêm (Engineered Features)
Ba đặc trưng nhị phân được tạo dựa trên kiến thức về tấn công:

```python
# Phát hiện RC4 encryption (đặc trưng của Kerberoasting)
is_rc4 = 1 if ticketEncryptionType == "0x17" else 0

# Phát hiện tài khoản không yêu cầu pre-auth (đặc trưng của AS-REP)
is_no_preauth = 1 if preAuthType == "0" else 0

# Phát hiện service account (mục tiêu của Kerberoasting)
is_service_account = 1 if "svc_" in serviceName.lower() else 0
```

### Encoding
Tất cả dữ liệu categorical được chuyển đổi sang dạng số bằng **Label Encoding**:

```python
from sklearn.preprocessing import LabelEncoder

encoders = {}
for col in X.columns:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    encoders[col] = le  # Lưu để sử dụng lại khi predict

# Lưu encoders để predict trên dữ liệu mới
joblib.dump(encoders, "label_encoders.pkl")
```

---

## 🤖 Mô hình Machine Learning

### Lựa chọn XGBoost

**Lý do**:
- ✅ Hiệu quả cao với dữ liệu dạng bảng (tabular data)
- ✅ Xử lý tốt các feature categorical
- ✅ Tốc độ huấn luyện nhanh
- ✅ Cung cấp feature importance analysis
- ✅ Hỗ trợ multi-class classification

### Cấu hình mô hình

```python
model = XGBClassifier(
    n_estimators=150,        # 150 cây quyết định
    max_depth=4,             # Độ sâu tối đa
    learning_rate=0.1,       # Tốc độ học
    objective="multi:softprob",  # Multi-class classification
    num_class=3,             # 3 lớp: normal, kerberoasting, asrep
    eval_metric="mlogloss",  # Metric đánh giá
    random_state=42
)
```

### Quy trình huấn luyện

1. **Train/Test Split**: 80/20 với stratified sampling
   ```python
   X_train, X_test, y_train, y_test = train_test_split(
       X, y,
       test_size=0.2,
       random_state=42,
       stratify=y  # Giữ nguyên tỷ lệ các lớp
   )
   ```

2. **Huấn luyện mô hình**
   ```python
   model.fit(X_train, y_train)
   ```

3. **Đánh giá**
   ```python
   from sklearn.metrics import classification_report, confusion_matrix
   
   y_pred = model.predict(X_test)
   print(classification_report(y_test, y_pred))
   print(confusion_matrix(y_test, y_pred))
   ```

---

## 📦 Các tệp đầu ra

Sau khi huấn luyện, ba file được lưu để sử dụng trong giai đoạn phát hiện:

### 1. `xgboost_kerberos_model.pkl`
- **Nội dung**: Mô hình XGBoost đã huấn luyện
- **Kích thước**: ~1-2 MB
- **Sử dụng**: Dự đoán lớp của log mới
```python
model = joblib.load("xgboost_kerberos_model.pkl")
prediction = model.predict(X_new)  # Trả về 0, 1, hoặc 2
confidence = model.predict_proba(X_new)  # Trả về độ tin cậy
```

### 2. `label_encoders.pkl`
- **Nội dung**: Dictionary chứa LabelEncoder cho từng feature
- **Kích thước**: ~100 KB
- **Sử dụng**: Encode dữ liệu categorical thành số khi predict
```python
encoders = joblib.load("label_encoders.pkl")
# Dùng để encode các giá trị mới
X_encoded[col] = encoders[col].transform(X[col])
```

### 3. `features.pkl`
- **Nội dung**: Danh sách các feature được sử dụng
- **Kích thước**: < 1 KB
- **Sử dụng**: Đảm bảo dữ liệu predict có đúng thứ tự feature
```python
features = joblib.load("features.pkl")
# features = ['eventID', 'targetUserName', 'serviceName', ...]
X_new = df[features].copy()
```

---

## 🚀 Triển khai trên Ubuntu (Wazuh Manager)

### Yêu cầu hệ thống
- Ubuntu Server (20.04 LTS trở lên)
- Wazuh Manager đã được cài đặt
- Python 3.8+
- Các thư viện: pandas, scikit-learn, xgboost, joblib

### Cài đặt dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt**:
```
pandas==3.0.0
scikit-learn==1.3.0
xgboost==2.0.0
joblib==1.5.3
```

### Cấu trúc thư mục trên Ubuntu

```
/opt/wazuh/scripts/
├── realtime_detect.py
├── xgboost_kerberos_model.pkl
├── label_encoders.pkl
└── features.pkl
```

### Chạy script phát hiện

#### 1. Chạy thủ công

```bash
cd /opt/wazuh/scripts/
sudo python3 -E realtime_detect.py
```

Flag `-E` giữ nguyên các environment variables của user hiện tại khi chạy với sudo.

#### 2. Chạy dưới dạng systemd service (tự động khởi động)

Tạo file `/etc/systemd/system/wazuh-ml-detect.service`:

```ini
[Unit]
Description=Wazuh ML Kerberos Attack Detection
After=wazuh-manager.service
Requires=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wazuh/scripts/
ExecStart=/usr/bin/sudo /usr/bin/python3 -E /opt/wazuh/scripts/realtime_detect.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Kích hoạt service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-ml-detect
sudo systemctl start wazuh-ml-detect
sudo systemctl status wazuh-ml-detect
```

#### 3. Chạy dưới dạng background process

```bash
sudo python3 -E realtime_detect.py > detection.log 2>&1 &
```

---

## 🔍 Chi tiết script realtime_detect.py

### Chức năng chính

Script này thực hiện hai loại phát hiện:

#### 1. **Phát hiện từng sự kiện** (Per-Event Detection)
- Đọc từng log từ `/var/ossec/logs/archives/archives.json`
- Trích xuất dữ liệu theo cấu trúc của Wazuh
- Encode features sử dụng label encoders
- Dự đoán lớp (normal, kerberoasting, asrep)
- Hiển thị kết quả nếu phát hiện tấn công

```python
def extract_row(log):
    """Trích xuất dữ liệu từ log Wazuh"""
    win = log.get("data", {}).get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})
    agent = log.get("agent", {})
    
    return {
        "eventID": str(system.get("eventID", "unknown")),
        "targetUserName": eventdata.get("targetUserName", "unknown"),
        # ... các field khác
    }

def predict(row):
    """Dự đoán lớp của log"""
    # 1. Tạo DataFrame từ row
    df = pd.DataFrame([row]).fillna("unknown")
    
    # 2. Feature engineering
    df["is_rc4"] = ...
    df["is_no_preauth"] = ...
    df["is_service_account"] = ...
    
    # 3. Encoding
    X = df[features].copy()
    for col in X.columns:
        if col in encoders:
            X[col] = encoders[col].transform(X[col])
    
    # 4. Predict
    pred = model.predict(X)[0]
    conf = model.predict_proba(X)[0]
    
    return label_map[pred], conf[pred]
```

#### 2. **Phát hiện hành vi theo chuỗi sự kiện** (Behavioral Detection)
- Theo dõi các sự kiện 4769 (request service ticket) theo IP và user
- Đếm số service account khác nhau được request trong 60 giây
- Nếu số service ≥ 3 → Cảnh báo Kerberoasting burst

```python
def check_kerberoast_burst(row):
    """Phát hiện burst Kerberoasting"""
    if row["eventID"] != "4769":
        return False, 0
    
    now = time.time()
    key = (row["ipAddress"], row["targetUserName"])
    
    # Lưu thời gian và service vào window
    kerberoast_window[key].append((now, row["serviceName"]))
    
    # Xóa log cũ ngoài 60 giây
    while kerberoast_window[key] and now - kerberoast_window[key][0][0] > 60:
        kerberoast_window[key].popleft()
    
    # Đếm số service khác nhau
    unique_services = set(service for _, service in kerberoast_window[key])
    
    # Nếu ≥ 3 service trong 60 giây → Alert
    if len(unique_services) >= 3:
        return True, len(unique_services)
    
    return False, len(unique_services)
```

### Luồng xử lý log

```
Đọc log từ archives.json
        ↓
extract_row() → Trích xuất dữ liệu
        ↓
check_kerberoast_burst() → Phát hiện burst (nếu là event 4769)
        ↓
predict() → Phân loại bằng model
        ↓
Nếu attack → In cảnh báo
        ↓
Tiếp tục đọc log tiếp theo
```

### Output khi phát hiện tấn công

```
[ALERT] AS-REP Roasting Detection
Event ID: 4768
User: user1@LAB.LOCAL
Service: krbtgt
IP: 192.168.1.100
Prediction: asrep | Confidence: 0.9996

[ALERT] Kerberoasting Burst Detection
IP/User: 192.168.1.100 / user1@LAB.LOCAL
Services requested: 3 (svc_web, svc_sql, svc_file)
Time window: 60 seconds
Severity: HIGH
```

---

## 📈 Kết quả thử nghiệm

### Phát hiện AS-REP Roasting
- **Event ID**: 4768
- **Độ tin cậy**: ≈ 0.9996
- **Thời gian phát hiện**: Gần thời gian thực (< 1 giây)

### Phát hiện Kerberoasting
- **Event ID**: 4769
- **Độ tin cậy**: ≈ 0.9991
- **Phát hiện hành vi Kerberoasting burst**:
  - Nếu cùng 1 user/IP request > 3 service trong 60 giây
  - Severity: HIGH
  - Đầy đủ thông tin user, service, IP, thời gian

---

## ⚠️ Hạn chế và ghi chú

### Hạn chế của dataset lab

1. **Ít nhiễu hơn thực tế**
   - Dataset được xây dựng từ môi trường lab
   - Dữ liệu đã được pre-filter bởi Wazuh
   - Các edge case hiếm gặp có thể không được cover

2. **Feature leakage**
   - Một số features (eventID, ticketEncryptionType, preAuthType) có khả năng phân tách lớp rất mạnh
   - Mô hình có thể học theo pattern cụ thể thay vì hành vi phức tạp
   - Có thể cần điều chỉnh khi triển khai trên môi trường thực

3. **Phụ thuộc vào cấu trúc log**
   - Một số field có thể không tồn tại trong tất cả event
   - Script xử lý bằng cách thay thế `unknown`
   - Có thể cần điều chỉnh nếu cấu trúc log thay đổi

### Khuyến nghị

- **Tái huấn luyện định kỳ**: Khi thu thập dữ liệu thực từ sản xuất
- **Điều chỉnh threshold**: Thay đổi SERVICE_THRESHOLD từ 3 tùy theo chiến lược
- **Giám sát**: Theo dõi false positive/negative để cải thiện mô hình
- **Cập nhật**: Xem xét các tấn công Kerberos mới có thể xảy ra
