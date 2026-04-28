# Phát hiện tấn công Kerberos bằng XGBoost

Hệ thống dựa trên Machine Learning để phát hiện các tấn công Kerberos (Kerberoasting & AS-REP Roasting) từ nhật ký Event của Windows theo thời gian thực.

## 📋 Mục lục

- [Tổng quan](#-tổng-quan-phương-pháp)
- [Cài đặt](#-cài-đặt)
- [Sử dụng](#-sử-dụng)
- [Kiến trúc](#-kiến-trúc-hệ-thống)
- [Tùy chỉnh](#-tùy-chỉnh)

---

## 🎯 Tổng quan phương pháp

### Quy trình tổng thể

Hệ thống phát hiện tấn công Kerberos kết hợp Wazuh SIEM và mô hình XGBoost:

```
Thu thập log → Tiền xử lý → Trích xuất đặc trưng → Huấn luyện XGBoost
→ Phát hiện real-time → Cảnh báo
```

**Ba loại sự kiện**:
- **Normal**: Xác thực Kerberos hợp pháp
- **Kerberoasting**: Tấn công yêu cầu nhiều service ticket (Event ID 4769 + RC4)
- **AS-REP Roasting**: Tấn công khộng xác thực trước (Event ID 4768 + preAuthType=0)

### Dataset

- **Nguồn**: `kerberos_dataset.csv` (gộp 3 loại log từ Wazuh)
- **Lớp**: 3 (Normal, Kerberoasting, AS-REP)
- **Đặc trưng**: 12 feature (9 gốc + 3 engineered)
- **Train/Test**: 80/20 stratified

### Feature Engineering

```python
# Raw features (9)
eventID, targetUserName, serviceName, ticketEncryptionType, 
ticketOptions, preAuthType, status, ipAddress, agent.name

# Engineered features (3)
is_rc4 = (ticketEncryptionType == "0x17")          # RC4 detection
is_no_preauth = (preAuthType == "0")               # Pre-auth disabled
is_service_account = ("svc_" in serviceName)       # Service account
```

---

## 🚀 Cài đặt

```bash
# Yêu cầu
python >= 3.8

# Cài đặt dependencies
pip install -r requirements.txt
```

**Phụ thuộc**:
- pandas==3.0.2 - Dữ liệu
- scikit-learn==1.8.0 - LabelEncoder, metrics
- xgboost==3.2.0 - Mô hình
- joblib==1.5.3 - Tuần tự hóa

---

## 📖 Sử dụng

### 1. Huấn luyện mô hình

```bash
python train_xgboost_kerberos.py
```

**Quy trình**:
1. Đọc `kerberos_dataset.csv`
2. Xử lý: Fill NaN → chuẩn hóa kiểu dữ liệu
3. Feature engineering: Tạo 3 đặc trưng nhị phân
4. Label encoding: Mã hóa tất cả feature
5. Train/Test split: 80/20 stratified
6. Huấn luyện: XGBoost (n_estimators=150, max_depth=4)
7. Đánh giá: Accuracy, Precision, Recall, F1-score
8. Lưu: 3 file `.pkl`

**Output**:
```
Dataset shape: (5000, 13)
label
    0    2000  (normal)
    1    1500  (kerberoasting)
    2    1500  (as-rep)

Accuracy: 0.9950

Classification Report:
           precision  recall  f1-score  support
normal        0.99     0.99     0.99      400
kerberoasting 1.00     0.99     0.99      300
as-rep        0.99     1.00     0.99      300

Feature Importance:
ticketEncryptionType   0.45
preAuthType            0.30
is_rc4                 0.12
serviceName            0.08
```

**File được tạo**:
- `xgboost_kerberos_model.pkl` ⭐
- `label_encoders.pkl` ⭐
- `features.pkl` ⭐

### 2. Phát hiện real-time

```bash
python realtime_detect.py
```

**Yêu cầu**: 
- Wazuh/OSSEC chạy trên Linux
- File logs: `/var/ossec/logs/archives/archives.json`
- Cả 3 file `.pkl` từ training

**Quy trình**:
1. Đọc live logs từ archives.json
2. Trích xuất feature (extract_row)
3. Encode bằng `label_encoders.pkl`
4. Predict bằng `xgboost_kerberos_model.pkl`
5. Nếu score > 0.5 → Sinh cảnh báo

**Output (tấn công Kerberoasting)**:
```
[+] Realtime Kerberos ML Detector started...
[+] Burst rule: >= 3 services within 60s

============================================================
[ALERT] KERBEROASTING | confidence=0.9991
eventID: 4769
user: user1@LAB.LOCAL
service: svc_web
encryption: 0x17
preAuthType: 0
ip: 192.168.1.100
agent: win-domain-01

[ALERT] KERBEROASTING | confidence=0.9989
service: svc_sql

[ALERT] KERBEROASTING | confidence=0.9988
service: svc_file

[HIGH] Kerberoasting burst detected: 3 different services requested within 60s
```

---

## 📁 Cấu trúc dự án

```
Machine Learning/
├── train_xgboost_kerberos.py      # Huấn luyện mô hình
├── realtime_detect.py             # Phát hiện real-time
├── kerberos_dataset.csv           # Dữ liệu huấn luyện
├── xgboost_kerberos_model.pkl     # Mô hình ⭐
├── label_encoders.pkl             # LabelEncoders ⭐
├── features.pkl                   # Feature list ⭐
├── requirements.txt               # Dependencies
├── .gitignore                     # Git rules
└── README.md                      # File này
```

**⭐ Ghi chú**: File `.pkl` được tạo từ `train_xgboost_kerberos.py`

---

## 🚨 Tính năng phát hiện

### 1. Phát hiện từng log riêng lẻ

Mô hình dự đoán **class** cho từng log:
- **0 = Normal** (xác thực hợp pháp)
- **1 = Kerberoasting** (request nhiều service tickets)
- **2 = AS-REP Roasting** (pre-auth disabled)

Output: Class + Confidence score

### 2. Burst Detection (Phát hiện đột phát)

Phát hiện Kerberoasting dựa trên **chuỗi sự kiện**:

**Logic**:
```
Theo dõi (IP, User) → Event ID 4769
Trong 60 giây: 
  Nếu yêu cầu ≥ 3 service account khác nhau
  → Cảnh báo HIGH (Kerberoasting burst)
```

**Ưu điểm**: Giảm false positive, phát hiện hành vi đặc trưng

---

## 🔧 Tùy chỉnh

### Điều chỉnh Burst Detection

Trong `realtime_detect.py`:

```python
WINDOW_SECONDS = 60      # Cửa sổ thời gian (giây)
SERVICE_THRESHOLD = 3    # Ngưỡng service khác nhau
```

**Ví dụ**:
```python
WINDOW_SECONDS = 30      # Nhạy hơn (30s)
SERVICE_THRESHOLD = 2    # Cảnh báo sớm hơn (2 service)
```

### Chỉnh siêu tham số mô hình

Trong `train_xgboost_kerberos.py`:

```python
model = XGBClassifier(
    n_estimators=150,       # Tăng = phức tạp hơn
    max_depth=4,            # Tăng = nguy hiểm overfitting
    learning_rate=0.1,      # Giảm = huấn luyện lâu hơn
    objective="multi:softprob",
    num_class=3,
    eval_metric="mlogloss",
    random_state=42
)
```

⚠️ **Sau khi chỉnh**, cần re-train mô hình

---

## 📊 Đánh giá

### Chỉ số

Mô hình được đánh giá trên test set (20%):

- **Accuracy**: Tỷ lệ dự đoán đúng
- **Precision**: Cảnh báo đúng / Tất cả cảnh báo
- **Recall**: Phát hiện được / Tất cả tấn công thực tế
- **F1-score**: Cân bằng Precision-Recall
- **Confusion Matrix**: TP, FP, TN, FN

### Feature Importance

Mô hình cung cấp xếp hạng feature:

```
ticketEncryptionType       0.45  (Loại mã hóa - quan trọng nhất)
preAuthType                0.30  (Xác thực trước)
is_rc4                     0.12  (Phát hiện RC4)
serviceName                0.08  (Tên dịch vụ)
targetUserName             0.03
eventID                    0.02
```

---

## 📝 Ghi chú quan trọng

### Thiết kế

- **Loại trừ `is_attacker_ip`**: Tránh học cứng vào IP attacker
- **LabelEncoder**: Lưu để phải dùng trong prediction
- **Fill NaN**: Giá trị thiếu → `"unknown"`
- **Stratified Split**: Giữ tỷ lệ lớp trong train/test

### Tại sao archives.json?

- **archives.json**: Raw logs (không lọc bởi rule)
- **alerts.json**: Chỉ log thỏa rule (có thể bỏ sót)

**Lợi ích**:
✅ Mô hình độc lập với Wazuh rules
✅ Phát hiện hành vi mới
✅ Phát hiện tất cả tấn công

### Hạn chế

1. Dataset từ lab (ít nhiễu hơn thực tế)
2. Một số feature quá rõ ràng (feature leakage)
3. Dữ liệu đã lọc bởi Wazuh trước

**Tuy nhiên** ✓ Dễ triển khai, độ chính xác cao (99%+)

---

## 📄 Giấy phép

Dự án riêng tư

## 👤 Tác giả

Nghiên cứu phát hiện tấn công Kerberos trên Active Directory

---

## 🎯 Tổng quan phương pháp

### Quy trình tổng thể

Hệ thống phát hiện tấn công Kerberos được xây dựng dựa trên kết hợp giữa hệ thống SIEM (Wazuh) và mô hình học máy:

```
Thu thập log → Lọc log Kerberos → Tiền xử lý → Trích xuất đặc trưng 
→ Huấn luyện mô hình → Phân loại → Cảnh báo
```

Dự án phát hiện ba loại sự kiện xác thực Kerberos:
- **Normal**: Xác thực Kerberos hợp pháp
- **Kerberoasting**: Tấn công nhắm vào các tài khoản dịch vụ
- **AS-REP Roasting**: Tấn công vào người dùng vô hiệu hóa xác thực trước

---

## 📊 Bộ dữ liệu

### Nguồn dữ liệu

- **Nền tảng**: Wazuh SIEM
- **Loại log**: Windows Event logs
- **Event IDs**: 4624, 4625, 4768, 4769, 4770, 4771

### Cấu trúc dữ liệu

Dataset được xây dựng bằng cách **gộp ba nhóm log riêng biệt**:

| Loại | Nguồn | Điều kiện lọc | Số sự kiện |
|------|-------|--------------|-----------|
| **Normal** | Hoạt động đăng nhập hợp pháp | Event ID: 4624, 4625, 4768, 4769, 4770, 4771 (không có dấu hiệu tấn công) | normal_log.csv |
| **Kerberoasting** | Yêu cầu service ticket | Event ID 4769 + ticketEncryptionType = 0x17 (RC4) + tài khoản dịch vụ (svc_*) | kerberoasting_log.csv |
| **AS-REP Roasting** | Cấp phát TGT | Event ID 4768 + preAuthType = 0 (pre-auth disabled) | asrep_log.csv |

**File dữ liệu chính**: `kerberos_dataset.csv` (gộp từ 3 nguồn trên)

### Xử lý dữ liệu

**Bước tiền xử lý**:

1. **Xử lý giá trị thiếu**: Thay thế bằng `"unknown"`
   - Không phải tất cả Event ID chứa đầy đủ các trường
   - Ví dụ: Log Kerberoasting không có `preAuthType`, AS-REP không có `ticketOptions`

2. **Chuẩn hóa kiểu dữ liệu**: 
   - Chuyển `eventID` thành string
   - Đảm bảo tất cả feature có định dạng phù hợp

3. **Đảm bảo tính nhất quán**: Các giá trị rỗng/null đều được xử lý trước encoding

---

## 📈 Trích xuất và xây dựng đặc trưng

### 1. Đặc trưng gốc (Raw Features)

Trực tiếp từ log Windows:

```python
[
    "eventID",                # Loại sự kiện (4768, 4769, ...)
    "targetUserName",         # Tài khoản người dùng
    "serviceName",            # Tên dịch vụ yêu cầu
    "ticketEncryptionType",   # Loại mã hóa (0x17 = RC4)
    "ticketOptions",          # Tùy chọn ticket
    "preAuthType",            # Loại xác thực trước
    "status",                 # Trạng thái sự kiện
    "ipAddress",              # Địa chỉ IP nguồn
    "agent.name"              # Tên agent Wazuh
]
```

### 2. Đặc trưng xây dựng thêm (Feature Engineering)

Ba đặc trưng nhị phân được tạo từ logic tấn công:

```python
# Phát hiện RC4 - đặc trưng của Kerberoasting
is_rc4 = 1 if ticketEncryptionType == "0x17" else 0

# Phát hiện pre-auth disabled - đặc trưng của AS-REP Roasting
is_no_preauth = 1 if preAuthType == "0" else 0

# Phát hiện tài khoản dịch vụ - mục tiêu của Kerberoasting
is_service_account = 1 if "svc_" in serviceName.lower() else 0
```

**Lợi ích**: Giúp mô hình học được các pattern quan trọng thay vì chỉ dựa vào dữ liệu thô.

### 3. Mã hóa dữ liệu

- **Phương pháp**: Label Encoding
- **Mục đích**: Chuyển đổi các trường chuỗi sang dạng số nguyên phù hợp với XGBoost
- **Lưu trữ**: Encoders được lưu trong `label_encoders.pkl` để sử dụng trong phát hiện real-time

---

## 🔧 Lựa chọn mô hình

### XGBoost Classifier

**Lý do chọn**:

| Tiêu chí | XGBoost |
|----------|---------|
| Hiệu quả với dữ liệu bảng | ✅ Rất cao |
| Xử lý feature rời rạc | ✅ Xuất sắc |
| Tốc độ huấn luyện | ✅ Nhanh |
| Feature importance | ✅ Có |
| Phân loại đa lớp | ✅ Hỗ trợ |

### Siêu tham số

```python
model = XGBClassifier(
    n_estimators=150,           # Số vòng boosting
    max_depth=4,                # Độ sâu cây (tránh overfitting)
    learning_rate=0.1,          # Tốc độ học
    objective="multi:softprob", # Phân loại 3 lớp
    num_class=3,                # Normal, Kerberoasting, AS-REP
    eval_metric="mlogloss",     # Hàm đánh giá đa lớp
    random_state=42             # Tái tạo kết quả
)
```

---

## 🚀 Quy trình huấn luyện

### Các bước

1. **Tải dữ liệu**: Đọc từ `kerberos_dataset.csv`
2. **Tiền xử lý**: Fill NaN, chuẩn hóa kiểu dữ liệu
3. **Feature Engineering**: Tạo 3 đặc trưng nhị phân
4. **Chọn Feature**: Lọc 12 đặc trưng quan trọng nhất
5. **Mã hóa**: Label Encode tất cả cột categorical
6. **Chia dữ liệu**: Train 80% / Test 20% (với stratification)
7. **Huấn luyện**: Fit XGBoost trên training set
8. **Dự đoán**: Predict trên test set
9. **Đánh giá**: Tính accuracy, precision, recall, F1-score
10. **Lưu mô hình**: Pickle model + encoders + features

### Cài đặt

```bash
python >= 3.8
pip install -r requirements.txt
```

### Huấn luyện mô hình

```bash
python train_xgboost_kerberos.py
```

**Kết quả đầu ra**:
- `xgboost_kerberos_model.pkl` - Mô hình đã huấn luyện
- `label_encoders.pkl` - Bộ mã hóa đặc trưng (lưu từ LabelEncoder)
- `features.pkl` - Danh sách 12 đặc trưng

---

## 📊 Đánh giá mô hình

### Chỉ số đánh giá

Mô hình được đánh giá trên tập test 20%:

- **Accuracy**: Tỷ lệ dự đoán đúng
- **Precision**: Tỷ lệ cảnh báo đúng trong tất cả cảnh báo
- **Recall**: Tỷ lệ phát hiện được tấn công trong tất cả tấn công
- **F1-score**: Điểm cân bằng giữa precision và recall
- **Confusion Matrix**: Hiển thị TP, FP, TN, FN cho từng lớp

### Feature Importance

Mô hình cung cấp xếp hạng các đặc trưng theo mức độ quan trọng:

```bash
Feature Importance:
feature                       importance
ticketEncryptionType         0.45
preAuthType                  0.30
is_rc4                       0.12
serviceName                  0.08
...
```

---

## 🚨 Phát hiện theo thời gian thực

### 1. Kiểm tra mô hình

```bash
python test.py
```

Test trên 10 samples ngẫu nhiên từ `test_logs.csv`.

**Output**:
```
--- Log 0 ---
Dự đoán: KERBEROASTING
Confidence: 0.9991

--- Log 1 ---
Dự đoán: NORMAL
Confidence: 0.9998
```

### 2. Phát hiện live từ OSSEC/Wazuh

```bash
python realtime_detect.py
```

**Quy trình**:
1. Đọc live logs từ `/var/ossec/logs/archives/archives.json`
2. Trích xuất feature từ mỗi log mới
3. Encode và predict bằng mô hình
4. Nếu là tấn công → sinh cảnh báo

### 3. Cơ chế Burst Detection

**Mục đích**: Phát hiện Kerberoasting dựa trên chuỗi sự kiện

**Logic**:
- Theo dõi sự kiện Event ID 4769 theo (IP, User)
- Nếu trong 60 giây, **≥ 3 service account khác nhau** được yêu cầu
- → Sinh cảnh báo mức **HIGH** (Kerberoasting burst)

**Tùy chỉnh**:

```python
WINDOW_SECONDS = 60      # Cửa sổ thời gian (giây)
SERVICE_THRESHOLD = 3    # Ngưỡng số service khác nhau
```

**Ví dụ**:
```
[+] Realtime Kerberos ML Detector started...
[+] Burst rule: >= 3 services within 60s

[ALERT] KERBEROASTING | confidence=0.9991
eventID: 4769
user: user1@LAB.LOCAL
service: svc_web
...

[HIGH] Kerberoasting burst detected: 3 different services requested within 60s
service: [svc_web, svc_sql, svc_file]
```

---

## 📁 Cấu trúc dự án

```
├── train_xgboost_kerberos.py    # Script huấn luyện mô hình
├── test.py                       # Kiểm tra mô hình
├── realtime_detect.py            # Giám sát nhật ký theo thời gian thực
├── kerberos_dataset.csv          # Dữ liệu huấn luyện (gộp từ 3 nguồn)
├── normal_log.csv                # Nhật ký bình thường
├── kerberoasting_log.csv         # Nhật ký Kerberoasting
├── asrep_log.csv                 # Nhật ký AS-REP Roasting
├── test_logs.csv                 # Dữ liệu kiểm tra
├── requirements.txt              # Python dependencies
├── .gitignore                    # Quy tắc bỏ qua Git
└── README.md                     # File này
```

**Ghi chú**: 
- Tất cả file CSV được lưu trữ trong repository
- Chỉ file mô hình `.pkl` được bỏ qua bởi `.gitignore`

---

## 🛠️ Tùy chỉnh

### Điều chỉnh ngưỡng phát hiện đột phát

Trong `realtime_detect.py`:

```python
WINDOW_SECONDS = 60      # Cửa sổ thời gian (giây)
SERVICE_THRESHOLD = 3    # Số dịch vụ để kích hoạt cảnh báo
```

### Chỉnh sửa siêu tham số mô hình

Trong `train_xgboost_kerberos.py`:

```python
model = XGBClassifier(
    n_estimators=150,       # Số vòng boosting (tăng = mô hình phức tạp hơn)
    max_depth=4,            # Độ sâu cây (tăng = có thể overfitting)
    learning_rate=0.1,      # Tốc độ học (giảm = huấn luyện lâu hơn nhưng chính xác hơn)
)
```

---

## 📝 Ghi chú quan trọng

### Thiết kế mô hình

- **Loại trừ `is_attacker_ip`**: Tránh mô hình học cứng vào một số IP attacker cụ thể
- **LabelEncoder**: Tất cả feature categorical được mã hóa, lưu để dùng lại
- **Xử lý NaN**: Giá trị thiếu được điền `"unknown"` để tránh lỗi encoding
- **Stratified Split**: Train/Test 80/20 với phân tầng để đảm bảo tỷ lệ lớp

### Sử dụng archives.json (không alerts.json)

**Tại sao**?

- **archives.json**: Chứa tất cả raw logs, không bị lọc bởi rule-based detection
- **alerts.json**: Chỉ chứa log đã thỏa mãn rule (có thể bỏ sót hành vi mới)

Sử dụng archives.json giúp:
- Mô hình độc lập với Wazuh rules
- Phát hiện cả hành vi bình thường và tấn công
- Phát hiện các tấn công chưa định nghĩa trong rule

---

## ⚠️ Thảo luận và hạn chế

### Hạn chế hiện tại

1. **Dữ liệu lab**: Dataset được xây dựng trong môi trường lab, ít nhiễu hơn thực tế
2. **Feature rõ ràng**: Một số feature như `eventID`, `ticketEncryptionType` có khả năng phân tách lớp rất mạnh
3. **Feature leakage**: Mô hình có thể học theo rule thay vì hành vi phức tạp
4. **Dữ liệu lọc trước**: Dataset đã được lọc bởi Wazuh trước tiền xử lý

### Lý do vẫn hợp lý

✅ Dễ triển khai và kiểm soát
✅ Minh họa rõ ràng cơ chế phát hiện
✅ Phù hợp với mục tiêu nghiên cứu
✅ Kết quả phát hiện đạt độ chính xác cao trên test set

---

## 📊 Demo kết quả

### AS-REP Roasting Detection

Khi thực hiện tấn công AS-REP Roasting:

```
[ALERT] AS-REP ROASTING | confidence=0.9996
eventID: 4768
user: victim_user@LAB.LOCAL
encryption: 0x17
preAuthType: 0
ip: 192.168.1.100
agent: win-server-01
```

### Kerberoasting Burst Detection

Khi thực hiện tấn công Kerberoasting:

```
[ALERT] KERBEROASTING | confidence=0.9991
eventID: 4769
user: user1@LAB.LOCAL
service: svc_web

[ALERT] KERBEROASTING | confidence=0.9989
service: svc_sql

[ALERT] KERBEROASTING | confidence=0.9988
service: svc_file

[HIGH] Kerberoasting burst detected: 3 different services within 60s
```

---

## 🔗 Các phụ thuộc

| Package | Phiên bản | Mục đích |
|---------|-----------|---------|
| pandas | 3.0.2 | Thao tác và phân tích dữ liệu |
| scikit-learn | 1.8.0 | LabelEncoder, metrics, preprocessing |
| xgboost | 3.2.0 | Mô hình Gradient Boosting Classifier |
| joblib | 1.5.3 | Tuần tự hóa model, encoders, features |

---

## 📄 Giấy phép

Dự án riêng tư

## 👤 Tác giả

Được tạo cho nghiên cứu phát hiện tấn công Kerberos trong Active Directory
