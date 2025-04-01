import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# Load network profile dataset (Assumes previously captured traffic is stored here)
df = pd.read_csv("network_profile.csv")

# Select relevant numerical features for training (Remove IPs and categorical fields)
features = ['packet_count', 'byte_count', 'sbytes', 'dbytes', 'spkts', 'dpkts',
            'sload', 'dload', 'source_ttl', 'dest_ttl', 'source_tcp_win', 'dest_tcp_win',
            'tcprtt', 'http_methods', 'ftp_cmds']

# Fill missing values with median values
df = df[features].fillna(df.median())

# Train Isolation Forest model (1% of data assumed to be anomalous)
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(df)

# Save the trained model
joblib.dump(model, "anomaly_detector.pkl")
print("✅ Anomaly detection model trained and saved as anomaly_detector.pkl")
