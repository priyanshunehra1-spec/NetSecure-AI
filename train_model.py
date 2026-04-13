#!/usr/bin/env python3

import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib
import warnings
warnings.filterwarnings('ignore')

FEATURES = [
    'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_same_src_port_rate'
]

def create_dummy_data():
    np.random.seed(42)
    n_samples = 10000

    data = {
        'service': np.random.randint(0, 70, n_samples),
        'flag': np.random.randint(0, 11, n_samples),
        'src_bytes': np.random.randint(0, 10000, n_samples),
        'dst_bytes': np.random.randint(0, 10000, n_samples),
        'count': np.random.randint(0, 100, n_samples),
        'same_srv_rate': np.random.uniform(0, 1, n_samples),
        'diff_srv_rate': np.random.uniform(0, 1, n_samples),
        'dst_host_srv_count': np.random.randint(0, 100, n_samples),
        'dst_host_same_srv_rate': np.random.uniform(0, 1, n_samples),
        'dst_host_same_src_port_rate': np.random.uniform(0, 1, n_samples),
    }

    target = np.where(
        (data['src_bytes'] > 5000) |
        (data['dst_bytes'] > 5000) |
        (data['count'] > 50) |
        (data['same_srv_rate'] < 0.3),
        0,
        1
    )

    df = pd.DataFrame(data)
    df['class'] = target
    return df

def load_real_data():
    try:
        df = pd.read_csv('dataset/train.csv')
        print("Loaded real data:", df.shape)
        return df
    except:
        print("Using dummy data")
        return create_dummy_data()

def preprocess_data(df):
    df.drop_duplicates(inplace=True)
    df.fillna(0, inplace=True)

    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}

    for col in categorical_columns:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

    if 'class' in df.columns:
        le_target = LabelEncoder()
        y = le_target.fit_transform(df['class'])
        joblib.dump(le_target, 'target_encoder.sav')
    else:
        y = np.random.randint(0, 2, len(df))

    for feature in FEATURES:
        if feature not in df.columns:
            df[feature] = 0

    X = df[FEATURES].copy()

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')

    X.fillna(0, inplace=True)

    joblib.dump(label_encoders, 'label_encoders.sav')

    return X, y

def train_model():
    print("Loading data...")
    df = load_real_data()
    X, y = preprocess_data(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    try:
        smote = SMOTE(random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        print("SMOTE applied")
    except:
        print("SMOTE skipped")

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training Logistic Regression model...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    print(confusion_matrix(y_test, y_pred))

    joblib.dump(model, 'model.sav')
    joblib.dump(scaler, 'scaler.sav')

    print("Model saved as model.sav")

    return model, scaler

def test_model():
    model = joblib.load('model.sav')
    scaler = joblib.load('scaler.sav')

    sample_data = [
    [1, 2, 100, 200, 5, 0.8, 0.1, 3, 0.9, 0.1],   # normal
    [50, 8, 9000, 8000, 80, 0.1, 0.9, 90, 0.2, 0.9]  # anomaly
]

    df = pd.DataFrame(sample_data, columns=FEATURES)
    df = scaler.transform(df)

    preds = model.predict(df)

    for i, p in enumerate(preds):
        print("Sample", i+1, ":", "normal" if p == 1 else "anomaly")

if __name__ == "__main__":
    print("Training Logistic Regression IDS...")
    train_model()
    test_model()