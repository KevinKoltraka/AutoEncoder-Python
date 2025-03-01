"""
Enterprise-Grade Malicious Login Detection System
Author: Kevin Koltraka
Version: 2.1
"""

import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from tensorflow.keras.regularizers import l1_l2
from tensorflow.keras.mixed_precision import set_global_policy
import shap
import logging
from datetime import datetime
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from imblearn.over_sampling import SMOTE
from joblib import dump, load

# Configure global settings
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
set_global_policy('mixed_float16')
np.random.seed(42)
tf.random.set_seed(42)

# ----------------------------
# 1. Enhanced Data Generation
# ----------------------------

class LoginDataGenerator:
    def __init__(self, base_ip_ranges=None):
        self.base_ip_ranges = base_ip_ranges or [
            '192.168.1.{}', 
            '10.0.{}.{}',
            '172.16.0.{}'
        ]
        self.device_weights = [0.35, 0.35, 0.2, 0.1]
        
    def generate_dataset(self, num_samples=5000, malicious_ratio=0.15):
        data = pd.DataFrame({
            'user_id': np.random.randint(1000, 9999, num_samples),
            'login_time': self._generate_login_times(num_samples),
            'login_success': np.random.binomial(1, 0.85, num_samples),
            'device_type': np.random.choice(
                ['mobile', 'desktop', 'tablet', 'unknown'],
                num_samples, p=self.device_weights
            ),
            'ip_address': self._generate_ips(num_samples),
            'geo_location': np.random.choice(
                ['US', 'EU', 'ASIA', 'OTHER'], 
                num_samples, p=[0.5, 0.3, 0.15, 0.05]
            ),
            'is_malicious': np.zeros(num_samples)
        })

        mal_idx = self._inject_malicious_patterns(data, malicious_ratio)
        return data.sample(frac=1).reset_index(drop=True), mal_idx

    def _generate_login_times(self, n):
        base = np.abs(np.random.normal(1.2, 0.6, n))
        return base * np.random.uniform(0.9, 1.1, n)

    def _generate_ips(self, n):
        ips = []
        for _ in range(n):
            template = np.random.choice(self.base_ip_ranges)
            if '{}' in template:
                ips.append(template.format(
                    np.random.randint(1, 255),
                    np.random.randint(1, 255)
                ))
            else:
                ips.append(template)
        return ips

    def _inject_malicious_patterns(self, data, ratio):
        mal_idx = np.random.choice(
            data.index, 
            int(len(data)*ratio), 
            replace=False
        )
        
        # Malicious features
        data.loc[mal_idx, 'login_time'] = np.abs(
            np.random.normal(0.4, 0.3, len(mal_idx)))
        data.loc[mal_idx, 'login_success'] = np.random.binomial(
            1, 0.2, len(mal_idx))
        data.loc[mal_idx, 'device_type'] = np.random.choice(
            ['mobile', 'unknown', 'desktop'], 
            len(mal_idx), 
            p=[0.4, 0.4, 0.2]
        )
        data.loc[mal_idx, 'ip_address'] = [
            f"10.0.{np.random.randint(1,50)}.{x}" 
            for x in np.random.randint(1, 255, len(mal_idx))
        ]
        data.loc[mal_idx, 'geo_location'] = np.random.choice(
            ['ASIA', 'OTHER', 'EU'], 
            len(mal_idx), 
            p=[0.5, 0.3, 0.2]
        )
        data.loc[mal_idx, 'is_malicious'] = 1
        
        return mal_idx


# ----------------------------
# 2. Advanced Preprocessing
# ----------------------------

class LoginPreprocessor:
    """End-to-end feature engineering pipeline"""
    
    def __init__(self):
        self.ct = ColumnTransformer([
            ('num', StandardScaler(), ['user_id', 'login_time', 'login_success']),
            ('geo', OneHotEncoder(handle_unknown='ignore'), ['geo_location']),
            ('dev', OneHotEncoder(handle_unknown='infrequent_if_exist'), ['device_type']),
            ('ip', OneHotEncoder(min_frequency=50, handle_unknown='infrequent_if_exist'), ['ip_address'])
        ])
        self.smote = SMOTE(sampling_strategy='minority', random_state=42)
        
    def fit_transform(self, data):
        processed = self.ct.fit_transform(data)
        return processed
    
    def handle_imbalance(self, X, y):
        return self.smote.fit_resample(X, y)
    
    def save_pipeline(self, path='preprocessor.joblib'):
        dump(self.ct, path)
        
    @classmethod
    def load_pipeline(cls, path='preprocessor.joblib'):
        processor = cls()
        processor.ct = load(path)
        return processor

# ----------------------------
# 3. Neural Architecture
# ----------------------------

class ThreatDetectionModel:
    """Production-grade detection model with explainability"""
    
    def __init__(self, input_dim):
        self.model = self._build_model(input_dim)
        self.explainer = None
        
    def _build_model(self, input_dim):
        model = Sequential([
            Dense(128, activation='swish', 
                 kernel_regularizer=l1_l2(0.01, 0.05),
                 input_shape=(input_dim,)),
            BatchNormalization(),
            Dropout(0.4),
            
            Dense(64, activation='swish',
                 kernel_regularizer=l1_l2(0.005, 0.02)),
            Dropout(0.3),
            
            Dense(32, activation='swish'),
            Dropout(0.2),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Nadam(learning_rate=0.0005),
            loss='binary_crossentropy',
            metrics=[
                tf.keras.metrics.AUC(name='prc', curve='PR'),
                tf.keras.metrics.PrecisionAtRecall(0.9, name='patr'),
                'accuracy'
            ]
        )
        return model
    
    def train(self, X_train, y_train, X_val, y_val):
        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ModelCheckpoint('best_model.keras', save_best_only=True),
            ReduceLROnPlateau(factor=0.5, patience=3)
        ]
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=100,
            batch_size=512,
            class_weight={0: 1, 1: 3},
            callbacks=callbacks,
            verbose=1
        )
        return history
    
    def explain(self, X_sample, feature_names):
        """Generate SHAP explanations for predictions"""
        if not self.explainer:
            self.explainer = shap.DeepExplainer(self.model, X_sample[:100])
        shap_values = self.explainer.shap_values(X_sample)
        return shap.force_plot(
            self.explainer.expected_value[0].numpy(),
            shap_values[0][0], 
            feature_names=feature_names
        )
    
    def save_model(self, path='threat_model.keras'):
        self.model.save(path)
        
    @classmethod
    def load_model(cls, path='threat_model.keras'):
        model = cls(1)  # Dummy input_dim
        model.model = load_model(path)
        return model

# ----------------------------
# 4. Production Monitoring
# ----------------------------

class ThreatMonitor:
    """Real-time threat monitoring system"""
    
    def __init__(self, model_path, preprocessor_path):
        self.model = ThreatDetectionModel.load_model(model_path)
        self.preprocessor = LoginPreprocessor.load_pipeline(preprocessor_path)
        self.threshold = self._load_threshold()
        
    def _load_threshold(self, path='threshold.npy'):
        try:
            return np.load(path)
        except FileNotFoundError:
            return 0.85  # Default threshold
            
    def analyze_login(self, login_data):
        """Process and evaluate login attempt"""
        try:
            processed = self.preprocessor.ct.transform(
                pd.DataFrame([login_data]))
            proba = self.model.model.predict(processed, verbose=0)[0][0]
            
            return {
                'timestamp': datetime.now().isoformat(),
                'risk_score': float(proba),
                'verdict': 'MALICIOUS' if proba > self.threshold else 'SAFE',
                'features': login_data
            }
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {'error': 'Invalid input format'}

# ----------------------------
# 5. Evaluation Framework
# ----------------------------

def full_evaluation(model, X_test, y_test):
    """Comprehensive model evaluation"""
    y_pred = model.model.predict(X_test)
    y_class = (y_pred > 0.5).astype(int)
    
    print("Classification Report:")
    print(classification_report(y_test, y_class))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_class))
    
    precision, recall, thresholds = precision_recall_curve(y_test, y_pred)
    optimal_idx = np.argmax(precision * recall)
    optimal_threshold = thresholds[optimal_idx]
    
    print(f"\nOptimal Decision Threshold: {optimal_threshold:.4f}")
    return optimal_threshold

# ----------------------------
# Main Workflow
# ----------------------------

if __name__ == "__main__":
    # Generate data
    logger.info("Generating dataset...")
    generator = LoginDataGenerator()
    data, _ = generator.generate_dataset(5000)
    data.to_csv('logins.csv', index=False)
    
    # Preprocess
    preprocessor = LoginPreprocessor()
    X = preprocessor.fit_transform(data)
    y = data['is_malicious'].values
    
    # Handle imbalance
    X_bal, y_bal = preprocessor.handle_imbalance(X, y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_bal, y_bal, test_size=0.2, stratify=y_bal)
    
    # Initialize model
    model = ThreatDetectionModel(X_train.shape[1])
    
    # Train
    logger.info("Training model...")
    history = model.train(X_train, y_train, X_test, y_test)
    
    # Evaluate
    logger.info("Evaluating model...")
    threshold = full_evaluation(model, X_test, y_test)
    np.save('threshold.npy', threshold)
    
    # Save artifacts
    model.save_model()
    preprocessor.save_pipeline()
    
    # Example monitoring
    monitor = ThreatMonitor('threat_model.keras', 'preprocessor.joblib')
    sample_login = {
        'user_id': 6241,
        'login_time': 0.31,
        'login_success': 0,
        'device_type': 'unknown',
        'ip_address': '10.0.42.187',
        'geo_location': 'ASIA'
    }
    result = monitor.analyze_login(sample_login)
    print("\nReal-time Analysis:")
    print(result)