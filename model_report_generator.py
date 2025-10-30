import os
import io
import sys
import json
import shutil
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Conv1D, GlobalMaxPooling1D, Dense, Concatenate
from tensorflow.keras.utils import plot_model
from typing import Dict, List, Optional
from data_structures import ClassificationResult, StaticFeatures, LLMDescriptions, ArtemisTensor

class DualBranchCNN:
    """
    DualBranchCNN implements a Convolutional Neural Network (CNN) architecture with two distinct branches.
    One branch processes static and binary features (like permissions, API calls, URLs) after numerical conversion.
    The second branch processes semantic embeddings derived from LLM-generated descriptions.
    The outputs of these branches are concatenated and fed into a final classification layer
    to determine if an Android application is benign or malicious.
    """
    def __init__(self, static_vocab_size: int = 100000, llm_embedding_dim: int = 384):
        """
        Initializes the DualBranchCNN model.
        
        Args:
            static_vocab_size (int): The size of the vocabulary for static features (used for embedding/hashing).
            llm_embedding_dim (int): The dimensionality of the LLM-generated embeddings.
        """
        
        self.static_vocab_size = static_vocab_size
        self.llm_embedding_dim = llm_embedding_dim
        self.model = self._build_model()
    
    def _build_model(self):
        """
        Constructs the dual-branch CNN model architecture.
        
        The first branch takes static/binary features (e.g., hashed integer sequences) and processes them
        through a 1D Convolutional layer followed by GlobalMaxPooling.
        
        The second branch takes LLM embeddings (e.g., 384-dimensional vectors) and processes them
        through a dense layer.
        
        The outputs of both branches are concatenated and passed through additional dense layers
        for final binary classification using a sigmoid activation function.

        Returns:
            tensorflow.keras.models.Model: The compiled Keras model.
        """
        # Branch 1: Static and Binary Features
        static_input = Input(shape=(100,), dtype='float32', name='static_input')
        # Reshape input to add channel dimension: (batch, steps, features) -> (batch, steps, 1)
        # Using a Lambda layer to wrap tf.expand_dims for compatibility with Keras tensors
        static_reshaped = tf.keras.layers.Lambda(lambda x: tf.expand_dims(x, axis=-1))(static_input)
        static_conv1 = Conv1D(filters=64, kernel_size=5, activation='relu')(static_reshaped)
        static_conv2 = Conv1D(filters=32, kernel_size=3, activation='relu')(static_conv1)
        static_pool = GlobalMaxPooling1D()(static_conv2)
        
        # Branch 2: LLM Descriptions
        llm_input = Input(shape=(self.llm_embedding_dim,), dtype='float32', name='llm_input')
        llm_dense1 = Dense(64, activation='relu')(llm_input)
        llm_dense2 = Dense(32, activation='relu')(llm_dense1)

        # Concatenate and classify
        merged = Concatenate()([static_pool, llm_dense2])
        final_dense1 = Dense(32, activation='relu')(merged)
        final_dense2 = Dense(16, activation='relu')(final_dense1)
        output = Dense(1, activation='sigmoid')(final_dense2)
        
        model = Model(inputs=[static_input, llm_input], outputs=output)
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def load_weights(self, weights_path: str):
        """
        Loads pre-trained weights into the CNN model.

        Args:
            weights_path (str): The file path to the saved model weights (e.g., .h5 or .keras).
        """
        self.model.load_weights(weights_path)

    def predict_one(self, tensors: ArtemisTensor) -> ClassificationResult:
        """
        Performs a single prediction on a given set of input tensors.
        The input tensors are expanded to include a batch dimension (e.g., (1, 100) from (100,)).
        
        Args:
            tensors (ArtemisTensor): A dataclass containing the static and LLM tensors for prediction.
            
        Returns:
            ClassificationResult: A dataclass instance holding the prediction label, confidence,
                                  and a boolean indicating if it's malicious.
        """
        try:
            # Ensure tensors have the correct shape for the model
            # static_tensor should have shape (1, 100) and llm_tensor should have shape (1, 384)
            static_tensor = tensors.static_tensor
            llm_tensor = tensors.llm_tensor
            
            # If static_tensor has extra dimensions, squeeze them
            if len(static_tensor.shape) > 2:
                static_tensor = tf.squeeze(static_tensor, axis=0)
            
            # Add batch dimension if needed
            if len(static_tensor.shape) == 1:
                static_tensor = static_tensor[None, :]
                
            if len(llm_tensor.shape) == 1:
                llm_tensor = llm_tensor[None, :]
            
            # Make a prediction using the trained model
            prediction = self.model.predict([static_tensor, llm_tensor])[0][0]
            # Determine the label based on a threshold (e.g., 0.5).
            label = "Malicious" if prediction > 0.5 else "Benign"
            return ClassificationResult(
                label=label,
                confidence=float(prediction) if label == "Malicious" else float(1 - prediction),
                is_malicious=prediction > 0.5,
                details={}
            )
        except Exception as e:
            print(f"Model prediction failed: {e}")
            return ClassificationResult(label="Unknown", confidence=0.0, is_malicious=False, details={"error": str(e)})


def render_report_html(output_path: str, result: ClassificationResult, static: StaticFeatures, llm: LLMDescriptions) -> str:
    """
    Generates an HTML report summarizing the APK analysis results.
    This report includes the classification, confidence, LLM-based behavioral analysis,
    and detailed static features (permissions, URLs, components, APIs, intent filters).

    Args:
        output_path (str): The file path where the HTML report will be saved.
        result (ClassificationResult): The classification outcome from the CNN model.
        static (StaticFeatures): The extracted static features of the APK.
        llm (LLMDescriptions): The LLM-generated descriptions of suspicious behaviors.

    Returns:
        str: The path to the generated HTML report.
    """
    # Helper functions for generating report content
    def get_confidence_class(confidence):
        if confidence >= 0.8:
            return "confidence-high"
        elif confidence >= 0.5:
            return "confidence-medium"
        else:
            return "confidence-low"
    
    def generate_suspicious_features_list(static, result):
        suspicious_items = []
        
        # Add suspicious permissions
        high_risk_permissions = [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION"
        ]
        
        for perm in static.permissions:
            if perm in high_risk_permissions:
                suspicious_items.append(f"<li><strong>Suspicious Permission:</strong> {perm}</li>")
        
        # Add suspicious URLs
        for url in static.urls:
            if "http://" in url or "ftp://" in url:  # Insecure protocols
                suspicious_items.append(f"<li><strong>Insecure URL:</strong> {url}</li>")
        
        # Add suspicious APIs
        suspicious_apis = [
            "Ldalvik/system/DexClassLoader",
            "Ljava/lang/Runtime;->exec",
            "Landroid/telephony/SmsManager;->sendTextMessage",
            "Landroid/location/LocationManager",
            "Ljava/net/HttpURLConnection"
        ]
        
        for api in static.apis:
            for suspicious_api in suspicious_apis:
                if suspicious_api in api:
                    suspicious_items.append(f"<li><strong>Suspicious API Call:</strong> {api}</li>")
        
        if not suspicious_items:
            suspicious_items.append("<li>No highly suspicious features detected</li>")
            
        return "<ul>" + "".join(suspicious_items) + "</ul>"
    
    def generate_recommendations(static, result):
        recommendations = []
        
        if result.is_malicious:
            recommendations.append("<li><strong>Immediate Action:</strong> Do not install or run this application</li>")
            recommendations.append("<li><strong>Security Scan:</strong> Run a full system scan to ensure your device is not compromised</li>")
            recommendations.append("<li><strong>Report:</strong> Consider reporting this application to app store providers</li>")
        else:
            recommendations.append("<li><strong>General Security:</strong> Keep your device and applications updated</li>")
            recommendations.append("<li><strong>Permission Review:</strong> Regularly review app permissions in your device settings</li>")
            recommendations.append("<li><strong>Security Software:</strong> Maintain up-to-date antivirus and anti-malware software</li>")
            
        # Specific recommendations based on detected features
        dangerous_permissions = [p for p in static.permissions if "SMS" in p or "CONTACTS" in p or "LOCATION" in p]
        if dangerous_permissions:
            recommendations.append(f"<li><strong>Permission Caution:</strong> Review permissions: {', '.join(dangerous_permissions)}</li>")
            
        insecure_urls = [url for url in static.urls if "http://" in url]
        if insecure_urls:
            recommendations.append(f"<li><strong>Network Security:</strong> Application uses insecure HTTP connections</li>")
            
        return "<ul>" + "".join(recommendations) + "</ul>"
    
    template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Artemis Analysis Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
            .container {{ width: 80%; margin: auto; padding: 20px; }}
            h1, h2, h3 {{ border-bottom: 2px solid #ccc; padding-bottom: 5px; }}
            .label-malicious {{ color: #dc3545; font-weight: bold; }}
            .label-benign {{ color: #28a745; font-weight: bold; }}
            .label-unknown {{ color: #6c757d; font-weight: bold; }}
            pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            .suspicious-list {{ background: #fff3cd; padding: 15px; border-radius: 5px; border: 1px solid #ffeaa7; }}
            .recommendations {{ background: #d4edda; padding: 15px; border-radius: 5px; border: 1px solid #c3e6cb; }}
            .confidence-high {{ color: #28a745; }}
            .confidence-medium {{ color: #ffc107; }}
            .confidence-low {{ color: #dc3545; }}
        </style>
    </head>
    <body>
    <div class="container">
        <h1>Artemis Analysis Report</h1>
        
        <h2>Summary</h2>
        <p><strong>Classification:</strong> <span class="label-{result.label.lower()}">{result.label}</span></p>
        <p><strong>Confidence:</strong> <span class="{get_confidence_class(result.confidence)}">{result.confidence:.2%}</span></p>
        
        <h2>Most Suspicious Features</h2>
        <div class="suspicious-list">
            {generate_suspicious_features_list(static, result)}
        </div>
        
        <h2>LLM-based Behavioral Analysis</h2>
        <pre>{llm.by_feature.get('summary', 'No LLM summary available.')}</pre>
        
        <h2>Actionable Recommendations</h2>
        <div class="recommendations">
            {generate_recommendations(static, result)}
        </div>
        
        <h2>Static Feature Details</h2>
        <h3>Permissions</h3>
        <ul>{''.join([f'<li>{p}</li>' for p in static.permissions])}</ul>
        
        <h3>URLs Found</h3>
        <ul>{''.join([f'<li>{url}</li>' for url in static.urls])}</ul>
        
        <h3>Components</h3>
        <pre>{json.dumps(static.components, indent=2)}</pre>

        <h3>APIs Found</h3>
        <ul>{''.join([f'<li>{api}</li>' for api in static.apis])}</ul>
        
        <h3>Intent Filters</h3>
        <pre>{json.dumps(static.intent_filters, indent=2)}</pre>
        
    </div>
    </body>
    </html>
    """
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(template)
    
    return output_path