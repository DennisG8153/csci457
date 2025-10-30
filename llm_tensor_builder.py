import os
import hashlib
import json
import subprocess
from typing import Dict, List, Optional
from data_structures import StaticFeatures, LLMDescriptions, ArtemisTensor
from tensorflow import constant as tf_constant # For building tensors
# Handle TensorFlow imports with fallback for different versions
try:
    from tensorflow.keras.preprocessing.text import text_to_word_sequence
    from tensorflow.keras.preprocessing.sequence import pad_sequences
except ImportError:
    try:
        from keras.preprocessing.text import text_to_word_sequence
        from keras.preprocessing.sequence import pad_sequences
    except ImportError:
        # Fallback implementations if preprocessing modules are not available
        def text_to_word_sequence(text):
            return text.split()
        
        def pad_sequences(sequences, maxlen=None, padding='post'):
            # Simplified padding implementation
            if maxlen is None:
                return sequences
            padded = []
            for seq in sequences:
                if len(seq) < maxlen:
                    if padding == 'post':
                        padded_seq = seq + [0] * (maxlen - len(seq))
                    else:
                        padded_seq = [0] * (maxlen - len(seq)) + seq
                else:
                    padded_seq = seq[:maxlen]
                padded.append(padded_seq)
            return padded
# Handle optional imports with fallbacks
try:
    from sentence_transformers import SentenceTransformer
    HAS_SBERT = True
except ImportError:
    HAS_SBERT = False
    SentenceTransformer = None

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    OpenAI = None

try:
    from dotenv import load_dotenv
    # Load environment variables from .env file
    load_dotenv()
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False
    def load_dotenv():
        pass


class LLMDescriber:
    """
    The LLMDescriber class is responsible for generating semantic descriptions of extracted
    Android application features using a Large Language Model (LLM), such as OpenAI's GPT models
    or Hugging Face models. It includes caching mechanisms to store and retrieve previously 
    generated descriptions to reduce API calls and speed up processing.
    """
    def __init__(self, provider: str = "openai", model: str = "gpt-4o-mini", cache_path: str = "llm_cache.json"):
        """
        Initializes the LLMDescriber with a specified LLM provider, model, and cache path.
        Loads existing cache data if the cache file exists.

        Args:
            provider (str): The LLM provider to use (e.g., "openai").
            model (str): The specific LLM model to use (e.g., "gpt-4o-mini").
            cache_path (str): The file path for storing LLM response cache.
        """
        self.provider = provider
        self.model = model
        self.cache_path = cache_path
        self._cache = {}
        # Load cache from file if it exists
        if os.path.exists(self.cache_path):
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                self._cache = json.load(f)
        
    def _describe_openai(self, features: StaticFeatures) -> str:
        """
        Generates a description for the given static features using the OpenAI API.

        Args:
            features (StaticFeatures): An object containing the extracted static features.

        Returns:
            str: A concise summary of potential risks or a fallback message if the API call fails.
        """
        if not HAS_OPENAI:
            return "OpenAI library not found. Cannot generate description."
        
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return "OpenAI API key not found in environment variables. Cannot generate description."
        
        client = OpenAI(api_key=api_key)
        # Construct a detailed prompt for the LLM based on permissions and components
        prompt = f"Analyze the following Android application permissions and components. Identify any suspicious or potentially malicious behaviors based on them. Permissions: {features.permissions}. Components: {features.components}. Provide a concise summary of potential risks."
        
        try:
            # Make the API call to OpenAI
            response = client.chat.completions.create(
                model=self.model or "gpt-4o-mini",  # Use default model if none specified
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            # Fallback in case of API call failure
            print(f"OpenAI API call failed: {e}")
            # Continue with fallback even if API quota is exceeded
            return self._fallback_desc(features)
    
    def _describe_huggingface(self, features: StaticFeatures) -> str:
        """
        Generates a description for the given static features using a Hugging Face model.
        
        Args:
            features (StaticFeatures): An object containing the extracted static features.
            
        Returns:
            str: A concise summary of potential risks or a fallback message if the model call fails.
        """
        if not HAS_SBERT:
            return "SentenceTransformer library not found. Cannot generate description with Hugging Face model."
        
        try:
            # Load the Hugging Face model
            from transformers import pipeline
            # Use a conversational model for text generation
            generator = pipeline("text2text-generation", model=self.model)
            
            # Construct a detailed prompt for the model based on permissions and components
            prompt = f"Analyze the following Android application permissions and components. Identify any suspicious or potentially malicious behaviors based on them. Permissions: {', '.join(features.permissions)}. Components: {features.components}. Provide a concise summary of potential risks."
            
            # Generate a response using the Hugging Face model
            response = generator(prompt, max_length=200, num_return_sequences=1)
            return response[0]['generated_text']
        except Exception as e:
            # Fallback in case of model call failure
            print(f"Hugging Face model call failed: {e}")
            return self._fallback_desc(features)

    def _fallback_desc(self, features: StaticFeatures) -> str:
        """
        Provides a basic fallback description when the LLM API call fails.

        Args:
            features (StaticFeatures): An object containing the extracted static features.

        Returns:
            str: A basic description constructed from available features.
        """
        return f"Fallback analysis: Permissions include {', '.join(features.permissions)}. Suspicious URLs found: {', '.join(features.urls)}. This is a basic description due to LLM failure."

    def describe(self, features: StaticFeatures) -> LLMDescriptions:
        """
        Generates a description for a given set of static features, utilizing a cache.
        If a description for the given features exists in the cache, it's returned.
        Otherwise, a new description is generated using the configured LLM and cached.

        Args:
            features (StaticFeatures): An object containing the extracted static features.

        Returns:
            LLMDescriptions: An object containing the LLM-generated description.
        """
        # Generate a hash for the features to use as a cache key
        features_hash = hashlib.sha256(str(features).encode()).hexdigest()
        if features_hash in self._cache:
            # Return from cache if available
            return LLMDescriptions(by_feature=self._cache[features_hash])

        # Generate new description using the OpenAI method
        description = self._describe_openai(features)
        
        # Update cache with the new description
        self._cache[features_hash] = {"summary": description}
        with open(self.cache_path, 'w', encoding='utf-8') as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=2)

        return LLMDescriptions(by_feature={"summary": description})

class TensorBuilder:
    """
    The TensorBuilder class is responsible for converting extracted features (StaticFeatures)
    and LLM-generated descriptions (LLMDescriptions) into numerical tensor formats
    suitable for input into the Convolutional Neural Network (CNN) model.
    It uses SentenceTransformer for LLM description embeddings and a simplified hashing
    for static features.
    """
    def __init__(self):
        """
        Initializes the TensorBuilder. Attempts to load a pre-trained SentenceTransformer model
        for generating embeddings from LLM descriptions.
        """
        self.sbert_model = None
        if HAS_SBERT:
            try:
                # Load a pre-trained SentenceTransformer model
                self.sbert_model = SentenceTransformer("all-MiniLM-L6-v2")
            except Exception as e:
                print(f"Failed to load SentenceTransformer model: {e}")
                self.sbert_model = None

    def build(self, static: StaticFeatures, llm: LLMDescriptions) -> ArtemisTensor:
        """
        Builds two types of tensors: one for static/binary features and one for LLM descriptions.

        Args:
            static (StaticFeatures): An object containing extracted static features.
            llm (LLMDescriptions): An object containing LLM-generated descriptions.

        Returns:
            ArtemisTensor: A dataclass holding the static and LLM tensors.
        """
        
        # Simplified example for building static tensor:
        # Combines permissions and URLs, hashes each part, and pads the sequence.
        combined_features = " ".join(static.permissions + static.urls + static.apis) # Include APIs now
        feature_vector = [int(hashlib.sha256(f.encode()).hexdigest(), 16) % 1000000 for f in combined_features.split()]
        static_tensor = tf_constant(feature_vector, dtype='float32')
        # Pad sequences to a fixed length (e.g., 100) for consistent input to the CNN
        static_tensor = tf_constant(pad_sequences([static_tensor], maxlen=100, padding='post').tolist())

        # Build LLM tensor:
        # If SentenceTransformer is available and an LLM summary exists, encode the summary into an embedding.
        # Otherwise, use a fallback tensor of zeros.
        llm_tensor = None
        if self.sbert_model and "summary" in llm.by_feature:
            embedding = self.sbert_model.encode(llm.by_feature["summary"])
            llm_tensor = tf_constant(embedding, dtype='float32')
        else:
            print("Warning: SentenceTransformer not available or LLM summary missing. Using fallback for LLM tensor.")
            llm_tensor = tf_constant([0.0] * 384, dtype='float32') # 384 is the default dimension for all-MiniLM-L6-v2
            
        return ArtemisTensor(static_tensor=static_tensor, llm_tensor=llm_tensor)