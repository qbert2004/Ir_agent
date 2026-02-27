"""
Neural Security Event Classifier

Hybrid approach: LLM Embeddings + Neural Network Classifier
This gives you LLM-level text understanding with ML speed and interpretability.

Architecture:
    Event Text ──▶ [Sentence Transformer] ──▶ Embedding ──▶ [Neural Network] ──▶ Classification
                   (frozen, pretrained)      (384-768d)     (trainable)

This is the bridge between traditional ML and full LLM:
- Uses transformer embeddings (LLM-like understanding)
- Fast inference (no LLM API calls)
- Can run offline
- Trainable on small datasets (1000+ samples)
"""

import os
import json
import pickle
import logging
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np

logger = logging.getLogger("neural-classifier")

# Try to import deep learning libraries
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available - neural classifier disabled")

try:
    from sentence_transformers import SentenceTransformer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class NeuralClassificationResult:
    """Result from neural classifier."""
    predicted_class: str
    confidence: float
    all_probabilities: Dict[str, float]
    embedding_used: bool = True


# ============================================================================
# NEURAL NETWORK ARCHITECTURE
# ============================================================================

if TORCH_AVAILABLE:

    class SecurityEventClassifier(nn.Module):
        """
        Neural network classifier for security events.

        Architecture:
            Input (embedding_dim)
            → Linear(512) → ReLU → Dropout(0.3)
            → Linear(256) → ReLU → Dropout(0.2)
            → Linear(num_classes)
            → Softmax
        """

        def __init__(self, embedding_dim: int = 384, num_classes: int = 10, dropout: float = 0.3):
            super().__init__()

            self.classifier = nn.Sequential(
                nn.Linear(embedding_dim, 512),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.BatchNorm1d(512),

                nn.Linear(512, 256),
                nn.ReLU(),
                nn.Dropout(dropout * 0.7),
                nn.BatchNorm1d(256),

                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Dropout(dropout * 0.5),

                nn.Linear(128, num_classes)
            )

        def forward(self, x):
            return self.classifier(x)

        def predict_proba(self, x):
            with torch.no_grad():
                logits = self.forward(x)
                return F.softmax(logits, dim=1)


    class SecurityEventDataset(Dataset):
        """Dataset for training the classifier."""

        def __init__(self, embeddings: np.ndarray, labels: np.ndarray):
            self.embeddings = torch.FloatTensor(embeddings)
            self.labels = torch.LongTensor(labels)

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            return self.embeddings[idx], self.labels[idx]


# ============================================================================
# MAIN CLASSIFIER CLASS
# ============================================================================

class NeuralSecurityClassifier:
    """
    Hybrid LLM + Neural Network classifier for security events.

    Uses sentence-transformers for embeddings (LLM-level understanding)
    and a trainable neural network for classification.
    """

    # Class labels for incident types
    INCIDENT_CLASSES = [
        "benign",
        "malware",
        "ransomware",
        "credential_theft",
        "lateral_movement",
        "data_exfiltration",
        "persistence",
        "command_and_control",
        "reconnaissance",
        "privilege_escalation",
    ]

    # Class labels for event classification (binary + severity)
    EVENT_CLASSES = [
        "benign",
        "suspicious_low",
        "suspicious_medium",
        "malicious_high",
        "malicious_critical",
    ]

    def __init__(
        self,
        embedding_model: str = "all-MiniLM-L6-v2",
        model_path: Optional[str] = None,
        device: str = "auto"
    ):
        """
        Initialize the neural classifier.

        Args:
            embedding_model: Sentence transformer model name
            model_path: Path to saved classifier weights
            device: "cpu", "cuda", or "auto"
        """
        self.embedding_model_name = embedding_model
        self.model_path = model_path
        self.embedder = None
        self.classifier = None
        self.class_names = self.EVENT_CLASSES
        self.embedding_dim = 384  # Default for MiniLM

        # Determine device
        if device == "auto":
            self.device = "cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self._initialized = False

        # Initialize if libraries available
        if TORCH_AVAILABLE and TRANSFORMERS_AVAILABLE:
            self._initialize()

    def _initialize(self):
        """Initialize embedding model and classifier."""
        try:
            # Load embedding model
            logger.info(f"Loading embedding model: {self.embedding_model_name}")
            self.embedder = SentenceTransformer(self.embedding_model_name)
            self.embedding_dim = self.embedder.get_sentence_embedding_dimension()
            logger.info(f"Embedding dimension: {self.embedding_dim}")

            # Initialize classifier
            self.classifier = SecurityEventClassifier(
                embedding_dim=self.embedding_dim,
                num_classes=len(self.class_names)
            ).to(self.device)

            # Load weights if available
            if self.model_path and os.path.exists(self.model_path):
                self._load_model(self.model_path)
            else:
                logger.info("No pre-trained classifier found - using random weights")
                logger.info("Train the model with .train() method")

            self._initialized = True
            logger.info(f"Neural classifier initialized on {self.device}")

        except Exception as e:
            logger.error(f"Failed to initialize neural classifier: {e}")
            self._initialized = False

    def _event_to_text(self, event: Dict[str, Any]) -> str:
        """Convert event dict to text for embedding."""
        parts = []

        # Event type/ID
        event_id = event.get('event_id', event.get('EventID', ''))
        if event_id:
            parts.append(f"Event ID {event_id}")

        event_type = event.get('event_type', event.get('EventType', ''))
        if event_type:
            parts.append(f"Type: {event_type}")

        # Process information
        process = event.get('process_name', event.get('ProcessName', event.get('Image', '')))
        if process:
            parts.append(f"Process: {process}")

        # Command line (most important)
        cmdline = event.get('command_line', event.get('CommandLine', ''))
        if cmdline:
            # Truncate very long command lines
            cmdline = cmdline[:500] if len(cmdline) > 500 else cmdline
            parts.append(f"Command: {cmdline}")

        # Parent process
        parent = event.get('parent_image', event.get('ParentImage', ''))
        if parent:
            parts.append(f"Parent: {parent}")

        # User
        user = event.get('user', event.get('SubjectUserName', event.get('TargetUserName', '')))
        if user:
            parts.append(f"User: {user}")

        # Network
        dest_ip = event.get('destination_ip', event.get('DestinationIp', ''))
        dest_port = event.get('destination_port', event.get('DestinationPort', ''))
        if dest_ip:
            parts.append(f"Destination: {dest_ip}:{dest_port}" if dest_port else f"Destination: {dest_ip}")

        # File path
        file_path = event.get('file_path', event.get('TargetFilename', ''))
        if file_path:
            parts.append(f"File: {file_path}")

        return " | ".join(parts) if parts else "Unknown event"

    def embed(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Generate embeddings for events.

        Args:
            events: List of event dictionaries

        Returns:
            Numpy array of embeddings (n_events, embedding_dim)
        """
        if not self._initialized:
            raise RuntimeError("Classifier not initialized")

        texts = [self._event_to_text(e) for e in events]
        embeddings = self.embedder.encode(texts, convert_to_numpy=True)
        return embeddings

    def classify(self, event: Dict[str, Any]) -> NeuralClassificationResult:
        """
        Classify a single security event.

        Args:
            event: Security event dictionary

        Returns:
            NeuralClassificationResult with class and confidence
        """
        if not self._initialized:
            return NeuralClassificationResult(
                predicted_class="unknown",
                confidence=0.0,
                all_probabilities={},
                embedding_used=False
            )

        # Get embedding
        embedding = self.embed([event])[0]

        # Classify
        self.classifier.eval()
        with torch.no_grad():
            x = torch.FloatTensor(embedding).unsqueeze(0).to(self.device)
            probs = self.classifier.predict_proba(x)[0].cpu().numpy()

        # Get results
        predicted_idx = int(np.argmax(probs))
        predicted_class = self.class_names[predicted_idx]
        confidence = float(probs[predicted_idx])

        all_probs = {
            self.class_names[i]: float(probs[i])
            for i in range(len(self.class_names))
        }

        return NeuralClassificationResult(
            predicted_class=predicted_class,
            confidence=confidence,
            all_probabilities=all_probs,
            embedding_used=True
        )

    def classify_batch(self, events: List[Dict[str, Any]]) -> List[NeuralClassificationResult]:
        """Classify multiple events at once (more efficient)."""
        if not self._initialized:
            return [
                NeuralClassificationResult("unknown", 0.0, {}, False)
                for _ in events
            ]

        # Get embeddings
        embeddings = self.embed(events)

        # Classify batch
        self.classifier.eval()
        with torch.no_grad():
            x = torch.FloatTensor(embeddings).to(self.device)
            probs = self.classifier.predict_proba(x).cpu().numpy()

        results = []
        for i in range(len(events)):
            predicted_idx = int(np.argmax(probs[i]))
            predicted_class = self.class_names[predicted_idx]
            confidence = float(probs[i][predicted_idx])

            all_probs = {
                self.class_names[j]: float(probs[i][j])
                for j in range(len(self.class_names))
            }

            results.append(NeuralClassificationResult(
                predicted_class=predicted_class,
                confidence=confidence,
                all_probabilities=all_probs,
                embedding_used=True
            ))

        return results

    # ========================================================================
    # TRAINING
    # ========================================================================

    def train(
        self,
        events: List[Dict[str, Any]],
        labels: List[str],
        epochs: int = 50,
        batch_size: int = 32,
        learning_rate: float = 0.001,
        validation_split: float = 0.2,
        early_stopping_patience: int = 5
    ) -> Dict[str, Any]:
        """
        Train the classifier on labeled data.

        Args:
            events: List of event dictionaries
            labels: List of class labels (must match self.class_names)
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            validation_split: Fraction for validation
            early_stopping_patience: Stop if no improvement for N epochs

        Returns:
            Training history dict
        """
        if not self._initialized:
            raise RuntimeError("Classifier not initialized")

        logger.info(f"Training neural classifier on {len(events)} samples")

        # Convert labels to indices
        label_to_idx = {label: idx for idx, label in enumerate(self.class_names)}
        y = np.array([label_to_idx.get(l, 0) for l in labels])

        # Generate embeddings
        logger.info("Generating embeddings...")
        X = self.embed(events)

        # Split data
        n_val = int(len(X) * validation_split)
        indices = np.random.permutation(len(X))
        train_idx, val_idx = indices[n_val:], indices[:n_val]

        X_train, y_train = X[train_idx], y[train_idx]
        X_val, y_val = X[val_idx], y[val_idx]

        logger.info(f"Train: {len(X_train)}, Validation: {len(X_val)}")

        # Create datasets
        train_dataset = SecurityEventDataset(X_train, y_train)
        val_dataset = SecurityEventDataset(X_val, y_val)

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)

        # Setup training
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(
            self.classifier.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', patience=3, factor=0.5
        )

        # Training loop
        history = {'train_loss': [], 'val_loss': [], 'val_accuracy': []}
        best_val_loss = float('inf')
        patience_counter = 0

        for epoch in range(epochs):
            # Training
            self.classifier.train()
            train_loss = 0.0

            for batch_x, batch_y in train_loader:
                batch_x = batch_x.to(self.device)
                batch_y = batch_y.to(self.device)

                optimizer.zero_grad()
                outputs = self.classifier(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                train_loss += loss.item()

            train_loss /= len(train_loader)

            # Validation
            self.classifier.eval()
            val_loss = 0.0
            correct = 0
            total = 0

            with torch.no_grad():
                for batch_x, batch_y in val_loader:
                    batch_x = batch_x.to(self.device)
                    batch_y = batch_y.to(self.device)

                    outputs = self.classifier(batch_x)
                    loss = criterion(outputs, batch_y)
                    val_loss += loss.item()

                    _, predicted = torch.max(outputs, 1)
                    total += batch_y.size(0)
                    correct += (predicted == batch_y).sum().item()

            val_loss /= len(val_loader)
            val_accuracy = correct / total

            # Record history
            history['train_loss'].append(train_loss)
            history['val_loss'].append(val_loss)
            history['val_accuracy'].append(val_accuracy)

            # Learning rate scheduling
            scheduler.step(val_loss)

            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                self._save_model("models/neural_classifier_best.pt")
            else:
                patience_counter += 1

            if (epoch + 1) % 5 == 0:
                logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {train_loss:.4f}, "
                    f"Val Loss: {val_loss:.4f}, "
                    f"Val Acc: {val_accuracy:.2%}"
                )

            if patience_counter >= early_stopping_patience:
                logger.info(f"Early stopping at epoch {epoch+1}")
                break

        # Load best model
        self._load_model("models/neural_classifier_best.pt")

        logger.info(f"Training complete. Best validation accuracy: {max(history['val_accuracy']):.2%}")

        return history

    def _save_model(self, path: str):
        """Save model weights."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            'model_state_dict': self.classifier.state_dict(),
            'class_names': self.class_names,
            'embedding_dim': self.embedding_dim,
            'embedding_model': self.embedding_model_name,
        }, path)
        logger.info(f"Model saved to {path}")

    def _load_model(self, path: str):
        """Load model weights."""
        if not os.path.exists(path):
            return

        checkpoint = torch.load(path, map_location=self.device)

        # Update class names if different
        if 'class_names' in checkpoint:
            self.class_names = checkpoint['class_names']

        # Reinitialize classifier if needed
        if checkpoint.get('embedding_dim') != self.embedding_dim:
            self.classifier = SecurityEventClassifier(
                embedding_dim=checkpoint['embedding_dim'],
                num_classes=len(self.class_names)
            ).to(self.device)

        self.classifier.load_state_dict(checkpoint['model_state_dict'])
        logger.info(f"Model loaded from {path}")

    def save(self, path: str = "models/neural_classifier.pt"):
        """Save the trained model."""
        self._save_model(path)

    def load(self, path: str = "models/neural_classifier.pt"):
        """Load a trained model."""
        self._load_model(path)

    # ========================================================================
    # UTILITIES
    # ========================================================================

    @property
    def is_ready(self) -> bool:
        return self._initialized

    def get_info(self) -> Dict[str, Any]:
        """Get classifier information."""
        return {
            "initialized": self._initialized,
            "device": self.device,
            "embedding_model": self.embedding_model_name,
            "embedding_dim": self.embedding_dim,
            "num_classes": len(self.class_names),
            "class_names": self.class_names,
            "torch_available": TORCH_AVAILABLE,
            "transformers_available": TRANSFORMERS_AVAILABLE,
        }


# ============================================================================
# SINGLETON
# ============================================================================

_neural_classifier: Optional[NeuralSecurityClassifier] = None


def get_neural_classifier(
    embedding_model: str = "all-MiniLM-L6-v2",
    model_path: Optional[str] = "models/neural_classifier.pt"
) -> NeuralSecurityClassifier:
    """Get neural classifier singleton."""
    global _neural_classifier
    if _neural_classifier is None:
        _neural_classifier = NeuralSecurityClassifier(
            embedding_model=embedding_model,
            model_path=model_path
        )
    return _neural_classifier


# ============================================================================
# DEMO
# ============================================================================

def demo():
    """Demo the neural classifier."""
    print("=" * 70)
    print("Neural Security Classifier Demo")
    print("=" * 70)

    classifier = NeuralSecurityClassifier()

    if not classifier.is_ready:
        print("ERROR: Classifier not ready. Install torch and sentence-transformers.")
        return

    print(f"\nClassifier Info:")
    for k, v in classifier.get_info().items():
        print(f"  {k}: {v}")

    # Test events
    events = [
        {
            "event_id": 4688,
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        },
        {
            "event_id": 4688,
            "process_name": "notepad.exe",
            "command_line": "notepad.exe document.txt",
        },
        {
            "event_id": 4688,
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SGVsbG8gV29ybGQ= -w hidden",
        },
    ]

    print("\nClassifying events:")
    for event in events:
        result = classifier.classify(event)
        print(f"\n  Process: {event['process_name']}")
        print(f"  Class: {result.predicted_class}")
        print(f"  Confidence: {result.confidence:.2%}")


if __name__ == "__main__":
    demo()
