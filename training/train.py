"""
Скрипт обучения нейросетевого классификатора.

ЗАПУСКАТЬ НА КОМПЬЮТЕРЕ С GPU (RTX 3060+ рекомендуется)

Требования:
    pip install torch sentence-transformers

Использование:
    python training/train.py

    Или с параметрами:
    python training/train.py --epochs 100 --batch_size 64 --embedding_model all-MiniLM-L6-v2

После обучения модель сохраняется в:
    models/neural_classifier.pt
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Добавляем корень проекта
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Проверяем зависимости
try:
    import torch
    import numpy as np
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("ОШИБКА: PyTorch не установлен!")
    print("Установите: pip install torch")
    sys.exit(1)

try:
    from sentence_transformers import SentenceTransformer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("ОШИБКА: sentence-transformers не установлен!")
    print("Установите: pip install sentence-transformers")
    sys.exit(1)

# Пути
DATA_DIR = ROOT / "training" / "data"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

# Классы
EVENT_CLASSES = [
    "benign",
    "suspicious_low",
    "suspicious_medium",
    "malicious_high",
    "malicious_critical",
]


# ============================================================================
# НЕЙРОСЕТЬ
# ============================================================================

class SecurityClassifierNet(torch.nn.Module):
    """Нейросетевой классификатор событий безопасности."""

    def __init__(self, embedding_dim: int = 384, num_classes: int = 5, dropout: float = 0.3):
        super().__init__()

        self.net = torch.nn.Sequential(
            torch.nn.Linear(embedding_dim, 512),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.BatchNorm1d(512),

            torch.nn.Linear(512, 256),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout * 0.7),
            torch.nn.BatchNorm1d(256),

            torch.nn.Linear(256, 128),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout * 0.5),

            torch.nn.Linear(128, num_classes)
        )

    def forward(self, x):
        return self.net(x)


# ============================================================================
# ПОДГОТОВКА ДАННЫХ
# ============================================================================

def event_to_text(event: dict) -> str:
    """Конвертирует событие в текст для embedding."""
    parts = []

    event_id = event.get('event_id', '')
    if event_id:
        parts.append(f"Event ID {event_id}")

    process = event.get('process_name', '')
    if process:
        parts.append(f"Process: {process}")

    cmdline = event.get('command_line', '')
    if cmdline:
        cmdline = cmdline[:500]  # Ограничиваем длину
        parts.append(f"Command: {cmdline}")

    parent = event.get('parent_image', '')
    if parent:
        parts.append(f"Parent: {parent}")

    user = event.get('user', '')
    if user:
        parts.append(f"User: {user}")

    return " | ".join(parts) if parts else "Unknown event"


def load_data():
    """Загружает подготовленные данные."""
    print("Загрузка данных...")

    with open(DATA_DIR / "train_events.json", "r", encoding="utf-8") as f:
        train_events = json.load(f)

    with open(DATA_DIR / "train_labels.json", "r", encoding="utf-8") as f:
        train_labels = json.load(f)

    with open(DATA_DIR / "val_events.json", "r", encoding="utf-8") as f:
        val_events = json.load(f)

    with open(DATA_DIR / "val_labels.json", "r", encoding="utf-8") as f:
        val_labels = json.load(f)

    print(f"  Train: {len(train_events)} событий")
    print(f"  Validation: {len(val_events)} событий")

    return train_events, train_labels, val_events, val_labels


def generate_embeddings(events: list, model: SentenceTransformer, batch_size: int = 64) -> np.ndarray:
    """Генерирует embeddings для событий."""
    texts = [event_to_text(e) for e in events]
    embeddings = model.encode(texts, batch_size=batch_size, show_progress_bar=True)
    return embeddings


def labels_to_indices(labels: list) -> np.ndarray:
    """Конвертирует текстовые метки в индексы."""
    label_to_idx = {label: idx for idx, label in enumerate(EVENT_CLASSES)}
    return np.array([label_to_idx.get(l, 0) for l in labels])


# ============================================================================
# ОБУЧЕНИЕ
# ============================================================================

def train(
    embedding_model: str = "all-MiniLM-L6-v2",
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 0.001,
    dropout: float = 0.3,
    patience: int = 10,
):
    """Основная функция обучения."""

    # Определяем устройство
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"\nУстройство: {device}")

    if device == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")

    # Загружаем embedding модель
    print(f"\nЗагрузка embedding модели: {embedding_model}")
    embedder = SentenceTransformer(embedding_model)
    embedding_dim = embedder.get_sentence_embedding_dimension()
    print(f"Размерность embedding: {embedding_dim}")

    # Загружаем данные
    train_events, train_labels, val_events, val_labels = load_data()

    # Генерируем embeddings
    print("\nГенерация embeddings для train...")
    X_train = generate_embeddings(train_events, embedder, batch_size=64)

    print("Генерация embeddings для validation...")
    X_val = generate_embeddings(val_events, embedder, batch_size=64)

    # Конвертируем метки
    y_train = labels_to_indices(train_labels)
    y_val = labels_to_indices(val_labels)

    print(f"\nРазмеры данных:")
    print(f"  X_train: {X_train.shape}")
    print(f"  X_val: {X_val.shape}")

    # Создаём DataLoader
    train_dataset = torch.utils.data.TensorDataset(
        torch.FloatTensor(X_train),
        torch.LongTensor(y_train)
    )
    val_dataset = torch.utils.data.TensorDataset(
        torch.FloatTensor(X_val),
        torch.LongTensor(y_val)
    )

    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = torch.utils.data.DataLoader(val_dataset, batch_size=batch_size)

    # Создаём модель
    model = SecurityClassifierNet(
        embedding_dim=embedding_dim,
        num_classes=len(EVENT_CLASSES),
        dropout=dropout
    ).to(device)

    print(f"\nАрхитектура модели:")
    print(model)

    total_params = sum(p.numel() for p in model.parameters())
    print(f"\nВсего параметров: {total_params:,}")

    # Вычисляем class weights для балансировки
    class_counts = np.bincount(y_train, minlength=len(EVENT_CLASSES))
    class_counts = np.maximum(class_counts, 1)  # Избегаем деления на 0
    class_weights = 1.0 / class_counts
    class_weights = class_weights / class_weights.sum() * len(EVENT_CLASSES)  # Нормализуем
    class_weights = torch.FloatTensor(class_weights).to(device)

    print(f"\nClass weights (для балансировки):")
    for i, cls in enumerate(EVENT_CLASSES):
        print(f"  {cls}: {class_weights[i]:.4f} (samples: {class_counts[i]})")

    # Оптимизатор и loss с весами классов
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=5, factor=0.5)

    # Обучение
    print(f"\n{'='*70}")
    print("ОБУЧЕНИЕ")
    print(f"{'='*70}")
    print(f"Epochs: {epochs}")
    print(f"Batch size: {batch_size}")
    print(f"Learning rate: {learning_rate}")
    print(f"Early stopping patience: {patience}")

    best_val_loss = float('inf')
    best_val_acc = 0
    patience_counter = 0
    history = {'train_loss': [], 'val_loss': [], 'val_acc': []}

    for epoch in range(epochs):
        # Train
        model.train()
        train_loss = 0.0

        for batch_x, batch_y in train_loader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()

        train_loss /= len(train_loader)

        # Validation
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x = batch_x.to(device)
                batch_y = batch_y.to(device)

                outputs = model(batch_x)
                loss = criterion(outputs, batch_y)
                val_loss += loss.item()

                _, predicted = torch.max(outputs, 1)
                total += batch_y.size(0)
                correct += (predicted == batch_y).sum().item()

        val_loss /= len(val_loader)
        val_acc = correct / total

        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_loss)
        history['val_acc'].append(val_acc)

        # Learning rate scheduling
        scheduler.step(val_loss)

        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_val_acc = val_acc
            patience_counter = 0

            # Сохраняем лучшую модель
            save_model(model, embedding_model, embedding_dim, "models/neural_classifier_best.pt")
        else:
            patience_counter += 1

        # Логирование
        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(f"Epoch {epoch+1:3d}/{epochs} | "
                  f"Train Loss: {train_loss:.4f} | "
                  f"Val Loss: {val_loss:.4f} | "
                  f"Val Acc: {val_acc:.2%}")

        if patience_counter >= patience:
            print(f"\nEarly stopping на epoch {epoch+1}")
            break

    # Финальная модель
    print(f"\n{'='*70}")
    print("РЕЗУЛЬТАТЫ")
    print(f"{'='*70}")
    print(f"Лучший Val Loss: {best_val_loss:.4f}")
    print(f"Лучший Val Accuracy: {best_val_acc:.2%}")

    # Сохраняем финальную модель
    save_model(model, embedding_model, embedding_dim, "models/neural_classifier.pt")

    # Сохраняем историю обучения
    with open(MODELS_DIR / "training_history.json", "w") as f:
        json.dump(history, f, indent=2)

    print(f"\nМодель сохранена в: models/neural_classifier.pt")
    print(f"История обучения: models/training_history.json")

    # Тестируем
    print(f"\n{'='*70}")
    print("ТЕСТИРОВАНИЕ")
    print(f"{'='*70}")
    test_model(model, embedder, device)


def save_model(model, embedding_model: str, embedding_dim: int, path: str):
    """Сохраняет модель."""
    torch.save({
        'model_state_dict': model.state_dict(),
        'class_names': EVENT_CLASSES,
        'embedding_dim': embedding_dim,
        'embedding_model': embedding_model,
        'created_at': datetime.now().isoformat(),
    }, path)


def test_model(model, embedder, device):
    """Тестирует модель на примерах."""
    test_events = [
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
            "command_line": "powershell.exe -enc SGVsbG8= -w hidden",
        },
        {
            "event_id": 4688,
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vssadmin delete shadows /all",
        },
    ]

    model.eval()

    for event in test_events:
        text = event_to_text(event)
        embedding = embedder.encode([text])

        with torch.no_grad():
            x = torch.FloatTensor(embedding).to(device)
            logits = model(x)
            probs = torch.nn.functional.softmax(logits, dim=1)[0]
            pred_idx = torch.argmax(probs).item()
            pred_class = EVENT_CLASSES[pred_idx]
            confidence = probs[pred_idx].item()

        print(f"\n  Process: {event['process_name']}")
        print(f"  Command: {event['command_line'][:50]}...")
        print(f"  Prediction: {pred_class} ({confidence:.2%})")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Обучение нейросетевого классификатора")
    parser.add_argument("--embedding_model", type=str, default="all-MiniLM-L6-v2",
                        help="Модель для embeddings")
    parser.add_argument("--epochs", type=int, default=50,
                        help="Количество эпох")
    parser.add_argument("--batch_size", type=int, default=32,
                        help="Размер батча")
    parser.add_argument("--learning_rate", type=float, default=0.001,
                        help="Learning rate")
    parser.add_argument("--dropout", type=float, default=0.3,
                        help="Dropout")
    parser.add_argument("--patience", type=int, default=10,
                        help="Early stopping patience")
    args = parser.parse_args()

    # Проверяем наличие данных
    if not (DATA_DIR / "train_events.json").exists():
        print("ОШИБКА: Данные не найдены!")
        print("Сначала запустите: python training/prepare_data.py")
        sys.exit(1)

    print("=" * 70)
    print("ОБУЧЕНИЕ НЕЙРОСЕТЕВОГО КЛАССИФИКАТОРА")
    print("=" * 70)

    train(
        embedding_model=args.embedding_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        dropout=args.dropout,
        patience=args.patience,
    )

    print("\n" + "=" * 70)
    print("ОБУЧЕНИЕ ЗАВЕРШЕНО!")
    print("=" * 70)


if __name__ == "__main__":
    main()
