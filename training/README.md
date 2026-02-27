# Обучение нейросетевого классификатора

## Обзор

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ПРОЦЕСС ОБУЧЕНИЯ                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ШАГ 1: Подготовка данных              ШАГ 2: Обучение                    │
│   ─────────────────────────              ──────────────────                 │
│   Компьютер: ЛЮБОЙ                       Компьютер: С GPU                   │
│   GPU: НЕ НУЖЕН                          GPU: НУЖЕН (8GB+ VRAM)             │
│                                                                             │
│   python training/prepare_data.py        python training/train.py           │
│            │                                      │                         │
│            ▼                                      ▼                         │
│   training/data/                         models/neural_classifier.pt        │
│   ├── train_events.json                                                     │
│   ├── train_labels.json                                                     │
│   ├── val_events.json                                                       │
│   └── val_labels.json                                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ШАГ 1: Подготовка данных (на текущем компьютере)

### 1.1 Убедитесь что есть датасет

```
datasets/
└── EVTX-ATTACK-SAMPLES/
    ├── Credential Access/
    ├── Defense Evasion/
    ├── Discovery/
    └── ...
```

Если нет - скачайте:
```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES datasets/EVTX-ATTACK-SAMPLES
```

### 1.2 Установите зависимости

```bash
pip install python-evtx
```

### 1.3 Запустите подготовку данных

```bash
python training/prepare_data.py
```

### 1.4 Проверьте результат

После выполнения появятся файлы:
```
training/data/
├── train_events.json    # ~80% данных для обучения
├── train_labels.json    # метки для train
├── val_events.json      # ~20% данных для валидации
├── val_labels.json      # метки для validation
└── data_stats.json      # статистика
```

### 1.5 Скопируйте проект

Скопируйте весь проект на новый компьютер с GPU:
- Папка `training/data/` (подготовленные данные)
- Папка `app/ml/` (код классификатора)
- Файл `training/train.py` (скрипт обучения)

---

## ШАГ 2: Обучение (на компьютере с GPU)

### 2.1 Требования к железу

| GPU | VRAM | Скорость | Рекомендация |
|-----|------|----------|--------------|
| RTX 3060 | 12GB | Хорошо | Рекомендуется |
| RTX 3070/3080 | 8-10GB | Отлично | Рекомендуется |
| RTX 4070/4080 | 12-16GB | Отлично | Идеально |
| RTX 4090 | 24GB | Отлично | Избыточно для этой задачи |

**CPU тоже работает, но в 10-20x медленнее**

### 2.2 Установите зависимости

```bash
# PyTorch с CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Sentence Transformers
pip install sentence-transformers
```

### 2.3 Проверьте GPU

```python
import torch
print(f"CUDA доступна: {torch.cuda.is_available()}")
print(f"GPU: {torch.cuda.get_device_name(0)}")
```

### 2.4 Запустите обучение

```bash
# Базовый запуск
python training/train.py

# С параметрами
python training/train.py --epochs 100 --batch_size 64 --learning_rate 0.001
```

### 2.5 Параметры

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--embedding_model` | all-MiniLM-L6-v2 | Модель для embeddings |
| `--epochs` | 50 | Количество эпох |
| `--batch_size` | 32 | Размер батча |
| `--learning_rate` | 0.001 | Learning rate |
| `--dropout` | 0.3 | Dropout |
| `--patience` | 10 | Early stopping |

### 2.6 Результат

После обучения:
```
models/
├── neural_classifier.pt        # Финальная модель
├── neural_classifier_best.pt   # Лучшая по validation
└── training_history.json       # История обучения
```

---

## Использование обученной модели

### В коде

```python
from app.ml.neural_classifier import NeuralSecurityClassifier

# Загрузка модели
classifier = NeuralSecurityClassifier(
    model_path="models/neural_classifier.pt"
)

# Классификация
result = classifier.classify({
    "event_id": 4688,
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords"
})

print(result.predicted_class)  # "malicious_critical"
print(result.confidence)       # 0.95
```

### Через API

```bash
curl -X POST http://localhost:9000/ml/classify \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_id": 4688,
      "process_name": "mimikatz.exe",
      "command_line": "sekurlsa::logonpasswords"
    }
  }'
```

---

## Улучшение качества

### 1. Добавьте больше данных

Редактируйте `training/prepare_data.py`:
- Добавьте свои EVTX файлы в `datasets/`
- Добавьте ручную разметку
- Расширьте паттерны

### 2. Используйте лучшую embedding модель

```bash
# Больше модель = лучше качество, медленнее
python training/train.py --embedding_model all-mpnet-base-v2  # 768 dim
python training/train.py --embedding_model paraphrase-multilingual-MiniLM-L12-v2  # Мультиязычная
```

### 3. Увеличьте сложность сети

Редактируйте `training/train.py`:
```python
self.net = torch.nn.Sequential(
    torch.nn.Linear(embedding_dim, 1024),  # Больше нейронов
    ...
)
```

---

## Troubleshooting

### CUDA out of memory
```bash
# Уменьшите batch_size
python training/train.py --batch_size 16
```

### Низкая точность
1. Добавьте больше данных
2. Увеличьте epochs
3. Проверьте качество разметки

### Модель переобучается
```bash
# Увеличьте dropout
python training/train.py --dropout 0.5

# Уменьшите learning rate
python training/train.py --learning_rate 0.0001
```

---

## Полный пайплайн (один скрипт)

```bash
# Установка зависимостей
python training/install_deps.py

# Скачивание датасетов
python scripts/download_datasets.py --all

# Полный пайплайн
python training/run_pipeline.py

# С аугментацией
python training/run_pipeline.py --augment --augment-factor 2.0

# Только подготовка (на слабом компьютере)
python training/run_pipeline.py --prepare-only

# Только обучение (на GPU)
python training/run_pipeline.py --train-only
```

---

## Доступные датасеты

| Датасет | Размер | Описание |
|---------|--------|----------|
| EVTX-ATTACK-SAMPLES | ~500MB | Windows Event Logs атак |
| Mordor | ~2-5GB | Записи атак по MITRE ATT&CK |
| Sigma Rules | ~100MB | 3000+ правил детекции |
| CICIDS2017/2018 | ~50GB+ | Сетевой трафик (требует ручного скачивания) |
| UNSW-NB15 | ~2GB | Сетевые атаки (требует ручного скачивания) |

---

## Структура модуля training/

```
training/
├── parsers/               # Парсеры датасетов
│   ├── __init__.py
│   ├── mordor_parser.py   # Mordor Security Datasets
│   ├── sigma_parser.py    # Sigma Detection Rules
│   └── network_parser.py  # CICIDS, UNSW-NB15
├── data/                  # Подготовленные данные (после prepare_data)
├── models/                # Обученные модели (после train)
├── install_deps.py        # Установка зависимостей
├── prepare_data.py        # Базовая подготовка (только EVTX)
├── prepare_data_full.py   # Полная подготовка (все датасеты)
├── validate_data.py       # Валидация данных
├── augment_data.py        # Аугментация данных
├── train.py               # Обучение модели
├── run_pipeline.py        # Полный пайплайн
├── config.json            # Конфигурация
└── README.md              # Документация
```

---

## Чеклист

### На текущем компьютере (подготовка):
- [ ] Установить зависимости: `python training/install_deps.py`
- [ ] Скачать датасеты: `python scripts/download_datasets.py --all`
- [ ] Подготовить данные: `python training/prepare_data_full.py`
- [ ] Валидация: `python training/validate_data.py`
- [ ] Опционально аугментация: `python training/augment_data.py --balance`
- [ ] Скопировать проект на новый компьютер

### На новом компьютере (обучение):
- [ ] Установить PyTorch с CUDA
- [ ] Установить sentence-transformers
- [ ] Проверить `torch.cuda.is_available() == True`
- [ ] Запустить `python training/train.py`
- [ ] Проверить `training/models/neural_classifier.pt`

### Или автоматически:
```bash
python training/run_pipeline.py
```
