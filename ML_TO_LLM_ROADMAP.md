# Roadmap: ML → LLM для Cybersecurity

## Обзор путей развития

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ML → LLM EVOLUTION                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ТЕКУЩЕЕ СОСТОЯНИЕ              ЦЕЛЬ                                      │
│   ─────────────────              ────                                      │
│   Random Forest                  Собственная CyberLLM                      │
│   XGBoost                        ↓                                         │
│   Heuristics                     Fine-tuned LLM для                        │
│   ↓                              кибербезопасности                         │
│                                                                             │
│   ┌────────────────────────────────────────────────────────────────────┐   │
│   │                      ПУТИ РАЗВИТИЯ                                  │   │
│   ├────────────────────────────────────────────────────────────────────┤   │
│   │                                                                     │   │
│   │  ПУТЬ 1: Neural Classifier (Гибрид)     ← РЕАЛИЗОВАНО              │   │
│   │  Сложность: ★★☆☆☆                                                  │   │
│   │  GPU: 8GB VRAM                                                      │   │
│   │  Время: 1-2 дня                                                     │   │
│   │  Файл: app/ml/neural_classifier.py                                  │   │
│   │                                                                     │   │
│   │  ПУТЬ 2: Fine-tune Small LLM (Phi-2)    ← СКРИПТ ГОТОВ             │   │
│   │  Сложность: ★★★☆☆                                                  │   │
│   │  GPU: 8-12GB VRAM                                                   │   │
│   │  Время: 3-5 дней                                                    │   │
│   │  Файл: scripts/finetune_llm.py                                      │   │
│   │                                                                     │   │
│   │  ПУТЬ 3: Fine-tune Large LLM (Llama/Mistral)                       │   │
│   │  Сложность: ★★★★☆                                                  │   │
│   │  GPU: 24GB+ VRAM или облако                                         │   │
│   │  Время: 1-2 недели                                                  │   │
│   │                                                                     │   │
│   │  ПУТЬ 4: Train from Scratch                                         │   │
│   │  Сложность: ★★★★★                                                  │   │
│   │  GPU: Кластер GPU                                                   │   │
│   │  Время: Месяцы                                                      │   │
│   │  НЕ РЕКОМЕНДУЕТСЯ для этого проекта                                │   │
│   └────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ПУТЬ 1: Neural Classifier (Гибридный подход)

### Что это
Комбинация LLM embeddings + нейросетевой классификатор.

```
Event Text ──▶ [Sentence Transformer] ──▶ Embedding ──▶ [Neural Net] ──▶ Class
               (понимание текста)        (384 dim)     (обучаемый)
```

### Преимущества
- ✅ LLM-уровень понимания текста
- ✅ Быстрый inference (~10ms)
- ✅ Работает offline
- ✅ Можно обучить на CPU
- ✅ Достаточно 1000+ примеров

### Файл
`app/ml/neural_classifier.py`

### Использование
```python
from app.ml.neural_classifier import NeuralSecurityClassifier

classifier = NeuralSecurityClassifier()

# Классификация
result = classifier.classify({
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords"
})
print(result.predicted_class)  # "malicious_critical"
print(result.confidence)       # 0.95

# Обучение
classifier.train(events, labels, epochs=50)
```

### Требования
```
torch>=2.0
sentence-transformers>=2.0
```

---

## ПУТЬ 2: Fine-tune Small LLM

### Рекомендуемые модели

| Модель | Размер | VRAM | Качество | Скорость |
|--------|--------|------|----------|----------|
| **microsoft/phi-2** | 2.7B | 6-8GB | Хорошее | Быстро |
| **TinyLlama/TinyLlama-1.1B** | 1.1B | 4GB | Среднее | Очень быстро |
| **stabilityai/stablelm-2-1_6b** | 1.6B | 5GB | Хорошее | Быстро |

### Скрипт
`scripts/finetune_llm.py`

### Запуск
```bash
# Phi-2 с 4-bit квантизацией (6GB VRAM)
python scripts/finetune_llm.py \
    --model_name "microsoft/phi-2" \
    --output_dir "./cyberllm-phi2" \
    --use_4bit \
    --epochs 3

# TinyLlama (4GB VRAM)
python scripts/finetune_llm.py \
    --model_name "TinyLlama/TinyLlama-1.1B-Chat-v1.0" \
    --output_dir "./cyberllm-tiny" \
    --epochs 5
```

### Требования
```
pip install transformers peft bitsandbytes accelerate datasets trl
```

### Время обучения
- 1000 примеров: ~30 минут
- 10000 примеров: ~3-4 часа

---

## ПУТЬ 3: Fine-tune Large LLM

### Рекомендуемые модели

| Модель | Размер | VRAM (QLoRA) | Качество |
|--------|--------|--------------|----------|
| **meta-llama/Llama-2-7b** | 7B | 12-16GB | Отличное |
| **mistralai/Mistral-7B-v0.1** | 7B | 12-16GB | Отличное |
| **meta-llama/Llama-3-8B** | 8B | 16-20GB | Лучшее |

### Запуск (с QLoRA)
```bash
python scripts/finetune_llm.py \
    --model_name "mistralai/Mistral-7B-v0.1" \
    --output_dir "./cyberllm-mistral" \
    --use_4bit \
    --epochs 3 \
    --batch_size 2 \
    --lora_r 32
```

### Облачные варианты

| Платформа | GPU | Цена/час | Рекомендация |
|-----------|-----|----------|--------------|
| **RunPod** | RTX 4090 | $0.44 | Лучшее соотношение |
| **Lambda Labs** | A100 | $1.10 | Для больших моделей |
| **Google Colab Pro** | T4/A100 | $10/мес | Для экспериментов |
| **Vast.ai** | RTX 3090 | $0.20 | Самый дешёвый |

---

## Подготовка данных для обучения

### Формат данных

```json
{
    "instruction": "Classify this security event: ...",
    "response": "Classification: MALICIOUS\nMITRE: T1003.001\n..."
}
```

### Источники данных для кибербезопасности

1. **EVTX-ATTACK-SAMPLES** (уже есть в проекте)
   - 4,633 реальных событий атак
   - Windows Event Logs

2. **MITRE ATT&CK**
   - Описания техник
   - Примеры детекции
   - Mitigations

3. **Sigma Rules**
   - 3000+ правил детекции
   - Описания угроз
   - https://github.com/SigmaHQ/sigma

4. **Threat Reports**
   - APT reports (Mandiant, CrowdStrike)
   - Incident reports

5. **Security StackExchange**
   - Q&A по кибербезопасности

### Скрипт генерации данных

```python
# scripts/generate_training_data.py

def generate_event_classification_examples():
    """Generate training examples from EVTX data."""
    examples = []

    # Load EVTX events
    for evtx_file in Path("datasets/EVTX-ATTACK-SAMPLES").glob("**/*.evtx"):
        events = parse_evtx(evtx_file)

        for event in events:
            instruction = format_event_for_instruction(event)
            response = generate_classification_response(event)
            examples.append({
                "instruction": instruction,
                "response": response
            })

    return examples
```

---

## Сравнение подходов

| Аспект | Neural Classifier | Fine-tune Small | Fine-tune Large |
|--------|-------------------|-----------------|-----------------|
| **VRAM** | 4-8 GB | 6-12 GB | 16-24 GB |
| **Время обучения** | 1-2 часа | 3-5 часов | 10-20 часов |
| **Данные** | 1000+ | 5000+ | 10000+ |
| **Inference** | ~10ms | ~100ms | ~500ms |
| **Генерация текста** | Нет | Да | Да |
| **Offline** | Да | Да | Да |
| **Качество** | Хорошее | Очень хорошее | Отличное |

---

## Рекомендуемый план

### Этап 1: Neural Classifier (Сейчас)
```
1. Обучить neural_classifier.py на EVTX данных
2. Интегрировать в ML Engine
3. Сравнить с Random Forest
```

### Этап 2: Fine-tune Phi-2 (1-2 недели)
```
1. Собрать 5000+ instruction-response пар
2. Fine-tune Phi-2 с QLoRA
3. Интегрировать для генерации отчётов
```

### Этап 3: Fine-tune Mistral-7B (Опционально)
```
1. Если нужно лучшее качество
2. Собрать 10000+ примеров
3. Использовать облачный GPU
```

---

## Интеграция в проект

### Архитектура с CyberLLM

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ФИНАЛЬНАЯ АРХИТЕКТУРА                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Events ──▶ [Neural Classifier] ──▶ Classification                        │
│                    │                       │                                │
│                    │                       ▼                                │
│                    │              [ML Engine] ──▶ Structured Analysis      │
│                    │                       │                                │
│                    │                       ▼                                │
│                    └─────────────▶ [CyberLLM] ──▶ Reports & Explanations   │
│                                   (Fine-tuned)                              │
│                                                                             │
│   Без внешних API!                                                         │
│   Полностью автономно!                                                     │
│   Работает offline!                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Код интеграции

```python
from app.ml.neural_classifier import get_neural_classifier
from app.ml.cyber_ml_engine import get_ml_engine

# Будущее: from cyberllm import CyberLLM

class AutonomousInvestigator:
    def __init__(self):
        self.neural = get_neural_classifier()
        self.ml_engine = get_ml_engine()
        # self.llm = CyberLLM.from_pretrained("./cyberllm")

    def investigate(self, events):
        # 1. Neural classification
        classifications = self.neural.classify_batch(events)

        # 2. ML analysis
        result = self.ml_engine.investigate("INC-001", events)

        # 3. LLM report generation (local, no API)
        # report = self.llm.generate_report(result)

        return result
```

---

## Требования к библиотекам

### requirements-ml.txt
```
# Neural Classifier
torch>=2.0.0
sentence-transformers>=2.2.0

# LLM Fine-tuning
transformers>=4.36.0
peft>=0.7.0
bitsandbytes>=0.41.0
accelerate>=0.25.0
datasets>=2.14.0
trl>=0.7.0

# Training utilities
wandb  # optional, for tracking
tensorboard  # optional, for visualization
```

### Установка
```bash
pip install -r requirements-ml.txt
```

---

## FAQ

**Q: Можно ли обойтись без GPU?**
A: Neural Classifier - да (медленнее). Fine-tuning - нет, нужен GPU.

**Q: Сколько данных нужно?**
A: Минимум 1000 примеров. Оптимально 5000-10000.

**Q: Какую модель выбрать для начала?**
A: Phi-2 - лучший баланс качества и требований.

**Q: Можно ли использовать результат коммерчески?**
A: Зависит от лицензии базовой модели:
- Phi-2: MIT License (можно)
- Llama 2: Community License (ограничения)
- Mistral: Apache 2.0 (можно)

**Q: Как измерить качество?**
A: Метрики: F1, Accuracy на тестовом наборе + human evaluation.
