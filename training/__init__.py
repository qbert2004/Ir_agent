# Training package for Neural Classifier
#
# Модуль обучения нейросетевого классификатора для детекции угроз
#
# Структура:
#   training/
#   ├── parsers/              # Парсеры датасетов
#   │   ├── mordor_parser.py  # Mordor Security Datasets
#   │   ├── sigma_parser.py   # Sigma Detection Rules
#   │   └── network_parser.py # CICIDS, UNSW-NB15
#   ├── data/                 # Подготовленные данные
#   ├── models/               # Обученные модели
#   ├── prepare_data.py       # Базовая подготовка
#   ├── prepare_data_full.py  # Полная подготовка
#   ├── validate_data.py      # Валидация данных
#   ├── augment_data.py       # Аугментация
#   ├── train.py              # Обучение
#   └── run_pipeline.py       # Полный пайплайн
#
# Использование:
#   1. python training/install_deps.py
#   2. python scripts/download_datasets.py --all
#   3. python training/run_pipeline.py
#
# Или по шагам:
#   1. python training/prepare_data_full.py
#   2. python training/validate_data.py
#   3. python training/train.py

__version__ = "1.0.0"
