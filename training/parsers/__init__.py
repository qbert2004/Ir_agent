# Parsers for different security datasets
#
# Доступные парсеры:
#   - mordor_parser: Mordor Security Datasets (MITRE ATT&CK recordings)
#   - sigma_parser: Sigma Detection Rules (3000+ rules)
#   - network_parser: Network traffic datasets (CICIDS, UNSW-NB15)
#
# Использование:
#   from training.parsers.mordor_parser import parse_mordor
#   from training.parsers.sigma_parser import SigmaRulesParser
#   from training.parsers.network_parser import parse_cicids, parse_unsw

__all__ = [
    'parse_mordor',
    'SigmaRulesParser',
    'parse_cicids',
    'parse_unsw',
]

# Lazy imports to avoid loading everything at once
def parse_mordor(*args, **kwargs):
    from .mordor_parser import parse_mordor as _parse_mordor
    return _parse_mordor(*args, **kwargs)

def parse_cicids(*args, **kwargs):
    from .network_parser import parse_cicids as _parse_cicids
    return _parse_cicids(*args, **kwargs)

def parse_unsw(*args, **kwargs):
    from .network_parser import parse_unsw as _parse_unsw
    return _parse_unsw(*args, **kwargs)
