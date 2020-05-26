import enum
from binaryninja.log import log_error

class Dependency:
    @classmethod
    def can_parse(cls, file):
        raise NotImplemented

    def is_valid(self):
        raise NotImplemented

    def get_exports(self):
        raise NotImplemented

    def get_symbol_type(self, sym):
        return None

    def get_user_types(self, sym):
        return {}

class MatchingMethod(enum.Enum):
    Auto    = 'auto'
    Ordinal = 'ordinal'
    Name    = 'name'
    Address = 'address'


TYPES = []

def register_dependency_type(cls):
    TYPES.append(cls)
    
def parse_dependency(file):
    ds = []
    for dt in TYPES:
        try:
            if not dt.can_parse(file):
                continue
            d = dt(file)
            if not d.is_valid():
                continue
            ds.append(d)
        except Exception as e:
            log_error('{} could not parse "{}": {}'.format(dt.__name__, file, e))
            continue
    return ds
