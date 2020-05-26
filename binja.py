from binaryninja.enums import SymbolType, SymbolBinding
from binaryninja.types import Symbol, Type, FunctionParameter
from binaryninja.binaryview import BinaryViewType

from .util import get_symbol_name, find_nested_types
from .base import Dependency, register_dependency_type

EXPORTABLE_TYPES = {SymbolType.FunctionSymbol, SymbolType.DataSymbol}


@register_dependency_type
class BinaryViewDependency(Dependency):
    @classmethod
    def can_parse(cls, file):
        # Hard to predict, so let's assume we can try for everything
        return True

    def __init__(self, file):
        self.bv = BinaryViewType.get_view_of_file(file, update_analysis=False)

    def is_valid(self):
        return self.bv is not None and self.bv.has_symbols

    def get_exports(self):
        return [
            Symbol(s.type, s.address,
                s.short_name, full_name=get_symbol_name(self.bv, s), raw_name=s.raw_name,
                binding=s.binding, namespace=s.namespace, ordinal=s.ordinal
            )
            for s in self.bv.get_symbols() if s.type in EXPORTABLE_TYPES and s.binding == SymbolBinding.GlobalBinding
        ]

    def get_symbol_type(self, sym):
        if self.bv.has_database:
            func = self.bv.get_function_at(sym.address)
            if func:
                return Type.function(
                    func.return_type, [FunctionParameter(param.type, param.name, location=param) for param in func.parameter_vars],
                    calling_convention=func.calling_convention, variable_arguments=func.has_variable_arguments, stack_adjust=func.stack_adjustment
                )
            dvar = self.bv.get_data_var_at(sym.address)
            if dvar:
                return dvar.type
        return None

    def get_user_types(self, sym):
        if self.bv.has_database:
            symtype = self.get_symbol_type(sym)
            if symtype is not None:
                return find_nested_types(self.bv, symtype)
        return {}
