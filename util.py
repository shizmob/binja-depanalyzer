import os
from binaryninja.types import Symbol, Type
from binaryninja.demangle import get_qualified_name, demangle_gnu3, demangle_ms


DEMANGLERS = [demangle_gnu3, demangle_ms]

def demangle(bv, name):
	""" Try and demangle given name using all available demanglers """
	for demangler in DEMANGLERS:
		type, new_name = demangler(bv.arch, name)
		if type is None or name == new_name:
			continue
		return get_qualified_name(new_name)
	return name


def is_only_ordinal(sym):
	""" Check whether a symbol is only defined by ordinal """
	return sym.raw_name.lower().startswith('ordinal_') and sym.ordinal > 0

def supports_ordinals(bv):
	""" Check whether the BinaryView supports ordinal imports """
	return bv.view_type == 'PE'

def get_symbol_name(bv, sym):
	""" Get 'actual' name for symbol. """
	func = bv.get_function_at(sym.address)
	if func:
		name = func.name
	else:
		name = sym.full_name
	if sym.full_name == name and is_only_ordinal(sym):
		basename, _ = os.path.splitext(os.path.basename(bv.file.filename))
		return '{}_{}'.format(basename, sym.ordinal)
	return name

def set_symbol_name(bv, sym, name):
	""" Rename symbol to given name """
	# If the symbol has an associated function, this is way quicker and also updates it.
	func = bv.get_function_at(sym.address)
	if func:
		func.name = name
	else:
		name = name.split('@', 1)[0]
		old_suffixes = sym.raw_name.split('@')[1:]
		if old_suffixes:
			name += '@' + '@'.join(old_suffixes)
		new_sym = Symbol(sym.type, sym.address, name, binding=sym.binding, namespace=sym.namespace, ordinal=sym.ordinal)
		bv.undefine_auto_symbol(sym)
		bv.define_user_symbol(new_sym)

def set_symbol_type(bv, sym, type):
	""" Re-type symbol to given type """
	func = bv.get_function_at(sym.address)
	if func:
		func.set_user_type(type)
		return
	dvar = bv.get_data_var_at(sym.address)
	if dvar:
		bv.undefine_data_var(dvar.address)
		bv.define_user_data_var(dvar.address, Type.pointer(bv.arch, type))
		return

def get_symbol_module(sym):
	""" Get the module name belonging to a symbol """
	return sym.namespace.name[0]
