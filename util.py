import os
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
	# We can't rename function symbols directly yet,
	# so for now only rename any associated function stub
	func = bv.get_function_at(sym.address)
	if not func:
		return
	func.name = name

def get_symbol_module(sym):
	""" Get the module name belonging to a symbol """
	return sym.namespace.name[0]
