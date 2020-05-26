import os, glob
import json

from binaryninja.log import log_info, log_warn
from binaryninja.enums import SymbolType, SettingsScope
from binaryninja.settings import Settings
from binaryninja.plugin import PluginCommand

from .util import supports_ordinals, get_symbol_module, set_symbol_name, set_symbol_type, demangle, set_type_metadata
from .base import MatchingMethod, parse_dependency
# dependency formats
from . import msdef, idt, binja


def get_identifier(bv, sym):
	""" Find identifier for symbol according to current matching method """
	method = get_matching_method(bv)
	if method == MatchingMethod.Ordinal:
		return sym.ordinal
	elif method == MatchingMethod.Address:
		return sym.address
	elif method == MatchingMethod.Name:
		return sym.raw_name.split('@', 1)[0]

def analyze_dependency(bv, module, filename, candidates):
	""" Analyze single dependency and apply found information to given symbols """
	for dep in parse_dependency(filename):
		# Rename imports to more accurate information from dependency
		for nsym in dep.get_exports():
			ident = get_identifier(bv, nsym)
			if ident not in candidates:
				continue
			name = demangle(bv, nsym.full_name)
			type = dep.get_symbol_type(nsym)

			for ref, t in dep.get_user_types(nsym).items():
				newname = bv.define_type(ref.type_id, ref.name, t)
				newtype = bv.get_type_by_name(newname)
				set_type_metadata(bv, newtype, 'source', module)
				log_info('Imported type: {}'.format(newname))

			for osym in candidates.pop(ident):
				set_symbol_name(bv, osym, name)
				if type is not None:
					set_symbol_type(bv, osym, type)
				log_info('Renamed: {} -> {}'.format(osym.name, name))


def prioritize_file_types(k):
	""" Give a proper priority to certain file types when sorting """
	# BN databases should always go first
	if k.endswith('.bndb'):
		return 0
	# Definition files matter more than raw files
	if any(k.endswith(e) for e in ('.def', '.idt')):
		return 5
	return 10

def find_possible_dependencies(bv, names):
	matchnames = [n.lower() for n in names]
	for path in get_search_paths(bv):
		pattern = os.path.join(path, '*.*')
		for filename in sorted(glob.iglob(pattern), key=prioritize_file_types):
			if not os.path.isfile(filename):
				continue
			basename, _ = os.path.splitext(os.path.basename(filename))
			if basename.lower() not in matchnames:
				continue
			yield (basename, filename)

def analyze_self(bv):
	""" Analyze metadata for self and apply found information """
	ownname = os.path.realpath(bv.file.filename)
	basename, ext = os.path.splitext(os.path.basename(ownname))
	dbname = ownname[:-len(ext)] + '.bndb'

	# Get all own modules and symbols
	candidates = {}
	for type in (SymbolType.DataSymbol, SymbolType.FunctionSymbol):
		for sym in bv.get_symbols_of_type(type):
			ident = get_identifier(bv, sym)
			if ident is None:
				continue
			syms = candidates.setdefault(ident, [])
			syms.append(sym)

	# Find any associated dependency files and process them
	for module, filename in find_possible_dependencies(bv, [basename]):
		if os.path.realpath(filename) in (ownname, dbname):
			continue

		log_info('Processing: {}...'.format(filename))
		analyze_dependency(bv, None, filename, candidates)

def analyze_dependencies(bv):
	""" Get all imported symbols, analyze dependencies and apply found information """
	# Get all imported modules and symbols
	candidates = {}
	for type in (SymbolType.ImportAddressSymbol, SymbolType.ImportedFunctionSymbol, SymbolType.ImportedDataSymbol):
		for sym in bv.get_symbols_of_type(type):
			ident = get_identifier(bv, sym)
			if ident is None:
				continue
			module = get_symbol_module(sym).lower()
			mod_syms = candidates.setdefault(module, {})
			these_syms = mod_syms.setdefault(ident, [])
			these_syms.append(sym)

	# Find any associated dependency files and process them
	for module, filename in find_possible_dependencies(bv, candidates.keys()):
		log_info('Processing: {}...'.format(filename))
		analyze_dependency(bv, module, filename, candidates[module])

PluginCommand.register("Analyze self", "Resolve metadata for self", analyze_self)
PluginCommand.register("Analyze dependencies", "Resolve metadata for analyzed dependencies", analyze_dependencies)


settings = Settings()
settings.register_group("depanalyzer", "Dependency Analyzer Plugin")
settings.register_setting("depanalyzer.path", json.dumps({
	'title': 'Dependency Paths',
	'description': 'Paths to search for dependencies',
	'type': 'array',
	'elementType': 'string',
	'default': ['.'],
}))
settings.register_setting("depanalyzer.matching_method", json.dumps({
	'title': 'Matching Method',
	'description': 'Method used to match dependency symbols to imported symbols',
	'type': 'string',
	'enum': [m.value for m in MatchingMethod],
	'default': 'auto',
}))

def get_matching_method(bv):
	method = MatchingMethod(settings.get_string('depanalyzer.matching_method'))
	if method == MatchingMethod.Address and bv.relocatable:
		log_warn('Attempted address-based matching on relocatable file: resetting to auto')
		method = MatchingMethod.Auto
		settings.set_string('depanalyzer.matching_method', method.value, view=bv, scope=SettingsScope.SettingsContextScope)
	if method == MatchingMethod.Ordinal and not supports_ordinals(bv):
		log_warn('Attempted ordinal-based matching on non-supported file type: resetting to auto')
		method = MatchingMethod.Auto
		settings.set_string('depanalyzer.matching_method', method.value, view=bv, scope=SettingsScope.SettingsContextScope)

	if method == MatchingMethod.Auto:
		if supports_ordinals(bv):
			method = MatchingMethod.Ordinal
		else:
			method = MatchingMethod.Name

	return method

def get_search_paths(bv):
	base_path = os.path.dirname(bv.file.filename)
	return (os.path.join(base_path, path) for path in settings.get_string_list('depanalyzer.path'))
