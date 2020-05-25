import os, glob
import json

from binaryninja.log import log_info, log_warn
from binaryninja.enums import SymbolType, SettingsScope
from binaryninja.settings import Settings
from binaryninja.plugin import PluginCommand

from .util import supports_ordinals, get_symbol_module, set_symbol_name, demangle
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
		return sym.raw_name

def prioritize_file_types(k):
	""" Give a proper priority to certain file types when sorting """
	# BN databases should always go first
	if k.endswith('.bndb'):
		return 0
	# Definition files matter more than raw files
	if any(k.endswith(e) for e in ('.def', '.idt')):
		return 5
	return 10

def analyze_dependency(bv, filename, candidates):
	""" Analyze single dependency and apply found information to given symbols """
	for dep in parse_dependency(filename):
		# Rename imports to more accurate information from dependency
		for nsym in dep.get_exports():
			ident = get_identifier(bv, nsym)
			if ident not in candidates:
				continue

			new_name = demangle(bv, nsym.full_name)
			osym = candidates[ident]
			set_symbol_name(bv, osym, demangle(bv, nsym.full_name))
			del candidates[ident]

			log_info('Renamed: {} -> {}...'.format(osym.name, new_name))

def analyze_all(bv):
	""" Get all imported symbols, analyze dependencies and apply found information """
	# Get all imported modules and symbols
	candidates = {}
	for type in (SymbolType.ImportedFunctionSymbol, SymbolType.ImportedDataSymbol):
		for sym in bv.get_symbols_of_type(type):
			module = get_symbol_module(sym).lower()
			syms = candidates.setdefault(module, {})
			syms[get_identifier(bv, sym)] = sym

	# Find any associated dependency files and process them
	for path in get_search_paths(bv):
		pattern = os.path.join(path, '*.*')
		for filename in sorted(glob.glob(pattern), key=prioritize_file_types):
			if not os.path.isfile(filename):
				continue

			raw_name, _ = os.path.splitext(os.path.basename(filename))
			raw_name = raw_name.lower()
			if raw_name not in candidates:
				continue

			log_info('Processing: {}...'.format(filename))
			analyze_dependency(bv, filename, candidates[raw_name])

PluginCommand.register("Analyze dependencies...", "Resolve imports for analyzed dependencies", analyze_all)


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
