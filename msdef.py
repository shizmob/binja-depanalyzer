import os

from binaryninja.types import Symbol
from binaryninja.enums import SymbolType
from .base import Dependency, register_dependency_type


def quoted_split(haystack, needle=None, maxsplit=-1):
	""" Split `haystack` on `needle`, except inside quote signs """
	start = 0
	search = 0
	parts = []

	while maxsplit == -1 or len(parts) < maxsplit:
		if needle:
			p = haystack.find(needle, search)
			if p < 0:
				break
			search = p + len(needle)
		else:
			p = search
			while p < len(haystack) and not haystack[p].isspace():
				p += 1
			if p == len(haystack):
				break
			search = p
			while search < len(haystack) and haystack[search].isspace():
				search += 1
			if p == search:
				break

		if haystack[start:p].count('"') % 2 != 0:
			continue

		parts.append(haystack[start:p])
		start = search

	parts.append(haystack[start:])
	return parts


@register_dependency_type
class DEFDependency(Dependency):
	SECTION_NAMES = {'EXPORTS', 'LIBRARY', 'HEAPSIZE', 'NAME', 'SECTIONS', 'STACKSIZE', 'STUB', 'VERSION'}

	@classmethod
	def can_parse(cls, file):
		return file.endswith('.def')

	def __init__(self, file):
		self.sections = []
		self._parse(file)

	def _parse(self, file):
		with open(file, 'r') as f:
			for line in f.readlines():
				# Line format: NAME [ARG1 ARG2 [...] ARGn] [; comment]
				line = quoted_split(line, ';')[0]
				if not line:
					continue
				parts = quoted_split(line.strip())
				name = parts[0]
				parts = parts[1:]

				# New section!
				if name in self.SECTION_NAMES:
					# Format: [ARG1,ARG2=VAL,[...],ARGn]
					args = {}
					for part in parts:
						for a in quoted_split(part, ','):
							if '=' in a:
								k, v = quoted_split(part, '=', maxsplit=1)
								args[k] = v
							else:
								args[a] = True
					self.sections.append((name, args, {}))
				# Entry in section!
				elif self.sections:
					# Format: NAME [PART1 PART2 [...] PARTn]
					parts = quoted_split(line.strip())
					self.sections[-1][2][parts[0]] = parts[1:]
				else:
					raise ValueError('entry found but no sections defined yet')

	def is_valid(self):
		# If we managed to parse it, it's valid to me
		return True
		
	def get_exports(self):
		symbols = []

		for (name, args, entries) in self.sections:
			if name != 'EXPORTS':
				continue
			for (name, args) in entries.items():
				# Format: NAME=INTERNAL_NAME @ordinal [KEYWORDS...]
				name = quoted_split(name, '=')[0]
				if not args[0].startswith('@'):
					continue

				if args[0][1:]:
					o = args[0][1:]
					tag_idx = 1
				elif len(args) > 1:
					o = args[1]
					tag_idx = 2
				else:
					continue

				if not o.isdigit():
					continue
				if 'DATA' in args[tag_idx:]:
					symtype = SymbolType.DataSymbol
				else:
					symtype = SymbolType.FunctionSymbol
				symbols.append(Symbol(symtype, 0, name, ordinal=int(o)))

		return symbols
