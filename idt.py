from binaryninja.types import Symbol
from binaryninja.enums import SymbolType
from .base import Dependency, register_dependency_type

@register_dependency_type
class IDTDependency(Dependency):
	@classmethod
	def can_parse(self, file):
		return file.lower().endswith('.idt')

	def __init__(self, file):
		self.declaration = None
		self.alignment = None
		self.entries = []
		self._parse(file)

	def _parse(self, file):
		with open(file, 'r') as f:
			while True:
				# Read possibly-multiline entry of format:
				# <command> KEY=VAL KEY2=VAL2 [; comment ]
				entry = ''
				while True:
					line = f.readline()
					if not line:
						return
					entry += line.split(';')[0].strip()
					if line[-1] != '\\':
						break
				if not entry:
					continue

				# Split line into ordinal and arguments
				parts = line.split()
				command = parts.pop(0)

				# We don't care about any non-ordinal commands or unnamed entries
				if command.isdigit():
					args = {k.lower(): v for k, v in (p.split('=', 1) for p in parts)}
					self.entries.append((int(command), args))
				elif command.lower() == 'alignment':
					self.alignment = int(parts[0])
				elif command.lower() == 'declaration':
					self.declaration = int(parts[0])
				else:
					raise ValueError('unknown command: {}'.format(command))

	def is_valid(self):
		# If we managed to parse it, it's valid to me
		return True

	def get_exports(self):
		return [Symbol(SymbolType.FunctionSymbol, 0, v['name'], ordinal=k) for k, v in self.entries if 'name' in v]
