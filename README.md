# Dependency Analyzer

Author: **Shiz**

_Analyze dependencies and resolve obfuscated imports_

## Description:

Dependency Analyzer is a Binary Ninja plugin for analyzing module dependencies in a more in-depth fashion and recovering important information such as import names from metadata files.

Supported formats:

* [Microsoft Module Definition (.def)](https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files?view=vs-2019) files
* IDA's IDT files
* Anything loadable by Binary Ninja (including databases with renamed functions)

Current analyses:

* Resolve imported symbol names
  - Import-by-ordinal
  - Import-by-address (e.g. embedded systems)
  - From renamed functions in a Binary Ninja database (e.g. manually analyzed obfuscated symbol names)

It will try to find files in `depanalyzer.path` with the same basename of any of the dependencies, and analyze them if they match anything loadable by the plugin.

Symbol matching can done in three ways:

* By name
* By address (non-relocatable binaries only)
* By ordinal (PE binaries only)

The current method is settable through `depanalyzer.matching_method`, globally and per-context. By default, and upon encountering a method that is inapplicable to the current binary, it will try to determine the best method automatically.

## Installation Instructions

Drop it in your plugin folder and go!

## Minimum Version

This plugin was tested with the following versions of Binary Ninja:

 * 2170

## Required Dependencies

None.

## License

This plugin is released under an MIT license.

## Metadata Version

2
