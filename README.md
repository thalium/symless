# Symless

Automatic structures identification & creation plugin for IDA. Symless facilitates the analyst's work by doing a pre-analysis of the IDB, i.e. identifying structures, c++ classes, vtables and propagating that information.

### Features
* Automatic creation of identified structures (c++ class, vtable and others)
* Xrefs linking structure's fields to where they are used
* Functions typing using gathered information

## Usage
### Entry points definition
You can define memory allocators that are used to reserve space for a structure. These are used to find structure creations in a binary.

Define those entry points in [imports.csv](symless/config/imports.csv). Syntax is discussed there.

### Command line
```
    $ python3 symless.py [-c config.csv] <target(s)>
```

* ```config.csv``` - configuration to be used (defaults to [imports.csv](symless/config/imports.csv))
* ```target(s)``` - one or more binaries / IDA bases

Symless will create a new IDA base when given an executable as an argument. Otherwise keep in mind it may overwrite user-modifications on existing bases.

If it is unable to find your IDA installation, set up the `IDA_DIR` env to point to it (point to the folder containing the `idat` executable).

Once done, the IDA base will be populated with information about identified structures.

## Support
Both stripped and non-stripped binaries are supported. Symbols are only used to name the created structures.

**x64** and **i386** binairies using the following calling conventions are supported:
* Windows x64 (```__fastcall```)
* Windows i386 (```__stdcall``` & ```__thiscall```)
* System V x64 (```__fastcall```)
* System V i386 (```__stdcall```)

**IDA Pro 7.6** or newer &  **python 3**

## Approach
Structures are identified from two entry points:

* By locating memory allocations
* By locating c++ constructors

Memory allocators are defined by the user in the configuration file. C++ constructors are located from their vtable(s), found by scanning the executable.

# Interactive plugin
Interactive version running as an IDA plugin.

The user defines a register containing a pointer on a structure, Symless propagates the information and automatically builds the structure.

## Installation
Copy the [symless](symless/) directory and [symless_plugin.py](plugin/symless_plugin.py) into IDA plugins folder.

## Usage
While in IDA disassembly view:
- Right click on a register containing a structure pointer
- Select **Propagate structure**
- Select which structure & shift to apply

Symless will then propagate the structure, build it and type untyped functions / operands with the harvested information. This action can be undone with **Ctrl-Z**.
