## x64dbgcutter

### About
Import and export x64dbg comments and breakpoints in Cutter

### Installation
Simply checkout or download the repository and copy x64dbgcutter.py to your cutter plugins directory ([locating the plugins directory](https://github.com/radareorg/cutter/blob/master/docs/source/plugins.rst#loading-and-overview)).

### File menu options

#### x64dbg - Import database
Import comments and breakpoints from an uncompressed x64dbg JSON database to Cutter.

#### x64dbg - Export database
Export comments and breakpoints to a JSON database that can be loaded by x64dbg.

### Notes
* Due to r2 constraints, comments and breakpoints are only imported for the main module.
* Labels and bookmarks aren't imported since they aren't relevant for Cutter.
