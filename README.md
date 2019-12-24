## x64dbgcutter

### About
Import and export x64dbg comments, labels, bookmarks and breakpoints in Cutter

### Installation
Simply checkout or download the repository and copy x64dbgcutter.py to your cutter plugins directory ([locating the plugins directory](https://github.com/radareorg/cutter/blob/master/docs/source/plugins.rst#loading-and-overview)).

### File menu options

#### x64dbg - Import database
Import comments, labels(as flags), bookmarks and breakpoints from an uncompressed x64dbg JSON database to Cutter.
Labels are imported to the x64dbgcutter.labels flagspace (`fs x64dbgcutter.labels`) and bookmarks are added with a bookmark_<addr> prefix to the x64dbgcutter.bookmarks flagspace. Use `fs-x64dbgcutter.<labels/bookmarks>` to remove the imported flags.

#### x64dbg - Export database
Export comments, flags(as labels) and breakpoints to a JSON database that can be loaded by x64dbg.

### Notes
* Due to r2 constraints, comments and breakpoints are only imported for the main module.