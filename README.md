# pdb_get_symbol_name_from_offset

This program reads a PDB file and a ReturnOfModding log file to match RVA offsets with symbols.

To get the matching PDB file:
1. Open the LogOutput.log file.
2. Retrieve the Git hash at the top of the log.
3. Download the binary.zip from the corresponding GitHub Action output associated with the Git hash.

Example usage: 
```bash
./pdb_get_symbol_name_from_offset.exe -pdb "d3d12.pdb" -log "LogOutput.log" -dll d3d12.dll
```
