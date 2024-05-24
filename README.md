# expelorer.py
## Simple PE explorer

### Info:
tool to investigate information contained mostly in the headers of PE files. Takes in a directory (folder path) as input and parses the imports, exports of all PE files inside it.
Inspired by automating assignment1 from the Sektor7 intermediate malware dev course (Which I highly recommend).
- supports DLLs and EXEs
- outputs to console or file (as JSON!)

### Usage:
```expelorer.py -d "C:\\Windows\\System32" -v -a -o results.txt```

#### Arguments:
- **-d**: directory of PE files to pull exports from
- **-v**: print status to console
- **-o**: dump exports info to file 
- **-i**: parse imports
- **-e**: parse exports
- **-a**: parse everything
- **-j**: toggle to be used with -o, makes the output JSON

### Dependencies
- argparse
- pefile
to install dependencies copy the following
```
pip3 install argparse
pip3 install pefile
```


#### Ex:

![Sample Execution](sample_execution.png)

To see a sample of the file output feature, check out sample_results.txt or sample_results.json

### Source(s):
- sektor7 intermediate malware dev course
- pefile github (https://github.com/erocarrera/pefile)
