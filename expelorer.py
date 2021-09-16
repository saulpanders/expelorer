'''
@saulpanders
expelorer.py PE export parser
Designed to automate assignment1 from Sektor7's malware dev intermediate course


input: a file path containing DLLs
output: structure containing     
	exported function names
    number of functions
    ordinals
    (check if there are any exported by ordinal only!)

'''

import argparse
import pefile
import os

#global dict of key = PE file, vals = exported functions
dll_exports = {}

# file write logic
def write_pe_exports(filename):
	with open(filename, 'w') as f:
		f.write("format:\n\t<path to file>\n\t(address, function name, ordinal #)\n\n")
		for key,val in dll_exports.items():
			f.write(key + '\n')
			f.writelines([str(x)+ '\n' for x in val])
			f.write('\n')


def main():
	parser = argparse.ArgumentParser(description='DIAL device enumeration')
	parser.add_argument('-d', '--directory',help='Directory to enumerate DLLs', default=".")
	parser.add_argument('-o', '--output',  help='write output to file')
	parser.add_argument('-v', '--verbose', action= 'store_true',  help='write output to stdout')
	args = parser.parse_args()

	directory = args.directory
	 
	# iterate over files in directory
	for filename in os.listdir(directory):
		f = os.path.join(directory, filename)

		# checking if it is a PE file (exe or dll) - exe's could be exporting something ;)
		if os.path.isfile(f) and f.endswith(("dll","exe")): 
			pe = pefile.PE(f, fast_load=True)

			#pulls imports and exports (add import logic later?)
			pe.parse_data_directories(directories = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

			#check if the file has any exports			
			try:
				# if PE has an export data directory structure, proceed
				if pe.DIRECTORY_ENTRY_EXPORT:
					export_list = []
					if args.verbose:
						print(f)
					for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
						pe_export_summary = (hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
						export_list.append(pe_export_summary)
						#if args.verbose:
							#print(pe_export_summary)
					dll_exports[f] = export_list
			except:
				pass

	if (args.output):
		write_pe_exports(args.output)



if __name__ == "__main__":
	main()