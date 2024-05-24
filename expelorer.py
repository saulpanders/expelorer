'''
@saulpanders
expelorer.py PE parser
Originally designed to automate assignment1 from Sektor7's malware dev intermediate course

tried to expand it to cover checking imports and certs, will expand probably as I see fit

input: a file path containing PE files for investigation
output: JSON data about the PE file
(possibly keep legacy write to file?)

todo FIX HEADER PARSING LOGIC: make nested dicts so the attrs show up in the string dump
'''

import argparse
import pefile
import os
import json

#global dicts hold values we collected along the way
#these are dicts, so we can just export JSON
pe_exports = {}
pe_imports = {}
pe_certs = {}
pe_header = {}

# file write logic
def write_pe_exports(filename):
	with open(filename, 'a+') as f:
		f.write("EXPORTS:\n")
		f.write("format:\n\t<path to file>\n\t(ordinal #, function name, address)\n\n")
		for key,val in pe_exports.items():
			f.write(key + '\n')
			f.writelines([str(x)+ '\n' for x in val])
			f.write('\n')

def write_pe_imports(filename):
	with open(filename, 'a+') as f:
		f.write("IMPORTS:\n")
		f.write("format:\n\t<path to file>\n\t(import DLL, function name, address)\n\n")
		for key,val in pe_imports.items():
			f.write(key + '\n')
			f.writelines([str(x)+ '\n' for x in val])
			f.write('\n')

#this is real ugly, just dump JSON
def write_pe_header(filename):
	with open(filename, 'a+') as f:
		for key,val in pe_header.items():
			f.write(key + '\n')
			for data in val.items():
				if "Sections" in str(data) and not "NumOfSections" in str(data):
					f.write(data[0]+ '(name, virt addr, virt size, sizeof raw data) '+'\n')
					for section in data[1:]:
						f.writelines([str(x)+ '\t\n' for x in section])
				else:
					f.write(str(data))
				f.write('\n')
			f.write('\n')

def write_json_data(filename):
	header_json = json.dumps(pe_header, indent=4)
	import_json = json.dumps(pe_imports, indent=4)
	export_json = json.dumps(pe_exports, indent=4)
	with open(filename+".json", "a+") as outfile:
		outfile.write(header_json)
		outfile.write(import_json)
		outfile.write(export_json)


def parse_pe_imports(pe):
	pe.parse_data_directories(directories = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
	#check if the file has any imports			
	import_list = []
	try:
		# if PE has an import data directory structure, proceed (hint: it should)
		if pe.DIRECTORY_ENTRY_IMPORT:
			for ent in pe.DIRECTORY_ENTRY_IMPORT:
				for imp in ent.imports:
					pe_import_summary = (ent.dll.decode(), imp.name.decode(), hex(imp.address))
					import_list.append(pe_import_summary)

	except Exception:
		pass
	return import_list



def parse_pe_exports(pe):
	pe.parse_data_directories(directories = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
	export_list = []
	#check if the file has any exports			
	try:
		# if PE has an export data directory structure, proceed
		if pe.DIRECTORY_ENTRY_EXPORT:
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				pe_export_summary = (exp.ordinal, exp.name.decode(), hex(pe.OPTIONAL_HEADER.ImageBase + exp.address))
				export_list.append(pe_export_summary)
	except Exception:
		pass

	return export_list


def parse_pe_header(pe):
	current_header = {}
	current_header['AddressOfEntryPoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	current_header['ImageBase'] = hex(pe.OPTIONAL_HEADER.ImageBase)
	current_header['NumOfSections'] = pe.FILE_HEADER.NumberOfSections
	sections = [] 
	for section in pe.sections:
  		sections.append((section.Name.decode(), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData))

	current_header['Sections'] = sections
	return current_header

def main():
	parser = argparse.ArgumentParser(description='portable Executable (PE) Investigation Tool')
	parser.add_argument('-d', '--directory',help='directory to enumerate PEs', default=".")
	parser.add_argument('-o', '--output',  help='write output to file')
	parser.add_argument('-v', '--verbose', action= 'store_true',  help='write output to stdout')
	parser.add_argument('-j', '--json', action='store_true', help='write output as JSON (default false)')
	parser.add_argument('-i', '--imports', action='store_true', help='parse imports')
	parser.add_argument('-e', '--exports', action='store_true', help='parse exports')
	parser.add_argument('-a', '--all', action= 'store_true', help='parse everything')
	args = parser.parse_args()

	directory = args.directory
	 
	# iterate over files in directory
	for filename in os.listdir(directory):
		f = os.path.join(directory, filename)

		# checking if it is a PE file (exe, dll, or sys) - exe's could be exporting something ;)
		if os.path.isfile(f) and f.endswith(("dll","exe", "sys")): 
			pe = pefile.PE(f)
			# may make header info optional later, idk
			pe_header[f] = parse_pe_header(pe)
			if args.imports or args.all:
				pe_imports[f]  = parse_pe_imports(pe)
			if args.exports or args.all:
				pe_exports[f] = parse_pe_exports(pe)

	if(args.verbose):
		print("[+] HEADER")
		print(pe_header)
		print("[+] EXPORTS:")
		print(pe_exports)
		print("[+] IMPORTS:")
		print(pe_imports)
		
	if (args.output):
		if(args.json):
			write_json_data(args.output)
		else:
			write_pe_header(args.output)
			write_pe_imports(args.output)
			write_pe_exports(args.output)



if __name__ == "__main__":
	main()