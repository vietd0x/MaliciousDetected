import hashlib

sha256Hash = hashlib.sha256()

f = open(".\\like_pe.txt", "r")

for filepath in f:
	with open(filepath[:-1], "rb") as openedFile:
		for byte_block in iter(lambda: openedFile.read(4096), b""):
			sha256Hash.update(byte_block)
		print("{},{}".format(filepath[:-1], sha256Hash.hexdigest()))
f.close()
