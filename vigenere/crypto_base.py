#!/usr/bin/python3

import sys
from math import ceil

BLOCK_SIZE = 16
MAX_NUM_BLOCKS = 256
MAX_SIZE = 4096

encrypt_matrix = [3, 12, -5, 17]
decrypt_matrix = [encrypt_matrix[3], (encrypt_matrix[1] * -1), (encrypt_matrix[2] * -1), encrypt_matrix[0]]

determinant = (1 / ((encrypt_matrix[0] * encrypt_matrix[3]) - (encrypt_matrix[1] * encrypt_matrix[2])))


def encrypt(infile, key):

	''' Functionality to transform the plaintext message into ciphertext
        First, we break up the input string into equal-sized segments,
        Then, we encrypt the blocks using a simple XOR with a single value,
        Finally, we output our result back into ini()'''

	encrypt_subset = []
	cipherstring = ''
	MATRIX_SIZE = len(encrypt_matrix)
	KEY_SIZE = len(key)

	''' *********STRING SEGMENTATION SECTION***********'''
	''' Ensure that there are enough blocks to store the entire message '''
	for i in range(0, (ceil(len(infile) / BLOCK_SIZE))):
		''' For each iteration, transpose segment by size of block. '''
		chunk = BLOCK_SIZE * i
		lower = 0 + chunk
		upper = 16 + chunk

		''' make sure that the upper end of the cipherstring segment will get into a block.
		i.e. make sure the string isn't overflowing the set of blocks! '''
		if ((upper / BLOCK_SIZE) <= ceil(len(infile) / BLOCK_SIZE)):
			for j in range(lower,upper):
				if (j >= len(infile)):
					infile.append('-')
				''' add all text to the block '''
				encrypt_subset.append(infile[j])
		
		''' *********ENCRYPTION SECTION*********** '''
		for k in range(lower, upper):
			cipherstring += chr(ord(encrypt_subset[k]) ^ ord(key[k % KEY_SIZE]))

	return cipherstring


def decrypt(infile, key):
	''' Inverse functionality of encrypt(): 
		We transform the ciphertext back into the plaintext message
		First, we break up the input string into equal-sized segments,
		Then, we decrypt the blocks using a simple XOR with a single value,
		Finally, we output our result back into ini()'''

	decrypt_subset = []
	messagestring = ''
	MATRIX_SIZE = len(decrypt_matrix)
	KEY_SIZE = len(key)

	
	''' *********STRING SEGMENTATION SECTION***********'''

	''' Ensure that there are enough blocks to store the entire message '''
	for i in range(0, (ceil(len(infile) / BLOCK_SIZE))):
		''' For each iteration, transpose segment by size of block. '''
		chunk = BLOCK_SIZE * i
		lower = 0 + chunk
		upper = 16 + chunk

		''' make sure that the upper end of the cipherstring segment will get into a block.
			i.e. make sure the string isn't overflowing the set of blocks! '''
		if ((upper / BLOCK_SIZE) <= ceil(len(infile) / BLOCK_SIZE)):
			for j in range(lower,upper):
				if (j >= len(infile)):
					infile.append(0)
					''' add all text to the block '''
				decrypt_subset.append(infile[j])


			''' *********DECRYPTION SECTION***********'''
			''' take each of the segments, and transform them with the matrix! '''
		for k in range(lower, upper):
			messagestring += chr(ord(decrypt_subset[k]) ^ ord(key[k % KEY_SIZE])) 

	return messagestring
    

def init():
	''' Initial function for all core operations.
		Imports user and configuration data to determine 
		essential functions to be performed. '''

	''' Make sure appropriate number of arguments are inputted. '''
	if len(sys.argv) < 3:
		print("\nUsage: <program> <option: -e -d> <input file>\n")
		return 1;
	else:
		ciphertext = ''
		messagetext = ''
       	
		''' Import the input file, which is to undergo the transformation  '''
		with open(sys.argv[2], 'r') as input:
			infile = list(input.read())
		with open('./keys/main_key.key', 'r') as keyfile:
			key = list(keyfile.read())
			''' Make sure the length of the message is under 4096B'''
			if (len(infile) < MAX_SIZE):
				''' Encryption: call [encrypt()] on infile, save result, '''
				''' export into output file '''
				if (sys.argv[1] == "-e"):
					ciphertext = encrypt(infile, key)
					with open("ciphertext.txt", 'w') as output:
						output.write(ciphertext)
						return 0

				elif (sys.argv[1] == "-d"):
					''' infile is 64-bytes '''
					messagetext = decrypt(infile, key)
					with open("message.txt", 'w') as output:
						output.write(messagetext)
						return 0 
				else:
					print("\nUsage: <program> <option: -e -d> <input file>\n")
					return 1;
			else:
				print('Error: message too long!\nPlease try again with a smaller one');
				return 2;


if __name__ == "__main__":
	init()
