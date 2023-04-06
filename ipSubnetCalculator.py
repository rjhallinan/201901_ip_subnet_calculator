#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" This python script will calculate basic IP subnet information from user submitted IP address and subnet mask.
		Site - Integer describing Site
		Mgmt_IP - String describing IP address

	Arguments:
		* NOTE: For the following arguments - both must be present for either to be effective; if not both then user will be prompted for each
		1) Optional - IP address
		2) Optional - subnet mask
		
"""

# import modules HERE
import sys											# this allows us to analyze the arguments	
from contextlib import contextmanager

# additional information about the script
__filename__ = "ipSubnetCalculator.py"
__author__ = "Robert Hallinan"
__email__ = "rhallinan@netcraftsmen.com"

#
# version history
#


"""
	20190125 - Initially creating the script
	20190207 - Using in production scripts so removed the bonus challenges and added output on prefix length
"""

@contextmanager
def open_file(path, mode):
	the_file = open(path, mode)
	yield the_file
	the_file.close()

def getIPInfo():

	# let's get the IP address from the user:
	ipConf = ""
	ipAddress = input("What IP address would you like to analyze (A.B.C.D)?: ")
	ipConf = input("The IP address provided is: " + ipAddress + ". Is this the IP address to analyze? (Y/N): ")
	ipConf = ipConf.upper()
	while ipConf != "Y":
		ipConf = ""
		loginName = input("What IP address would you like to analyze (A.B.C.D)?: ")
		ipConf = input("The IP address provided is: " + ipAddress + ". Is this the IP address to analyze? (Y/N): ")
		ipConf = ipConf.upper()
	
	# Need to validate the IP address before going any further
	if not validateIPAddress(ipAddress):
		print("This is an invalid IP address. Exiting now...")
		sys.exit()

	print("The following IP address will be analyzed: " + ipAddress)
			
	# let's get the subnet mask from the user
	submaskConf = ""
	subMask = input("What Subnet Mask would you like to analyze (A.B.C.D)?: ")
	submaskConf = input("The Subnet Mask provided is: " + subMask + ". Is this the Subnet Mask to analyze? (Y/N): ")
	submaskConf = submaskConf.upper()
	while submaskConf != "Y":
		submaskConf = ""
		subMask = input("What Subnet Mask would you like to analyze (A.B.C.D)?: ")
		submaskConf = input("The Subnet Mask provided is: " + subMask + ". Is this the Subnet Mask to analyze? (Y/N): ")
		submaskConf = submaskConf.upper()
	
	# Need to validate the subnet mask before going any further
	if not validateSubnetMask(subMask):
		print("This is an invalid Subnet Mask. Exiting now...")
		sys.exit()	
	
	return ipAddress,subMask
	
def validateIPAddress(ipAdd):
	""" This function will validate the IP address:
		Needs to be 4 numbers separated by '.'
		Each number needs to be between 0 and 255
		TODO: What IP addresses should be disallowed right from the beginning? - anything not in class A, B, or C; 
			maybe if class D then output that this is multicast and not part of calculator
			if class E then output that this is reserver
			if local loopback then output that this doesn't apply
	"""
	
	# initialize the return variable
	validAddress = True
	
	# first validate that there are four numbers separated by .
	if len(ipAdd.split('.')) != 4:
		print("This IP address is not 4 digits separated by a '.'. Exiting now...")
		sys.exit()
		
	# still going means that there are 4 digits - now validate that they are all between 0 and 255
	for octet in ipAdd.split('.'):
		try:
			intOct = int(octet)
		except:
			print("The octets are not all integers.")
			return False
			
		if intOct < 0 or intOct > 255:
			print ("The digits in this IP address are not all between 0 and 255.")
			return False
	
	return validAddress
		
def validateSubnetMask(subMask):
	""" This function will validate the subnet mask:
		Needs to be 4 numbers separated by '.'
		Each number needs to be between 0 and 255
		Needs to be a specific set of numbers
		1's need to be contiguous and then a set of 0s - thus as long as 01 never appears in the string it's good
	"""
	
	# initialize the return variable
	validAddress = True
	
	# first validate that there are four numbers separated by .
	if len(subMask.split('.')) != 4:
		print("This Subnet Mask is not 4 digits separated by a '.'. Exiting now...")
		sys.exit()
		
	# still going means that there are 4 digits - now validate that they are all between 0 and 255
	for octet in subMask.split('.'):
		try:
			intOct = int(octet)
		except:
			print("The octets are not all integers.")
			return False
			
		if intOct not in [0, 128, 192, 224, 240, 248, 252, 254, 255]:
			print ("The digits in this subnet mask are not valid.")
			return False
	
	# make sure that there is only a string of 1s followed by a string of 0s
	if '01' in dottedToBinary(subMask):
		print("This is not a contiguous subnet mask.")
		return False
	
	return validAddress

def calcWildcardMask(binaryString):
	""" This will calculate the wildcard mask from the subnet mask.
	"""
	
	# swap the ones and zeros in the mask - first swap 0 to 2, then 1 to 0, then the 2 to 1 and convert to mask
	return binaryToDotted(binaryString.replace('0','2').replace('1','0').replace('2','1'))

def countHostBits(binaryString):
	""" This will calculate the number of host bits in the mask
	"""
	
	# count the number of 0s in the subnet string
	return binaryString.count('0')


def getAddressClass(binaryString):
	""" This will calculate the address class of the IP address based on bits of binary string
			A: 0...
			B: 10..
			C: 110.
			D: 1110
			E: 1111
	"""
	
	# initialize variable
	addressClass=""
	
	# troubleshooting
	# print(binaryString)
	
	# determine the address class
	if binaryString[0] == "0":
		addressClass =  "A"
	elif binaryString[0:2] == "10":
		addressClass =  "B"
	elif binaryString[0:3] == "110":
		addressClass =  "C"
	elif binaryString[0:4] == "1110":
		addressClass =  "D"
	elif binaryString[0:4] == "1111":
		addressClass = "E"
	
	return addressClass

	
def calculateNetworkAddress(ipBinary, subBinary):
	""" This will calculate the network address using the binary of the IP address and subnet mask
	"""
	return binaryToDotted(''.join([ str(int(x[0]) and int(x[1])) for x in zip(ipBinary,subBinary)]))

def validateNetworkAddress(netAddress):
	""" This will check to see if the network address is a or fits within a reserved group from IANA not for use.
	"""
	
	# from the link here: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	 # 0.0.0.0/8 - This host on this network
	 # 100.64.0.0/10 - Shared address space
	 # 127.0.0.0/8 - Loopback
	 # 169.254.0.0/16 - Link Local
	 # 192.0.0.0/24 - IETF protocol assignments
	 # 192.0.2.0/24 - Documentation (test-net-1)
	 # 192.31.196.0/24 - AS112-v4
	 # 192.52.193.0/24 - AMT
	 # 192.175.48.0/24 - Direct delegation AS112 service
	 # 192.18.0.0/15 - Benchmarking
	 # 192.51.100.0/24 - Documentation (test-net-2)
	# 203.0.113.0/24 - Documentation (test-net-3)
	
	# the subnet mask lengths to consider here are 8 10 15 16 24
	# goal is to take the network address calculated, bit-and it with the subnet mask to consider, and make sure that the resultant network address is
	# not one of the reserved ones
	
	# make a dictionary of the reserved spaces
	reservedSpaces = {8:['0.0.0.0','127.0.0.0'], \
					  10:['100.64.0.0'], \
					  15:['192.18.0.0'], \
					  16:['169.254.0.0'], \
					  24:['192.0.0.0', '192.0.2.0', '192.31.196.0', '192.52.193.0', '192.175.48.0', '192.51.100.0', '203.0.113.0'] }
					  
	for smLength in reservedSpaces.keys():
		
		# first calculate the network address anded with the subnet mask
		if calculateNetworkAddress(dottedToBinary(netAddress),'1'*smLength+'0'*(32 - smLength)) in reservedSpaces[smLength]:
			print("This fits within one of the IANA reserved IPv4 Spaces: " + calculateNetworkAddress(dottedToBinary(netAddress),'1'*smLength+'0'*(32 - smLength)) + \
			"\nNo further processing required.\nSee https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml for further details.")
			sys.exit()
	

def calculateBroadcastAddress(binIPAddress, binSubnetMask):
	""" This will calculate the broadcast address of the network
	"""
	return binaryToDotted(binIPAddress[0:32-countHostBits(binSubnetMask)] + "1"*countHostBits(binSubnetMask))

def calculateFirstHost(networkAddress):
	""" this will return the first host address of the subnet
	"""
	return binaryToDotted(dottedToBinary(networkAddress)[0:31]+"1")

def calculateLastHost(broadcastAddress):
	""" this will return the last host address of the subnet
	"""
	return binaryToDotted(dottedToBinary(broadcastAddress)[0:31]+"0")
		
def binaryToDotted(binaryString):
	""" This function takes the 32 bit long string and returns the IP in dotted notation)
	"""
	return '.'.join([ str(int(binaryString[0:8],2)), str(int(binaryString[8:16],2)), str(int(binaryString[16:24],2)), str(int(binaryString[24:32],2))])
	
def dottedToBinary(dottedString):
	""" This function takes the dotted IP address and returns a 32 bit binary string
	"""
	
	binaryString=""
	for octet in dottedString.split('.'):
		
		# convert the int to a binary string - string manipulation to remove the 0b at beginning
		binOctet=bin(int(octet))[2:]
		# now to pad with 0's if length is less that 8
		binOctet = "0" * (8 - len(binOctet)) + binOctet
		
		# add to the binary string mask
		binaryString += binOctet	
	
	return binaryString

def dottedToBinaryDisplay(dottedString):
	""" This function takes the dotted IP address and returns a 32 biit binary string in 4 octets
	"""
	
	return dottedToBinary(dottedString)[0:8] + "." + dottedToBinary(dottedString)[8:16] + "." \
			+ dottedToBinary(dottedString)[16:24] + "." + dottedToBinary(dottedString)[24:32]

def dottedToHexDisplay(dottedString):
	""" Return the dotted IP address in hex
	"""
	hexString=[]
	for octet in dottedString.split('.'):
		
		# convert the int to a binary string - string manipulation to remove the 0b at beginning
		hexOctet=hex(int(octet))[2:]
		# now to pad with 0's if length is less that 8
		hexOctet = "0" * (2 - len(hexOctet)) + hexOctet
		
		# add to the binary string mask
		hexString.append(hexOctet)

	return '.'.join(hexString)
	

def main(system_arguments):
	
	#
	#		IP ADDRESS and SUBNET MASK
	#
	# determine if the IP address and subnet mask were provided
	
	try:
		ipAddress = system_arguments[1]
		subnetMask = system_arguments[2]
		if not validateIPAddress(ipAddress):
			print("This is an invalid IP address. Requesting input again...")
			print()
			print()
			sys.exit()
		if not validateSubnetMask(subnetMask):
			print("This is an invalid subnet mask. Requesting input again...")
			print()
			print()
			sys.exit()
	except:	
		ipAddress, subnetMask = getIPInfo()
		
	# Get the binary strings
	binaryStringIPAdd = dottedToBinary(ipAddress)
	binaryStringSubMask = dottedToBinary(subnetMask)
	
	# get the address class
	addressClass = getAddressClass(binaryStringIPAdd)
	
	# get the wildcard mask
	wildcardMask = calcWildcardMask(binaryStringSubMask)
	
	# get the number of host bits
	hostBits = countHostBits(binaryStringSubMask)
	
	# get the network address
	netAddress = calculateNetworkAddress(binaryStringIPAdd, binaryStringSubMask)
	
	# get the broadcast address
	bcastAddress = calculateBroadcastAddress(binaryStringIPAdd, binaryStringSubMask)
	
	# get the first host address
	firstHost = calculateFirstHost(netAddress)
	
	# get the last host address
	lastHost = calculateLastHost(bcastAddress)		
	
	# calculate the number of hosts
	numHosts = 2**hostBits - 2
	
	# Start the output	
	print("IP: " + ipAddress)
	# make decisions if IP address is class D or class E	
	if addressClass == "D":
		print("This is a multicast address in the class D space. No further analysis required.")
		sys.exit()
	elif addressClass == "E":
		print("This is an address in reserved space. No further analysis required.")
		sys.exit()
	
	# continue the output
	print("Subnet Mask: " + subnetMask)
	validateNetworkAddress(netAddress)
	
	print("Wildcard Mask: " + wildcardMask)
	print("The number of host bits: " + str(hostBits))
	print("The number of network bits: " + str(32-hostBits))
	print("The address class is: " + addressClass)
	print("The network address is: " + netAddress)
	print("The broadcast address is: " + bcastAddress)
	print("The first host address is: " + firstHost)
	print("The last host address is: " + lastHost)
	print("The number of host addresses available is: " + str(numHosts)	)
	print("The binary string of the IP address is: " + binaryStringIPAdd)
	print()
	print()

if __name__ == "__main__":

	# this gets run if the script is called by itself from the command line
	main(sys.argv)