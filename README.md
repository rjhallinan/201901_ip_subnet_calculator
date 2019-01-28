# NPL_January_Challenge
IP Subnet Calculator

January 2019 NPL Challenge

This is my script developed for the January 2019 NPL challenge to create an IP subnet calculator. The bonus tasks are combined in the same script.
Overall the challenge requirements are:
  Input - prompt the user for an IP address and subnet mask   (this script can accept IP and subnet mask as two arguments for easy  testing and will prompt the user for the information if not provided)
  
  Output -  1) The IP address provided by the user
            2) The subnet mask provided by the user
            3) The wildcard mask
            4) The number of host bits
            5) The address class (A, B, etc)
            6) The network address
            7) The broadcast address
            8) The first host address
            9) The last host address
            10) The number of host addresses available
            
Bonus challenges:
  Output - Display relevant results in binary and hexadecimal (1, 2, 3, 6, 7, 8, and 9 from above)
  
  Build a DNS bind reverse map zone file assigning a value to each available host address. 

I know modules for manipulating IP addresses exist but with the bonus challenges of displaying in Hex and binary I thought it would be a good exercise to work through all of the binary math. 

Validation of the supplies input includes:
  IP address to analyze - is it 4 digits separated by '.' and all integerers between 0 and 255
  Subnet mask - is it 4 digits separated by '.' and each in a set of allowed values [0, 128, 192, 224, 240, 248, 252, 255]
  Network Address - after calculating from the IP address and Subnet mask - is it in a reserved IANA IPv4 space?

Creating functions for switching between a 32 bit binary string and dotted notation was very helpful throughout. 