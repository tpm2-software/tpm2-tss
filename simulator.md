##To Build and Test the TPM 2.0 Simulator:

1. Get the TPM 2.0 simulator, 1.24 version, from the TCG web site, trustedcomputinggroup.org, and install it (this is only possible if you or your company is a TCG member):
  1.	Go to www.trustedcomputinggroup.org 
  1.	Click on the member login link (you will have to sign up if you aren't already) 
  1.	Go to groups' TPMWG' Documents ' Filter, and search for "TPM 2.0 VS".  The latest one as of this writing is 1.24.  
  1.	This will give you the source code, so you will have to follow the instructions for building it.  
1.	In Visual Studio 2012, open TPMcmd\simulator.sln solution file and build it.
1.	Copy libeay32.dll (from OpenSSL) into TPMcmd\debug directory.  
1.	Run TPMcmd\debug\simulator.exe
1.	To test it the following python script can be used.  
NOTE: you may have to cut and paste these commands into Python interpreter one by one.  I'm not a python expert, and I couldn't get the script to just run:

        import os

        import sys

        import socket 

        from socket import socket, AF_INET, SOCK_STREAM

        platformSock = socket(AF_INET, SOCK_STREAM)

        platformSock.connect(('localhost', 2322))

        platformSock.send('\0\0\0\1')

        tpmSock = socket(AF_INET, SOCK_STREAM)

        tpmSock.connect(('localhost', 2321))

        \# Send TPM_SEND_COMMAND 

        tpmSock.send('\x00\x00\x00\x08')

        \# Send locality

        tpmSock.send('\x03')

        \# Send # of bytes

        tpmSock.send('\x00\x00\x00\x0c')

        \# Send tag

        tpmSock.send('\x80\x01')

        \# Send command size

        tpmSock.send('\x00\x00\x00\x0c')

        \# Send command code:  TPMStartup

        tpmSock.send('\x00\x00\x01\x44')

        \# Send TPM SU

        tpmSock.send('\x00\x00')

        \# Receive 4  bytes of 0's 

        reply=tpmSock.recv(18)
