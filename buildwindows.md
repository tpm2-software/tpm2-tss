## To Build and Test Windows Version of TSS 2.0: 
1.	Create an environment variable, TSSTOOLS_PATH that points to your Visual Studio C nmake.exe, cl.exe, link.exe, and lib.exe utilities.  NOTE: the path should start and end with double quotes so that any spaces in the path are interpreted properly.
1.	In Visual Studio 2010, open the tss.sln solution file.
1.	Build it.  This will build the System API library (tpm.lib), the TAB/RM daemon (resourcemgr.exe) and the test application (tpmclient.exe).  tpm.lib is linked into both the TAB/RM daemon and the test application.  The test\tpmclient\debug or test\tpmclient\release directories are where the resourcemgr.exe and tpmclient.exe files are located after building, depending on the type of build.
1.	Start the TPM 2.0 simulator (this assumes you have a working version of this installed).
1.	Start the TAB/RM daemon, resourcemgr\<debug | release>\resourcemgr.exe.  There are command line parameters for selecting the TPM host and ports and the ports that will be used by applications to communicate with the daemon.  The easiest way is to run everything on the same machine, in which case no command line parameters are needed.  For help with the command line parameters, type "resourcemgr -?".  For comparing to known good output, redirect the resourcemgr output to a file.

