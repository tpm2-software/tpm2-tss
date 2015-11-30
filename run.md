##Run Instructions:

* Start the simulator: >..\TPMcmd\debug\simulator.exe
        
* Start the resource manager

  Linux:  >..\resourcemgr\resourcemgr

  Windows: >..\resourcemgr\debug\resourcemgr

* Run tpmclient

  Linux:  >..\test\tpmclient\tpmclient

  Windows: >..\test\tpmclient\debug\tpmclient

  To compare the test results, redirect the resource manager and tpmclient output to files and compare to test\tpmclient\good\rm.out.good and test\tpmclient\good\out.good, respectively.  The same number of commands should have run and pass/fail status should be the same for all the tests.  There will be miscompares due to randomness in some forms of output data from the TPM, but these are not errors.
 
  The above instructions assume that the simulator, resource manager, and tpmclient are all run on the same machine.  To run on separate machines, resource manager and tpmclient command line options will be required to set up the socket interfaces.

  Also, setting 'dbg -3' option for tpmclient will maximize the debug messages.