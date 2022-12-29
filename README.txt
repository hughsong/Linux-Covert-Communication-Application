#----------------------------------------------------------------------------------------------
# PROGRAM:    	  COMP 8505 Final Project
# FUNCTIONS:      A complete covert application that will allow a user to access a port (that 
#		  is otherwise closed) on a firewall and communicate with a “disguised” 
#		  backdoor application. The backdoor application will accept commands and 
#		  execute them; the results of the command execution will be sent back to the 
#		  remote client application. The application will watch for the creating of a 
#		  specific file in a specific directory and when that occurs, it will 
#		  automatically send the file to the attacker machine on the other side. In 
#		  addition to sending back requested files, this component will also install 
#		  a keylogger in the compromised system and send the keystrokes file to the 
#		  client.           
#    
# DATE:           December 6th, 2021
# DESIGNER:       Lingzhu Yu  A00904631
#                 Yuheng Song A00971421
#			
# PROGRAMMER:     Lingzhu Yu  A00904631
#                 Yuheng Song A00971421
#----------------------------------------------------------------------------------------------

1. Put the source code on the target and client machines and edit the configuration file. 
	
    1.1 Change the target IP and client IP before running the program.
 
    1.2 The sniffer filter and the raw socket protocol must be consistent.

 
2. Run the makefile

    2.1 On client machine:

         make client

    2.2 On target machine:

         make target

    2.3 To delete the executable file:

         make clean

3. Usage

    3.1 Client:
	
	./client.o -mode [cmd/file/watch/keylogger/close]

	-mode cmd: to send a command to target machine, then wait for the command 
		   execution result that return back from target machine

	-mode file: to request a specific file from the target machine. 

		    If only enter the file name, the application will be looking 
                    for the file under the same directory. 

		    If enter the file name with its absolute path, the application 
		    will be looking for the file from that path.

	-mode keylogger: remotely execute keylogger application. 

		    The keylogger application will be executed in background on the 
		    target machine. 

	            The keystrokes will be recorded in a file named "keyoutput.txt".

	-mode watch: watch for for the creation of a specific file in a specific directory. 

	-mode close: Terminate the target program.

		    Once the backdoor application is running on the target machine, it 
		    will keep sniffing packets until the user enter “./client.o -mode close” 
		    on the client machine.

    3.2 Target:

	./target.o


