#CONIKS Server

Copyright (C) 2015 Marcela S. Melara

http://www.coniks.org

##Introduction
CONIKS is a key management service that provides consistency and privacy for end-user public keys. It protects users against malicious or coerced key servers which may want to impersonate these users to compromise their secure communications: CONIKS will quickly detect any spurious keys, or any versions of the key directory that are inconsistent between two or more users. Nonetheless, CONIKS users do not need to worry about or even see these protocols, or the encryption keys, as CONIKS seamlessly integrates into any existing secure messaging application.

This is a basic implementation of a CONIKS server that currently only supports new key registrations and key lookups. It is designed to communicate with the CONIKS test client.

##Using the Server

###Preparing SSL
CONIKS servers communicate via SSL/TLS connections with any client or other key servers.
Unless you already have a valid certificate for your server, you will need to create self-signed certificates:
```
keytool -genkeypair -alias <alias> -keyalg RSA -validity 365 -keystore <keystore>
keytool -export -alias <alias> -keystore <keystore> -rfc -file <alias>.cer
keytool -import -alias <alias> -file <alias>.cer -keystore <truststore>
```
You will be asked to enter a password for each the keystore and the truststore. Make sure you remember these passwords. Notice that the self-signed certificates are set to expire within 365 days here.

###Server Configuration
- *ServerConfig.java*: You will need to fill in the following fields in the ```ServerConfig()``` constructor. If you would like, you may also create a config file that contains the information from the following fields in this exact order.
```
<port number>
<alias> (same alias used for your certificates)
<full server hostname>
<path to logs>/msg-handler-%g
<path to logs>/epoch-timer-%g
<path to logs>/server-%g
<epoch length in milliseconds>
<path to keystore>/<keystore>
<keystore password>
<path to truststore>/<truststore>
<truststore password>
```
If you're using a config file, make sure it is only readable by the users intended to use the CONIKS server.
- *ConiksServer.java*: Set the number of dummy users in the tree at startup time in the **SIZE** field.
Set the path to the configuration file in the **CONFIG_FILE** field if used, and use the appropriate ```ServerConfig``` constructor.
- *ServerOps.java*: Set the path to the debugging log in the **debugLog** field.
- *coniks_server.sh*: Set the **LOG_PATH** to be the the same <path to logs> used in the server configuration.

###Building
We understand that people may not necessarily want to build and run the server on the same machine. 
- Compiling:
In the *Makefile*, set the directory where you want the compiler to place the class files in **CLASS_DEST**. Then run:
```
make
```
- Pushing the compiled code to a remote machine:
In the *Makefile*, set the **PUBUSER**, **PUBHOST**, and **PUBPATH** variables to the appropriate values. Then run:
```
make pubbin
```
This step assumes the **PUBUSER** has ssh access to the remote machine.
- Pushing the run script to a remote machine:
```
make pubscr
```
This step also assumes the **PUBUSER** has ssh access to the remote machine **PUBHOST**, and may require you to change the permissions of the script on the remote host.

###Running
We provide a run script for the CONIKS server *coniks_server.sh*, which allows you to run the server as a background process, as well as clean up any logs written by the server.

The run script supports three commands: 
- ```start```: start the CONIKS server in the background, if it isn't running already.
- ```stop```: stop the CONIKS server.
- ```clean```: remove all logs written by the server, and stop the server if it's running.
For example, to start the server, use
```./coniks_server.sh start```
Analogously to stop the server, and remove the logs.

##Documentation
[Read the server's Java API (javadoc)](https://coniks-sys.github.io/coniks-ref-implementation)
