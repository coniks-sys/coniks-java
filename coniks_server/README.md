#CONIKS Server

Copyright (C) 2015-16 Princeton University.

https://coniks.cs.princeton.edu

##Introduction
This is a basic implementation of a server for the CONIKS key management system. It currently supports new key registrations, key lookups, and can generate consistency proofs and signed directory summaries. It is designed to communicate with the [CONIKS test client](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_test_client).

##Building the Server
- Prerequisites:
You'll need Java JDK7 or greater and need to ensure that the Google protobufs have been compiled with the most recent version of protoc. If you've already compiled the protobufs for the test client, you don't need
to repeat this step for the server.
You'll also need to install the automake and build-essential packages.
- Compiling:
The default classpath is *bin*. If you'd like to change this, you'll need to change the ```CLASS_DEST``` 
variable in the Makefile. To build, run:
```
make 
```

##Using the Server

The CONIKS server has two operating modes: Test Mode and Full Operation. 
Running the server in test mode allows you to still test all CONIKS protocols and operations,
but requires less setup as you can simply use the default configuration in the included *config* file.
**Note:** You must be running the test client in the same operating mode.

### Setup
- Generate an RSA signing key pair for the server:
Default alias: *localhost*. Default keystore: *keystore*.
Run the following command, using the default settings if setting up test mode:
```
keytool -genkeypair -alias <alias> -keyalg RSA -validity 365 -keystore <keystore>
```
Follow the prompts and enter suitable information. Make sure to enter legitimate information if running
in full operation mode. Notice that the key pair is set to expire within 365 days here, but you may 
change this setting when running this command.
- Full operation mode only: Generate self-signed certificates for SSL/TLS communication, 
if you don't already have certs for your server:
Make sure the alias and the keystore used in this step match the values used when generating the 
signing key pair in the previous step.
```
keytool -export -alias <alias> -keystore <keystore> -rfc -file <alias>.cer
keytool -import -alias <alias> -file <alias>.cer -keystore <truststore>
```
- Set all of the configurations in the config file:
Defaults are already set, except for the absolute path to the keystore generated in the 
previous step along with its password. You'll have to set these using the format
described below.
You may write your own config file, but it must follow the following format:
```
<port number> (must be the same in the CONIKS client config)
<alias> (same alias used for the server's signing key pair)
<full server hostname>
<epoch length in milliseconds>
<absolute path to keystore>/<keystore>
<keystore password>
<path to truststore>/<truststore> (not used in test mode)
<truststore password> (not used for test mode)
```
Especially if you're running in full operating mode, make sure the config file is only readable 
by the users allowed to run the CONIKS server to protect your keystore password.
- Set all of the configs in the run script *coniks_server.sh*:
Defaults are already set, but you may change the following variables:
```CLASS_DEST``` if you used a different classpath when building the server.
```CONIKS_SERVERCONFIG``` if you're using a different config file
```CONIKS_SERVERLOGS``` to store the server logs somewhere other than a *logs* directory

###Running
We provide a run script for the CONIKS server *coniks_server.sh*, which allows you to run the server in
full operation mode and test mode.
By default, the server is set to be initialized with 10 dummy users. You may change this by setting 
```CONIKS_INIT_SIZE``` in the run script the desired number.

The run script supports four commands: 
- ```start```: start the server in full operation mode (runs in background).
- ```test```: start the server in test mode (runs in foreground).
- ```stop```: stop the server.
- ```clean```: remove all logs written by the server, and stop the server if it's running.
For example, to start the server in full operation mode, use
```./coniks_server.sh start```
Analogously to test and stop the server, and remove the logs.

## Server Installation on a Remote Machine
You may want to install the server on a remote machine.
Set the ```PUBUSER```, ```PUBHOST``` and ```PUBPATH``` variables in the Makefile.
```PUBUSER``` will need ssh access to the remote machine.
You'll then have to run the setup steps on the remote machine or send the appropriate files.
Assuming you've built the server locally, run:
```
make pubbin
```
Next, install the run script on the remote machine:
```
make pubscr
```
You may need to change the permissions on the script to be able to execute it on the remote machine.

## Disclaimer
Please keep in mind that this CONIKS reference implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/citp/coniks-ref-implementation/releases).

##Documentation
[Read the server's Java API (javadoc)](https://citp.github.io/coniks-ref-implementation/org/coniks/coniks_server/package-summary.html)
