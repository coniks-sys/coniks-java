#CONIKS Test Client

Copyright (C) 2015-16 Princeton University.

https://coniks.cs.princeton.edu

##Introduction
This is a simple test client for the CONIKS key management system. It supports new key registrations, key lookups and key consistency checks. It is designed to communicate with the basic implementation of a [CONIKS server](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_server).

##Building the Test Client
- Prerequisites:
You'll need Java JDK7 or greater and need to ensure that the Google protobufs have been compiled with the most recent version of protoc. If you've already compiled the protobufs for the server, you don't need to
repeat this step for the client.
You'll also need to install the automake and build-essential packages.
- Compiling:
The default classpath is *bin*. If you'd like to change this, you'll need to change the ```CLASS_DEST``` 
variable in the Makefile. To build, run:
```
make 
```

##Using the Test Client

The CONIKS test client has two operating modes: Test Mode and Full Operation. 
Running the client in test mode allows you to still test all CONIKS protocols and operations,
but requires less setup as you can simply use the default configuration in the included *config* file.
**Note:** You must be running the server in the same operating mode.

### Setup
- Full operation mode only: Import the server certificate(s) for SSL/TLS communication.
Repeat the following steps for each server certificate:
```
keytool -import -alias <alias> -file <certificate file> -keystore <truststore name>
```
The alias must match the alias used when generating the cert for the server. You will be asked to
enter a password for each truststore. Make sure to remember this password.
- Set all of the configurations in the config file:
Defaults are already set, except for the absolute path to the keystore generated in the 
previous step along with its password. You'll have to set these using the format
described below.
You may write your own config file, but it must follow the following format:
```
<port number> (must be the same in the CONIKS server config)
```
- Set all of the configs in the run script *coniks_test_client.sh*:
Defaults are already set, but you may change the following variables:
```CLASS_DEST``` if you used a different classpath when building the client.
```CONIKS_CLIENTCONFIG``` if you're using a different config file

###Running
We provide a run script for the CONIKS test client *coniks_test_client.sh*, which allows you to run
the test client in full operation mode and test mode.
- Run in full operation mode:
```./coniks_test_client.sh <server hostname>```
- Run in test mode:
```./coniks_test_client.sh <server hostname> test```

Once running, the client prompts you to enter an operation, the number of users for which to
perform the operation and the first dummy user for which to run the operation. Dummy users are
identified by numbers, so user "5" is the 5th dummy user.
The test client will prompt you until you no longer want to continue.

Supported operations: 
- ```REGISTER```: register a new name-to-public key mapping with the CONIKS server.
- ```LOOKUP```: look up a public key, and obtaining a cryptographic proof is the user exists.
- ```VERIFY```: verify a cryptographic proof for a key mapping.

Some examples:
- REGISTER 10 10: registers 10 new users, identified as dummy users 10 through 19.
- LOOKUP 1 18: looks up the key for dummy user 18.
- VERIFY 4 7: verifies the consistency proof obtained from looking up the key for dummy users 7 through 10.

## Test Client Installation on a Remote Machine
You may want to install the test client on a remote machine.
Set the ```PUBUSER```, ```PUBHOST``` and ```PUBPATH``` variables in the Makefile.
```PUBUSER``` will need ssh access to the remote machine.
You'll then have to run the setup steps on the remote machine or send the appropriate files.
Assuming you've built the test client locally, run:
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
[Read the test client's Java API (javadoc)](https://citp.github.io/coniks-ref-implementation/org/coniks/coniks_test_client/package-summary.html)