#CONIKS Server

Copyright (C) 2015-16 Princeton University.

http://coniks.org

##Introduction
This is a basic reference implementation of a server for the CONIKS key management system. It currently supports new key registrations, key lookups, changes to key data and user policies (**new features**) and can generate consistency proofs and signed directory summaries. It is designed to communicate with the [CONIKS test client](https://github.com/coniks-sys/coniks-ref-implementation/tree/master/coniks_test_client).

##Building the Server - With Maven
The coniks_server build is managed using Maven. (Instructions for building without Maven coming soon)

1) Install Apache Maven, if you don't have it. Visit the [Maven downloads page](https://maven.apache.org/download.cgi) for details.

2) Install the library into your Maven repository:
```$ mvn install```

3) If you don't use Maven to manage your own build, you can build a .jar file to use:
```$ mvn package```

These instructions will install the ``coniks_server`` Maven artifact.

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

The run script supports four commands: 
- ```start```: start the server in full operation mode (runs in background).
- ```test```: start the server in test mode (runs in foreground).
- ```stop```: stop the server.
- ```clean```: remove all logs written by the server, and stop the server if it's running.
For example, to start the server in full operation mode, use
```./coniks_server.sh start```
Analogously to test and stop the server, and remove the logs.

## Disclaimer
Please keep in mind that this CONIKS reference implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/citp/coniks-ref-implementation/releases).

##Documentation
[Read the server's Java API (javadoc)](https://coniks-sys.github.io/coniks-ref-implementation/org/coniks/coniks_server/package-summary.html)
