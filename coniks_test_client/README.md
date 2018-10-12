# CONIKS Test Client

http://coniks.org

## Introduction
This is a simple test client for the CONIKS key management system. It supports new key registrations, key lookups, key changes (**new feature**), and user policy changes (e.g. key change policy) (**new feature**). It is designed to communicate with the basic implementation of a [CONIKS server](https://github.com/coniks-sys/coniks-java/tree/master/coniks_server).

## Building the Test Client - With Maven
The coniks_test_client build is managed using Maven. (Instructions for building without Maven coming soon)

1) Install Apache Maven, if you don't have it. Visit the [Maven downloads page](https://maven.apache.org/download.cgi) for details.

2) Install the library into your Maven repository:
```$ mvn install```

3) If you don't use Maven to manage your own build, you can build a .jar file to use:
```$ mvn package```

These instructions will install the ``coniks_test_client`` Maven artifact.
The build configuration for coniks_test_client assembles all dependencies,
and includes them in the generated .jar file, so you can run the server
only using the coniks_test_client .jar file.

## Using the Test Client

The CONIKS test client has two operating modes: Test Mode and Full Operation.
Running the client in test mode allows you to still test all CONIKS
protocols and operations, but requires less setup as you can simply use
the default configuration in the included *config* file.
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
Defaults for the port number and user keys directory are already set,
except for the absolute path to the keystore generated in the
previous step along with its password. You'll have to set these using the format
described below.
You may write your own config file, but it must follow the following format:
```
<port number> (must be the same in the CONIKS server config)
<user keys dir>
```
- Set all of the configs in the run script *coniks_test_client.sh*:
Defaults are already set, but you may change the following variables:
```CLASS_DEST``` if you've changed configurations such as the artifactID or version in the client's pom.xml file before building.
```CONIKS_CLIENTCONFIG``` if you're using a different config file
```CONIKS_CLIENTLOGS``` to store the client logs somewhere other than a *logs* directory

### Running
We provide a run script for the CONIKS test client *coniks_test_client.sh*, which allows you to run
the test client in full operation mode and test mode.

The run script supports three commands:
- ```start <server hostname>```: start the client in full operation mode, connecting it to the given server.
- ```test <server hostname>```: start the client in test mode, connecting it to the given server.
- ```clean```: remove all logs written by the client.
For example, to start the client in full operation mode, connecitng it to a server on the local machine, use
```./coniks_test_client.sh start localhost```
Analogously to test the client, and remove the logs (takes no second argument).

Once running, the client prompts you to enter an operation, the number of users for which to
perform the operation and the first dummy user for which to run the operation. Dummy users are
identified by numbers, so user "5" is the 5th dummy user.
The test client will prompt you until you no longer want to continue.

Supported operations:
- ```REGISTER```: register a new name-to-public key mapping with the CONIKS server.
- ```LOOKUP```: look up a public key, and verify the cryptographic proof of inclusion if the user exists.
- ```SIGNED```: change the public key registered for an existing name and authorize this change via a digital signature.
- ```UNSIGNED```: change the public key registered for an existing name, without authorization. This operation will fail if the affected user doesn't allow unsigned key changes.
` ```POLICY```: change the key change policy -- if unsigned changes are allowed, disallow them, and vice versa. The default policy is to allow unsigned changes.

Some examples:
- REGISTER 10 10: registers 10 new users, identified as dummy users 10 through 19.
- LOOKUP 1 18: looks up the key for dummy user 18.
- SIGNED 10 10: performs a signed key data change for users 10 through 19.
- UNSIGNED 10 10: performs an unsigned key data change for users 10 throught 19.
- POLICY 1 18: changes the key change policy for user 18.

## Disclaimer
Please keep in mind that this CONIKS Java implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-java/releases).

## Documentation
[Read the test client's Java API (javadoc)](https://coniks-sys.github.io/coniks-java/org/coniks/coniks_test_client/package-summary.html)
