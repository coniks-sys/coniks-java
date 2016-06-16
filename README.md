#CONIKS

[![Build Status](https://travis-ci.org/coniks-sys/coniks-ref-implementation.svg?branch=use-proto-bytestrs)](https://travis-ci.org/coniks-sys/coniks-ref-implementation)

Copyright (C) 2015-16 Princeton University.

http://coniks.org

##Introduction
CONIKS is a key management service that provides consistency and privacy for end-user public keys. It protects users against malicious or coerced key servers which may want to impersonate these users to compromise their secure communications: CONIKS will quickly detect any spurious keys, or any versions of the key directory that are inconsistent between two or more users. Nonetheless, CONIKS users do not need to worry about or even see these protocols, or the encryption keys, as CONIKS seamlessly integrates into any existing secure messaging application.

##CONIKS Reference Implementation
This software package serves as a reference implementation for the CONIKS system. The basic [CONIKS server](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_server) and simple [CONIKS test client](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_test_client) demonstrate the functionality of the system and the CONIKS protocols, so anyone interested in deploying CONIKS in their secure messaging system can then use this software package as a reference when implementing the service. This package also contains the [common message format definitions](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_common) that CONIKS servers and clients use to communicate. 

## Disclaimer
Please keep in mind that this CONIKS reference implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/citp/coniks-ref-implementation/releases).

##Documentation
[Read the package's Java API (javadoc)](https://coniks-sys.github.io/coniks-ref-implementation/)
