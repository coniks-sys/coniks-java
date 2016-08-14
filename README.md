#CONIKS

[![Build Status](https://travis-ci.org/coniks-sys/coniks-java.svg?branch=master)](https://travis-ci.org/coniks-sys/coniks-java)
[![Coverage Status](https://coveralls.io/repos/github/coniks-sys/coniks-java/badge.svg?branch=master&dummy=1)](https://coveralls.io/github/coniks-sys/coniks-java)

Copyright (C) 2015-16 Princeton University.

http://coniks.org

##Introduction
CONIKS is a key management system that provides transparency and privacy for end-user public keys. CONIKS protects end-to-end encrypted communications against malicious or compromised communication providers and surveillance by storing users' encryption keys in tamper-evident and publicly auditable key directories on the server side. This allows messaging clients to verify the identity of users automatically, and prevents malicious/compromised servers from hijacking secure communications without getting caught.

##Java Library
This software package serves as a Java library for the CONIKS system and includes reference implementations for the CONIKS server and client. The basic [CONIKS server](https://github.com/coniks-sys/coniks-java/tree/master/coniks_server) and simple [CONIKS test client](https://github.com/coniks-sys/coniks-java/tree/master/coniks_test_client) demonstrate the functionality of the system and the CONIKS protocols, so anyone interested in deploying CONIKS in their secure messaging system can then use this software package as a reference when implementing the service. This package also contains the [common message format definitions](https://github.com/coniks-sys/coniks-java/tree/master/coniks_common) that CONIKS servers and clients use to communicate.

## Disclaimer
Please keep in mind that this CONIKS Java implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-java/releases).

##Documentation
[Read the package's Java API (javadoc)](https://coniks-sys.github.io/coniks-java/)

## Current Core Developers
Releases of coniks-java will be signed with one of the following GPG keys:

- **Marcela Melara** &lt;msmelara@gmail.com&gt; `C0EB3C38F30F80AB6A12C9B78E556CF999AAFE`
