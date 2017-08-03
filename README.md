# CONIKS

[![Build Status](https://travis-ci.org/coniks-sys/coniks-java.svg?branch=master)](https://travis-ci.org/coniks-sys/coniks-java)
[![Coverage Status](https://coveralls.io/repos/github/coniks-sys/coniks-java/badge.svg?branch=master&dummy=1)](https://coveralls.io/github/coniks-sys/coniks-java)

http://coniks.org

## Introduction
CONIKS is a key management system that provides transparency and privacy for end-user public keys. CONIKS protects end-to-end encrypted communications against malicious or compromised communication providers and surveillance by storing users' encryption keys in tamper-evident and publicly auditable key directories on the server side. This allows messaging clients to verify the identity of users automatically, and prevents malicious/compromised servers from hijacking secure communications without getting caught.

## Java Library
The pckages in this library implement the various components of the CONIKS system and may be imported as jar files individually.

- `coniks_common`: Common message format definitions
- `coniks_server`: Prototype key server
- `coniks_test_client`: Prototype client CLI
- `crypto`: Cryptographic algorithms and operations
- `util`: Utility functions

The `protos` directory contains the Protocol Buffer message definitions
for the client-server messages.

## Disclaimer
Please keep in mind that this CONIKS Java implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-java/releases).

##Documentation
[Read the package's Java API (javadoc)](https://coniks-sys.github.io/coniks-java/)

## Current Core Developers
Releases of coniks-java will be signed with one of the following GPG keys:

- **Marcela Melara** &lt;msmelara@gmail.com&gt; `C0EB3C38F30F80AB6A12C9B78E556CF999AAFE`
