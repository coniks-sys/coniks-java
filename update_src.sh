#!/bin/bash

# copy over the source from the branch
git checkout origin/master coniks_common/src/main/java/org/coniks/coniks_common
git checkout origin/master coniks_server/src/main/java/org/coniks/coniks_server
git checkout origin/master coniks_test_client/src/main/java/org/coniks/coniks_test_client
git checkout origin/master crypto/src/main/java/org/coniks/crypto
git checkout origin/master util/src/main/java/org/coniks/util
mkdir -p src/org/coniks/coniks_common
mkdir -p src/org/coniks/coniks_server
mkdir -p src/org/coniks/coniks_test_client
mkdir -p src/org/coniks/crypto
mkdir -p src/org/coniks/util
cp coniks_common/src/main/java/org/coniks/coniks_common/*.java src/org/coniks/coniks_common/
cp coniks_server/src/main/java/org/coniks/coniks_server/*.java src/org/coniks/coniks_server/
cp coniks_test_client/src/main/java/org/coniks/coniks_test_client/*.java src/org/coniks/coniks_test_client/
cp crypto/src/main/java/org/coniks/crypto/*.java src/org/coniks/crypto/
cp util/src/main/java/org/coniks/util/*.java src/org/coniks/util/
git rm -rf coniks_common
git rm -rf coniks_server
git rm -rf coniks_test_client
git rm -rf crypto
git rm -rf util
