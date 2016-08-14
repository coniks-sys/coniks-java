#!/bin/bash

# copy over the source from the branch
git checkout origin/master coniks_common/src/main/java/org/coniks/coniks_common
git checkout origin/master coniks_server/src/main/java/org/coniks/coniks_server
git checkout origin/master coniks_test_client/src/main/java/org/coniks/coniks_test_client
git checkout origin/master crypto/src/main/java/org/coniks/crypto
cp coniks_common/src/main/java/org/coniks/coniks_common/*.java src/org/coniks/coniks_common/
cp coniks_server/src/main/java/org/coniks/coniks_server/*.java src/org/coniks/coniks_server/
cp coniks_test_client/src/main/java/org/coniks/coniks_test_client/*.java src/org/coniks/coniks_test_client/
cp crypto/src/main/java/org/coniks/crypto/*.java src/org/coniks/crypto/
git rm -rf coniks_common
git rm -rf coniks_server
git rm -rf coniks_test_client
git rm -rf crypto
