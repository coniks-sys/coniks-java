#!/bin/bash
# generates the Javadoc API for the coniks_common, coniks_server and
# coniks_test_client subpackages

if [ "$#" -ne 1 ]; then
    echo "specify version: e.g. 1.2"
    exit
fi

VERS=$1
    
javadoc -d . -public -overview ./src/org/coniks/overview.html -sourcepath ./src/ -classpath ./src/ -use -splitIndex -windowtitle "CONIKS Java Reference Implementation API Specification" -doctitle "CONIKS Java Reference Implementation v$VERS API Specification" -header "<b>CONIKS Java Reference Implementation v$VERS</b>" org.coniks.coniks_common org.coniks.coniks_server org.coniks.coniks_test_client
