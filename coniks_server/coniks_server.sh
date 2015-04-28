#!/bin/bash

#  Copyright (c) 2015, Princeton University.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are 
#  met:
#  * Redistributions of source code must retain the above copyright 
#  notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above 
#  copyright notice, this list of conditions and the following disclaimer 
#  in the documentation and/or other materials provided with the 
#  distribution.
#  * Neither the name of Princeton University nor the names of its
#  contributors may be used to endorse or promote products derived from
#  this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
#  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
#  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
#  POSSIBILITY OF SUCH DAMAGE.

## Runs or stops a CONIKS server instance

# Set all the configs here
CLASSPATH="-cp ."
SERVER_BIN="org.coniks.coniks_server.ConiksServer"
RUN_CONIKS="java $CLASSPATH $SERVER_BIN"
LOG_PATH="/path/to/logs"

if [ -z "$1" ]; then
    echo "Usage: $0 <start | stop | clean>"
    exit
fi

CMD=$1

# start up the server if no other instances are running.
if [ "$CMD" = "start" ]; then
    # need to check for 1 since the grep command 
    # itself is included in the count    
    if [ `ps ax | grep -c $SERVER_BIN` -gt 1 ]; then
        echo "An instance of $SERVER_BIN is already running."
        echo "Exiting."
        exit
    fi
    
    if [ ! -d "$LOG_PATH" ]; then
        mkdir "$LOG_PATH"
    fi

    echo "Starting up the CONIKS server."
    echo "All logs are in $LOG_PATH."

    # redirecting stderr to stdout to capture error messages in console log
    nohup sh -c "exec $RUN_CONIKS >> $LOG_PATH/console 2>&1" >>/dev/null &
    # need to store PID in file so we can stop the program later
    echo $! > $LOG_PATH/pid

# stop a running server
elif [ "$CMD" = "stop" ]; then
     if [ `ps ax | grep -c $SERVER_BIN` -eq 1 ]; then
        echo "CONIKS is not running."
        echo "Exiting."
        exit
    fi

     echo "Stopping the CONIKS server."
     
     kill -9 `cat $LOG_PATH/pid` >/dev/null
     rm -f $LOG_PATH/pid

# remove all logs in the LOG_PATH
elif [ "$CMD" = "clean" ]; then
    echo "Removing all logs in $LOG_PATH."

    # if we don't stop the server before, it will crash when trying to
    # write to one of the logs
     if [ `ps ax | grep -c $SERVER_BIN` -gt 1 ]; then
         echo "Stopping the CONIKS server."
     
         kill -9 `cat $LOG_PATH/pid` >/dev/null
         rm -f $LOG_PATH/pid
    fi

    rm -rf "$LOG_PATH/"*;

else
    echo "Usage: $0 <start | stop | clean>"
fi
