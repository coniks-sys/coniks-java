/*
  Copyright (c) 2016, Princeton University.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:
  * Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following disclaimer
  in the documentation and/or other materials provided with the
  distribution.
  * Neither the name of Princeton University nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
 */

package org.coniks.util;

import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.IOException;

// coniks-java imports
import org.coniks.util.Convert;

/** Implements the logger used by any CONIKS component.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class Logging {

    /** The maximum number of bytes logged per log file.
     */
    public static final int MAX_BYTES_LOGGED_PER_FILE = (1 << 15);

    /** The maximum number of log files per log.
     */
    public static final int MAX_NUM_LOG_FILES = 5;

    private static Logger logger;

    /** Sets up a logger for a CONIKS component.
     *
     *@param logFile the file name for this logger.
     *@param name the name for this logger.
     */
    public static void setup (String logFile, String name) {

        String logName = "";
        if (name != null) {
            logName = " - "+name;
        }

        logger = Logger.getLogger("ConiksLogger"+logName);

        // suppress the logging output to the console
        logger.setUseParentHandlers(false);

        logger.setLevel(Level.INFO);

        try {
             FileHandler handler = new FileHandler(logFile,
                                                  MAX_BYTES_LOGGED_PER_FILE,
                                                  MAX_NUM_LOG_FILES, true);

            // create a TXT formatter
            SimpleFormatter fmt = new SimpleFormatter();
            handler.setFormatter(fmt);

            // add the handler
            logger.addHandler(handler);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        catch (SecurityException e) {
            e.printStackTrace();
        }
    }

    /** Writes an information message {@code msg}
     * to the main client log.
     */
    public static void log (String msg) {
        logger.info(msg);
    }

    /** Writes a severe error message {@code msg}
     * to the main client log.
     */
    public static void error (String msg) {
        logger.severe(msg);
    }
}
