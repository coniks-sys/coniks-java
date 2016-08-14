/*
  Copyright (c) 2015-16, Princeton University.
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

package org.coniks.coniks_server;

// coniks-java imports
import org.coniks.util.Logging;

/** Represents the server's history. This history consists
 * of a linked list of signed tree roots forming a hash
 * chain.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ServerHistory {

    /** The head of the directory history hash chain
     * of {@link SignedTreeRoot}s.
     */
    private static SignedTreeRoot curSTR = null;

    /** The length of the directory history in
     * number of recorded STRs.
     */
    private static long length;

    /** Initializes the server's history with the given from the root node
     * {@code root}, the epoch {@code ep}, the previous epoch
     * {@code prevEp}, and the previous STR's hash {@code prevStrHash}.
     *
     *@return whether the intialization succeeded.
     */
    public static synchronized boolean initHistory(RootNode root, long ep,
                                                long prevEp, byte[] prevStrHash) {
        if (curSTR != null) {
            Logging.error("Trying to override existing history");
            return false;
        }

        // generates the first STR
        curSTR = TransparencyOps.generateSTR(root, ep, prevEp, prevStrHash);

        // want to make sure we didn't get a null STR
        if (curSTR == null) {
            Logging.error("Got a null STR from the init");
            return false;
        }

        return true;
    }

    /** Inserts the signed tree root for the next epoch at the head
    * of the history hash chain.
    * Ensures that the epochs are monotonically increasing and at least
    * EPOCH_INTERVAL apart.
    *
    *@param newSTR the signed tree root for the next epoch.
    *@return true if the STR is valid, false otherwise
    */
    public static synchronized boolean updateHistory(SignedTreeRoot newSTR) {

        // sanity check the input
        if (newSTR == null) {
            Logging.error("Got null STR");
            return false;
        }

        if (newSTR.getEpoch() < nextEpoch()) {
            Logging.error("Next epoch's STR has bad epoch");
            return false;
        }

        // Do we want to do some signature verification here?

        // reassign pointers
        curSTR = newSTR;

        // increment the length of the history hash chain
        length++;

        // TODO: evict oldest x STRs once length hits a certain value

        return true;
    }

    /** Retrieves the signed tree root for epoch {@code ep} from the linked
     * list representing the history.
     *
     *@return The signed tree root for epoch {@code ep}.
     *@throws An {@code UnsupportedOperationException} in case the
     * head of the list is reached before the requested signed tree root is found.
     */
    public static synchronized SignedTreeRoot getSTR(long ep){
        SignedTreeRoot runner = curSTR;

        while(runner.getEpoch() > ep && runner != null){
                // need to check if we reached the head of the list
                if (runner.getPrev() == null) {
                    throw new UnsupportedOperationException("reached the head of the list!");
                }
                else{
                    runner = runner.getPrev();
                }
        }

        return runner;
    }

    /** Gets the current signed tree root in the server's history. This is
     * used to synchronize between threads.
     *
     *@return curSTR
     */
    public static synchronized SignedTreeRoot getCurSTR() {
        return curSTR;
    }

    /** Gets the current epoch in the server's history. This is
     * used to synchronize between threads.
     *
     *@return curSTR's epoch
     */
    public static synchronized long getCurEpoch() {
        return curSTR.getEpoch();
    }

    /** Gets the current tree in the server's history. This is
     * used to synchronize between threads.
     *
     *@return curSTR's root node
     */
    public static synchronized RootNode getCurTree() {
        return curSTR.getRoot();
    }

    /** Computes the next epoch time given the current epoch time
     * and the epoch interval in the server's configuration.
     *
     *@return the next epoch time.
     */
    public static synchronized long nextEpoch() {
        return  curSTR.getEpoch()+ServerConfig.getEpochInterval();
    }

}
