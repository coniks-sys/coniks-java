/*
  Copyright (c) 2015, Princeton University.
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

package org.coniks.coniks_test_client;

/** Defines constants representing the types
 * of errors that can occur during CONIKS
 * consistency checks done by a client.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public final class ConsistencyErr {

    /** Private constructor for ConsistencyErr
     * restricts instantiation
     */
    private ConsistencyErr() {
    }

    /** Indicates that no error occurred during the 
     * consistency check. In other words, the check passed.
     */
    public static final int CHECK_PASSED = 20;

    /** Indicates that the name-to-key mapping sent by the server is
     * inconsistent with the root hash.
     */
    public static final int BAD_MAPPING_ERR = 21;

    /** Indicates an unexpected key for a known name-to-key mapping.
     */
    public static final int UNEXPECTED_KEY_ERR = 22;

    /** Indicates that an STR is inconsistent with the 
     * Merkle tree root to which it is being compared.
     */
    public static final int BAD_STR_ERR = 23;

    /** Indicates that an STR is inconsistent with another STR
     * for the same epoch and key server. In other words, the
     * key server has equivocated showing different parties diverging
     * views of its key directory.
    */
    public static final int EQUIVOCATION_ERR = 24;

    /** Indicates that the server's signature is invalid.
     */
    public static final int BAD_SERVER_SIG_ERR = 25;

    /** Indicates that the signature on a signed key or user info change 
     * is invalid.
     */
    public static final int BAD_SIGNED_CHANGE_ERR = 26;

    /** Indicates an error occurred while trying to load or save
        a client's key pair.
    */
    public static final int KEYSTORE_ERR = 27;

    /** Indicates the the client has attempted to do a disallowed operation.
     * E.g. perform an unsigned key change when the user doesn't allow this.
     */
    public static final int DISALLOWED_OP_ERR = 28;

}
