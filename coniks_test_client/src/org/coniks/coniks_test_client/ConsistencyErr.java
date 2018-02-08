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
    public static final int NO_ERR = 0;

    /** Indicates that an error internal to the client
     * occurred during the consistency check. 
     */
    public static final int INTERNAL_ERR = -1;

    /** Indicates that the binding sent by the server is
     * inconsistent with the root hash.
     */
    public static final int BAD_BINDING_ERR = -2;

    /** Indicates that the STR is inconsistent with the 
     * Merkle tree root to which it is being compared.
     */
    public static final int BAD_STR_ERR = -3;

    /** Indicates that the server's signature is invalid.
     */
    public static final int BAD_SERVER_SIG_ERR = -4;

    /** Indicates that the protobuf message was somehow
     * malformed or of the incorrect type.
     */
    public static final int MSG_ERR = -5;

}
