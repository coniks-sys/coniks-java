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

package org.coniks.coniks_common;

/** Defines constants representing the types
 * of errors that the server may return to a client.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public final class ServerErr {

    /** Private constructor for ServerErr
     * restricts instantiation
     */
    private ServerErr() {
    }

    /** Indicates that the server returned no error.
     */
    public static final int SUCCESS = 10;

    /** Indicates that an error internal to the server
     * occurred. 
     */
    public static final int INTERNAL_SERVER_ERR = 11;

    /** Indicates that the name the client tried to register
     * with the server already exists and could not be registered.
     */
    public static final int NAME_EXISTS_ERR = 12;

    /** Indicates that the server could not find the name the
     * client tried to lookup.
     */
    public static final int NAME_NOT_FOUND_ERR = 13;

     /** Indicates that the message the server received from the client
     * was malformed.
     */
    public static final int MALFORMED_CLIENT_MSG_ERR = 14;

    /** Indicates that the message the client received from the server
     * was malformed.
     */
    public static final int MALFORMED_SERVER_MSG_ERR = 15;

    /** Indicates that the server could not verify the signed change
     * message received by the client.
     */
    public static final int SIGNED_CHANGE_VERIF_ERR = 16;

    /** Indicates a generic server error.
     */
    public static final int SERVER_ERR = 17;

}
