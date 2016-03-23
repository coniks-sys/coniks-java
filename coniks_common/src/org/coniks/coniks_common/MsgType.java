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

package org.coniks.coniks_common;

/** Defines constants representing the types
 * of messages exchanged by CONIKS clients and servers.
 *
 *@author Marcela Melara (@masomel)
 *@author Michael Rochlin (@marisbest2)
 */
public final class MsgType {

    /** Private constructor for MsgType
     * restricts instantiation
     */
    private MsgType() {
    }

    /** A username-to-data binding registration message.
     */
    public static final int REGISTRATION = 0;
    
    /** A request for a server's STR, either the server's own
     * or an STR observed from another server.
     */
    public static final int COMMITMENT_REQ = 1;
    
    /** A data binding lookup request.
     */
    public static final int KEY_LOOKUP = 2;
    
    /** A simple server response message, usually indicating some
     * kind of error.
     */
    public static final int SERVER_RESP = 3;
    
    /** A message containing an STR.
     */
    public static final int COMMITMENT = 4;

    /** A message containing an authentication path (i.e. a data 
     * binding proof).
     */
    public static final int AUTH_PATH = 5;

    /** A registration response message containing the registration epoch.
     * TODO: This will become a temporary binding in a future release.
     */
    public static final int REGISTRATION_RESP = 6;

    /** A message containing an STR observed from a server.
     * Currently unused.
     * Note: In a future version, clients might use this message type
     * when helping to circumvent DOS attacks.
     */
    public static final int OBSERVED_STR_PUSH = 7;


    public static final int ULNCHANGE_REQ = 8;
    public static final int SIGNED_ULNCHANGE_REQ = 9;

}
