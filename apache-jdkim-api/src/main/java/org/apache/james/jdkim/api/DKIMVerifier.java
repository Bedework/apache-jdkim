/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/

package org.apache.james.jdkim.api;

import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * User: mike Date: 11/22/24 Time: 16:24
 */
public interface DKIMVerifier {
  SignatureRecord newSignatureRecord(final String record);

  PublicKeyRecord publicKeySelector(final List<String> records)
          throws PermFailException;

  /**
   * Iterates through signature's declared lookup method
   *
   * @param sign
   *                the signature record
   * @return an "applicable" PublicKeyRecord
   * @throws TempFailException on error
   * @throws PermFailException on error
   */
  PublicKeyRecord publicRecordLookup(SignatureRecord sign)
          throws TempFailException, PermFailException;

  /**
   * Verifies all of the DKIM-Signature records declared in the supplied input
   * stream
   *
   * @param is
   *                inputStream
   * @return a list of verified signature records.
   * @throws IOException if error
   * @throws FailException
   *                 if no signature can be verified
   */
  List<SignatureRecord> verify(InputStream is) throws IOException,
          FailException;

  public BodyHasher newBodyHasher(Headers messageHeaders) throws FailException;

  /**
   * Verifies all of the DKIM-Signature records declared in the Headers
   * object.
   *
   * @param messageHeaders
   *                parsed headers
   * @param bodyInputStream
   *                input stream for the body.
   * @return a list of verified signature records
   * @throws IOException on io error
   * @throws FailException
   *                 if no signature can be verified
   */
  List<SignatureRecord> verify(Headers messageHeaders,
                               InputStream bodyInputStream)
          throws IOException, FailException;

  /**
   * Completes the simultaneous verification of multiple
   * signatures given the previously prepared compound body hasher where
   * the user already written the body to the outputstream and closed it.
   *
   * @param bh the BodyHasher previously obtained by this class.
   * @return a list of valid (verified) signatures or null on null input.
   * @throws FailException if no valid signature is found
   */
  List<SignatureRecord> verify(BodyHasher bh) throws FailException;
}
