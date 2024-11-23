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

import java.security.PrivateKey;

/** Interface to jdkim so we can isolate it and it's dependencies.
 * User: mike Date: 11/22/24 Time: 15:04
 */
public interface JDKIM {
  /**
   *
   * @return a SignatureRecord implementation
   */
  SignatureRecord getSignatureRecord(String data);

  /**
   *
   * @return a SignatureRecord implementation for iSchedule
   */
  SignatureRecord getSignatureRecordForIschedule(String data);

  void addDKIMVerifierStoredKey(String domain,
                                String selector,
                                String key);

  DKIMVerifier getDKIMVerifier();

  DKIMVerifier getIscheduleDKIMVerifier();

  DKIMSigner getDKIMSigner(String signatureRecordTemplate,
                           PrivateKey privateKey);

  IscheduleDKIMSigner getIscheduleDKIMSigner(PrivateKey privateKey);

  IscheduleDKIMSigner getIscheduleDKIMSigner(String signatureRecordTemplate,
                                    PrivateKey privateKey);
}
