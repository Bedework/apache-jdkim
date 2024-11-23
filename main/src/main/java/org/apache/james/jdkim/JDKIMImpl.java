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

package org.apache.james.jdkim;

import org.apache.james.jdkim.api.DKIMSigner;
import org.apache.james.jdkim.api.DKIMVerifier;
import org.apache.james.jdkim.api.IscheduleDKIMSigner;
import org.apache.james.jdkim.api.JDKIM;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import java.security.PrivateKey;

/**
 * User: mike Date: 11/22/24 Time: 15:10
 */
public class JDKIMImpl implements JDKIM {
  @Override
  public SignatureRecord getSignatureRecord(final String data) {
    return new SignatureRecordImpl(data);
  }

  @Override
  public SignatureRecord getSignatureRecordForIschedule(
          final String data) {
    return SignatureRecordImpl.forIschedule(data);
  }

  @Override
  public void addDKIMVerifierStoredKey(final String domain,
                                       final String selector,
                                       final String key) {
    DKIMVerifierImpl.addStoredKey(domain, selector, key);
  }

  @Override
  public DKIMVerifier getDKIMVerifier() {
    return new DKIMVerifierImpl();
  }

  @Override
  public DKIMVerifier getIscheduleDKIMVerifier() {
    return new IscheduleDKIMVerifier();
  }

  @Override
  public DKIMSigner getDKIMSigner(
          final String signatureRecordTemplate,
          final PrivateKey privateKey) {
    return new DKIMSignerImpl(signatureRecordTemplate,
                              privateKey);
  }

  @Override
  public IscheduleDKIMSigner getIscheduleDKIMSigner(
          final PrivateKey privateKey) {
    return new IscheduleDKIMSignerImpl(privateKey);
  }

  @Override
  public IscheduleDKIMSigner getIscheduleDKIMSigner(
          final String signatureRecordTemplate,
          final PrivateKey privateKey) {
    return new IscheduleDKIMSignerImpl(
            signatureRecordTemplate,
            privateKey);
  }

}
