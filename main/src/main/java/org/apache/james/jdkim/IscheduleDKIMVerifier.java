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

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

/** Variation on the DKIMVerifier class which handles ischedule (http) data
 *
 */
public class IscheduleDKIMVerifier extends DKIMVerifierImpl {
	public IscheduleDKIMVerifier() {
		super();
		allowableFutureSeconds = 360;
	}

	public IscheduleDKIMVerifier(final PublicKeyRecordRetriever publicKeyRecordRetriever) {
		super(publicKeyRecordRetriever);
		allowableFutureSeconds = 360;
	}

	@Override
	public SignatureRecord newSignatureRecord(final String record) {
		return SignatureRecordImpl.forIschedule(record);
	}
}
