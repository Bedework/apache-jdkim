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

package org.apache.james.jdkim.impl;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Stores and returns public keys which have been supplied in some out of band manner
 */
public class StoredPublicKeyRecordRetriever implements PublicKeyRecordRetriever {
	/* Public keys indexed by domain then selector */
	private static Map<String, Map<String, String>> pkeys =
			new HashMap<String, Map<String, String>>();

    /**
     *
     */
    public StoredPublicKeyRecordRetriever() {
    }

    /**
     *
     */
    public static void clearKeys() {
    	pkeys.clear();
    }

    /**
     * @param domain per spec
     * @param selector per spec
     * @param key per spec
     */
    public static void addKey(final String domain, final String selector, final String key) {
    	Map<String, String> domainKeys = pkeys.get(domain);

    	if (domainKeys == null) {
    		domainKeys = new HashMap<String, String>();

    		pkeys.put(domain, domainKeys);
    	}

    	domainKeys.put(selector, key);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecordRetriever#getRecords(java.lang.CharSequence, java.lang.CharSequence, java.lang.CharSequence)
     */
    public List<String> getRecords(final CharSequence methodAndOptions,
            final CharSequence selector, final CharSequence token)
            throws TempFailException, PermFailException {
        if (!"private-exchange".equals(methodAndOptions)) {
			throw new PermFailException("Only private-exchange is supported: "
                    + methodAndOptions + " options unsupported.");
		}

        List<String> records = new ArrayList<String>();

    	Map<String, String> domainKeys = pkeys.get(token);

    	if (domainKeys != null) {
    		String key = domainKeys.get(selector);

    		if (key != null) {
    			records.add(key);
    		}
    	}

    	return records;
    }
}
