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

import java.io.LineNumberReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

/** Allows retrieval of the
 */
public class HttpPublicKeyRecordRetriever implements PublicKeyRecordRetriever {
    /**
     *
     */
    public HttpPublicKeyRecordRetriever() {
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecordRetriever#getRecords(java.lang.CharSequence, java.lang.CharSequence, java.lang.CharSequence)
     */
    public List<String> getRecords(final CharSequence methodAndOptions,
            final CharSequence selector, final CharSequence token)
            throws TempFailException, PermFailException {
        if (!"http/well-known".equals(methodAndOptions)) {
			throw new PermFailException("Only http/well-known is supported: "
                    + methodAndOptions + " options unsupported.");
		}

        StringBuilder path = new StringBuilder("http://");

        path.append(token);
        path.append(":8008");
        path.append("/.well-known/domainkey/");
        path.append(token);
        path.append("/");
        path.append(selector);

        String response = null;

        HttpClient httpclient = new DefaultHttpClient();
        try {
        	HttpGet httpget = new HttpGet(path.toString());

        	// Create a response handler
        	ResponseHandler<String> responseHandler = new BasicResponseHandler();
        	response = httpclient.execute(httpget, responseHandler);
        } catch (Throwable t) {
        	throw new PermFailException("Error fetching key from : "
        			+ path.toString());
        } finally {
        	// When HttpClient instance is no longer needed,
        	// shut down the connection manager to ensure
        	// immediate deallocation of all system resources
        	httpclient.getConnectionManager().shutdown();
        }

        if (response == null) {
        	return null;
        }

        LineNumberReader lnr = new LineNumberReader(new StringReader(response));
        List<String> records = new ArrayList<String>();

        for (;;) {
        	try {
        		String l = lnr.readLine();
        		if (l == null) {
        			return records;
        		}

        		records.add(l);
        	} catch (Throwable t) {
        		throw new PermFailException("Error parsing result from : "
        				+ path.toString());
        	}
        }
    }
}
