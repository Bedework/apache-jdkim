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

import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class DKIMCommon {
	//protected static transient Logger log;

	protected static boolean deepDebug;

    protected static void updateSignature(final Signature signature,
    		final boolean relaxed,
    		final boolean ischeduleRelaxed,
            final CharSequence header,
            final String fv) throws SignatureException {
        if (relaxed | ischeduleRelaxed) {
            if (deepDebug) {
				trace("#" + header.toString().toLowerCase() + ":-");
			}
            signature.update(header.toString().toLowerCase().getBytes());
            signature.update(":".getBytes());
            String headerValue = fv.substring(fv.indexOf(':') + 1);
            headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
            headerValue = headerValue.replaceAll("[\t ]+", " ");

            if (ischeduleRelaxed) {
                headerValue = headerValue.replaceAll(" , ", ",");
            }

            headerValue = headerValue.trim();
            signature.update(headerValue.getBytes());
            if (deepDebug) {
            	trace("#" + headerValue + "#");
			}
        } else {
            signature.update(fv.getBytes());
            if (deepDebug) {
            	trace("#" + fv + "#");
			}
        }
    }

    protected static void signatureCheck(final Headers h, final SignatureRecord sign,
            final List<CharSequence> headers, final Signature signature)
            throws SignatureException, PermFailException {

    	String headerCanonicalisation = sign.getHeaderCanonicalisationMethod();

        boolean relaxedHeaders =
        		SignatureRecord.RELAXED.equals(headerCanonicalisation);
        boolean ischeduleRelaxedHeaders =
        		SignatureRecord.ISCHEDULE_RELAXED.equals(headerCanonicalisation);

        if (!relaxedHeaders && !ischeduleRelaxedHeaders
                && !SignatureRecord.SIMPLE.equals(headerCanonicalisation)) {
            throw new PermFailException(
                    "Unsupported canonicalization algorithm: "
                            + headerCanonicalisation);
        }

        if (ischeduleRelaxedHeaders) {
            for (CharSequence header: headers) {
                // NOTE check this getter is case insensitive
            	String hdr = header.toString();

            	// ischedule message concatenaytes all values to 1
                List<String> hl = h.getFields(hdr);

                if ((hl == null) || (hl.size() == 0)) {
                	continue;
                }

                if (hl.size() > 1) {
                    throw new PermFailException(
                            "header canonicalization algorithm failed: "
                                    + "Got multiple headers for " + hdr);
                }

                trace("========= Signing header " + hdr);

                updateSignature(signature, false, true, header,
                		hl.get(0));
                signature.update("\r\n".getBytes());
            }
        } else {
	        // NOTE: this relies on the list returned by Message being in insertion
	        // order
	        Map<String, Integer> processedHeader = new HashMap<String, Integer>();

	        for (CharSequence header: headers) {
	            // NOTE check this getter is case insensitive
	        	String hdr = header.toString();

	            List<String> hl = h.getFields(hdr);

	            if ((hl == null) || (hl.size() == 0)) {
	            	continue;
	            }

	            Integer done = processedHeader.get(hdr);
	            if (done == null) {
	            	done = Integer.valueOf(0);
	            }

	            int doneHeaders = done.intValue() + 1;

	            if (doneHeaders > hl.size()) {
	            	continue;
	            }

	            /* This works backwards up the header values as per the spec */
	            String fv = hl.get(hl.size() - doneHeaders);
	            updateSignature(signature, relaxedHeaders, false, header, fv);
	            signature.update("\r\n".getBytes());
	            processedHeader.put(hdr, new Integer(doneHeaders));
	        }
        }

        String signatureStub = "DKIM-Signature:" + sign.toUnsignedString();
        updateSignature(signature, relaxedHeaders,
        		ischeduleRelaxedHeaders,
        		"dkim-signature",
                signatureStub);
    }

    public static void streamCopy(final InputStream bodyIs, final OutputStream out)
            throws IOException {
        byte[] buffer = new byte[2048];
        int read;
        while ((read = bodyIs.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        bodyIs.close();
        out.close();
    }

    /** ===================================================================
     *                   Logging methods
     *  =================================================================== */

    /* *
     * @return Logger
     * /
    protected static Logger getLogger() {
      if (log == null) {
        log = Logger.getLogger(DKIMCommon.class);
      }

      return log;
    }*/

    protected static void debugMsg(final String msg) {
//      getLogger().debug(msg);
    	System.out.println(msg);
    }

    protected static void trace(final String msg) {
//      getLogger().trace(msg);
    	System.out.println(msg);
    }
}