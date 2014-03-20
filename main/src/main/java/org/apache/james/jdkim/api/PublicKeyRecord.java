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

import java.security.PublicKey;
import java.util.List;
import java.util.regex.Pattern;

public interface PublicKeyRecord {

    public final static String ANY = ";any;";

    public abstract void validate();

    public abstract boolean isHashMethodSupported(CharSequence hash);

    public abstract boolean isKeyTypeSupported(CharSequence hash);

    /**
     * @return null if "any", otherwise a list of supported methods
     */
    public abstract List<CharSequence> getAcceptableHashMethods();

    /**
     * @return null if "any", otherwise a list of supported methods
     */
    public abstract List<CharSequence> getAcceptableKeyTypes();

    public abstract Pattern getGranularityPattern();

    public abstract PublicKey getPublicKey();

    public abstract List<CharSequence> getFlags();

    public abstract boolean isTesting();

    public abstract boolean isDenySubdomains();

}