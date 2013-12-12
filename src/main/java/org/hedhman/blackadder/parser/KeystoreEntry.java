/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hedhman.blackadder.parser;

/**
 * Compound token representing <i>keystore </i> clause. See policy format
 * {@link org.hedhman.blackadder.ConcurrentPolicyFile } description for details.
 *
 * @see DefaultPolicyParser
 * @see DefaultPolicyScanner
 */
class KeystoreEntry
{

    /**
     * The URL part of keystore clause.
     */
    private final String url;

    /**
     * The typename part of keystore clause.
     */
    private final String type;

    KeystoreEntry( String url, String type )
    {
        this.url = url;
        this.type = type;
    }

    public String toString()
    {
        String newline = "\n";
        int l = getUrl() == null ? 0 : getUrl().length();
        l = l + ( getType() == null ? 0 : getType().length() );
        l = l + 4;
        StringBuilder sb = new StringBuilder( l );
        if( getUrl() != null )
        {
            sb.append( getUrl() ).append( newline );
        }
        if( getType() != null )
        {
            sb.append( getType() ).append( newline );
        }
        return sb.toString();
    }

    /**
     * @return the url
     */
    String getUrl()
    {
        return url;
    }

    /**
     * @return the type
     */
    String getType()
    {
        return type;
    }
}
