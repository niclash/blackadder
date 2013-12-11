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
 * Compound token representing <i>principal </i> entry of a <i>grant </i>
 * clause. See policy format
 * {@code org.apache.river.api.security.ConcurrentPolicyFile } description for details.
 *
 * @see DefaultPolicyParser
 * @see DefaultPolicyScanner
 */
class PrincipalEntry
{

    /**
     * Wildcard value denotes any class and/or any name.
     * Must be asterisk, for proper general expansion and
     * PrivateCredentialsPermission wildcarding
     */
    public static final String WILDCARD = "*";

    /**
     * The classname part of principal clause.
     */
    private final String klass;

    /**
     * The name part of principal clause.
     */
    private final String name;

    PrincipalEntry( String classname, String name )
    {
        klass = classname;
        this.name = name;
    }

    public String toString()
    {
        String newline = "\n";
        int l = getKlass() == null ? 0 : getKlass().length();
        l = l + ( getName() == null ? 0 : getName().length() );
        l = l + 4;
        StringBuilder sb = new StringBuilder( l );
        if( getKlass() != null )
        {
            sb.append( getKlass() ).append( newline );
        }
        if( getName() != null )
        {
            sb.append( getName() ).append( newline );
        }
        return sb.toString();
    }

    /**
     * @return the klass
     */
    String getKlass()
    {
        return klass;
    }

    /**
     * @return the name
     */
    String getName()
    {
        return name;
    }
}
