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

import java.util.Collection;
import java.util.Properties;

/**
 * Compound token representing <i>grant </i> clause. See policy format
 * {@code org.apache.river.api.security.ConcurrentPolicyFile } description for details.
 *
 * @see DefaultPolicyParser
 * @see DefaultPolicyScanner
 */
class GrantEntry
{

    /**
     * The signers part of grant clause. This is a comma-separated list of
     * certificate aliases.
     */
    private final String signers;

    /**
     * The codebase part of grant clause. This is an URL from which code
     * originates.  Comma separate list allowed?
     */
    private final String codebase;

    /**
     * Collection of PrincipalEntries of grant clause.
     */
    private final Collection<PrincipalEntry> principals;

    /**
     * Collection of PermissionEntries of grant clause.
     */
    private final Collection<PermissionEntry> permissions;

    GrantEntry( String signers, String codebase,
                Collection<PrincipalEntry> pe,
                Collection<PermissionEntry> perms
    )
    {
        this.signers = signers;
        this.codebase = codebase;
        this.principals = pe;
        this.permissions = perms;
    }

    public String toString()
    {
        String newline = "\n";
        StringBuilder sb = new StringBuilder( 400 );
        if( signers != null )
        {
            sb.append( signers ).append( newline );
        }
        if( codebase != null )
        {
            sb.append( codebase ).append( newline );
        }
        if( principals != null )
        {
            sb.append( principals ).append( newline );
        }
        if( permissions != null )
        {
            sb.append( permissions ).append( newline );
        }
        return sb.toString();
    }

    /**
     * @return the signers
     */
    String getSigners()
    {
        return signers;
    }

    /**
     * @return the codebase
     */
    String getCodebase( Properties system )
    {
        if( system == null )
        {
            return codebase;
        }
        try
        {
            return PolicyUtils.expand( codebase, system );
        }
        catch( ExpansionFailedException ex )
        {
//                Logger.getLogger(DefaultPolicyScanner.class.getName()).log(Level.SEVERE, null, ex);
            ex.printStackTrace( System.err );
            return codebase;
        }
    }

    /**
     * @return the principals
     */
    Collection<PrincipalEntry> getPrincipals()
    {
        return principals;
    }

    /**
     * @return the permissions
     */
    Collection<PermissionEntry> getPermissions()
    {
        return permissions;
    }
}
