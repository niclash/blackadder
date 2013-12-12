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

import java.security.KeyStore;
import java.security.Principal;
import org.hedhman.blackadder.expander.ExpansionFailedException;
import org.hedhman.blackadder.expander.GeneralExpansionHandler;

/**
 * Specific handler for expanding <i>self</i> and <i>alias</i> protocols.
 */
class PermissionExpander
    implements GeneralExpansionHandler
{

    // Store KeyStore
    private final KeyStore ks;

    // Store GrantEntry
    private final GrantEntry ge;

    /**
     * Combined setter of all required fields.
     */
    PermissionExpander( GrantEntry ge,
                        KeyStore ks
    )
    {
        this.ge = ge;
        this.ks = ks;
    }

    /**
     * Resolves the following protocols:
     * <dl>
     * <dt>self
     * <dd>Denotes substitution to a principal information of the parental
     * GrantEntry. Returns a space-separated list of resolved Principals
     * (including wildcarded), formatting each as <b>class &quot;name&quot;</b>.
     * If parental GrantEntry has no Principals, throws ExpansionFailedException.
     * <dt>alias:<i>name</i>
     * <dd>Denotes substitution of a KeyStore alias. Namely, if a KeyStore has
     * an X.509 certificate associated with the specified name, then returns
     * <b>javax.security.auth.x500.X500Principal &quot;<i>DN</i>&quot;</b> string,
     * where <i>DN</i> is a certificate's subject distinguished name.
     * </dl>
     *
     * @throws org.hedhman.blackadder.expander.ExpansionFailedException - if protocol is other than <i>self</i> or <i>alias</i>, or if data resolution failed
     */
    public String resolve( String protocol, String data )
        throws ExpansionFailedException
    {
        if( "self".equals( protocol ) )
        {
            //need expanding to list of principals in grant clause
            if( ge.getPrincipals() != null && ge.getPrincipals().size() != 0 )
            {
                StringBuilder sb = new StringBuilder();
                for( PrincipalEntry pr : ge.getPrincipals() )
                {
                    if( pr.getKlass() == null )
                    {
                        // aliased X500Principal
                        try
                        {
                            sb.append( pc2str( DefaultPolicyParser.getPrincipalByAlias( ks, pr.getName() ) ) );
                        }
                        catch( Exception e )
                        {
                            if( e instanceof SecurityException )
                            {
                                throw (SecurityException) e;
                            }
                            throw new ExpansionFailedException(
                                "Error expanding alias : " + pr.getName(), e );
                        }
                    }
                    else
                    {
                        sb.append( pr.getKlass() ).append( " \"" ).append( pr.getName() )
                            .append( "\" " );
                    }
                }
                return sb.toString();
            }
            else
            {
                throw new ExpansionFailedException(
                    "Self protocol is valid only in context of Principal-based grant entries" );
            }
        }
        if( "alias".equals( protocol ) )
        {
            try
            {
                return pc2str( DefaultPolicyParser.getPrincipalByAlias( ks, data ) );
            }
            catch( Exception e )
            {
                if( e instanceof SecurityException )
                {
                    throw (SecurityException) e;
                }
                throw new ExpansionFailedException( "Error expanding alias : " + data, e );
            }
        }
        throw new ExpansionFailedException( "Unknown expansion protocol : " + protocol );
    }

    // Formats a string describing the passed Principal.
    private String pc2str( Principal pc )
    {
        String klass = pc.getClass().getName();
        String name = pc.getName();
        return klass + " \"" + name + "\"";
    }
}
