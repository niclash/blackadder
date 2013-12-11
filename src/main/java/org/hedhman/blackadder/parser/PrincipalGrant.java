/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.hedhman.blackadder.parser;

import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.UnresolvedPermission;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 *
 *
 */
class PrincipalGrant extends PermissionGrant implements Serializable
{
    private static final long serialVersionUID = 1L;
    protected final Set<Principal> pals;
    private final int hashCode;

    @SuppressWarnings("unchecked")
    PrincipalGrant( Principal[] pals, Permission[] perm )
    {
        super( perm );
        if( pals != null )
        {
            Set<Principal> palCol = new HashSet<Principal>( pals.length );
            palCol.addAll( Arrays.asList( pals ) );
            this.pals = Collections.unmodifiableSet( palCol );
        }
        else
        {
            this.pals = Collections.emptySet();
        }
        int hash = 5;
        hash = 97 * hash + ( this.pals != null ? this.pals.hashCode() : 0 );
        for( Permission p : getPermissions() )
        {
            if( p instanceof UnresolvedPermission )
            {
                hash = 97 * hash + p.hashCode();
            }
            else if( p != null )
            {
                Class c = p.getClass();
                String name = p.getName();
                String actions = p.getActions();
                hash = 97 * hash + ( c != null ? c.hashCode() : 0 );
                hash = 97 * hash + ( name != null ? name.hashCode() : 0 );
                hash = 97 * hash + ( actions != null ? actions.hashCode() : 0 );
            }
        }
        hashCode = hash;
    }

    @Override
    public boolean equals( Object o )
    {
        if( o == null )
        {
            return false;
        }
        if( o == this )
        {
            return true;
        }
        if( o.hashCode() != this.hashCode() )
        {
            return false;
        }
        if( o instanceof PrincipalGrant )
        {
            PrincipalGrant p = (PrincipalGrant) o;
            if( pals.equals( p.pals )
                && getPermissions().equals( p.getPermissions() ) )
            {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode()
    {
        return hashCode;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder( 300 );
        sb.append( "Principals: \n" );
        for( Principal principal : pals )
        {
            sb.append( principal.toString() ).append( "\n" );
        }
        sb.append( "\nPermissions: \n" );
        for( Permission permission : getPermissions() )
        {
            sb.append( permission.toString() ).append( "\n" );
        }
        return sb.toString();
    }

    boolean implies( Principal[] prs )
    {
        if( pals.isEmpty() )
        {
            return true;
        }
        if( prs == null || prs.length == 0 )
        {
            return false;
        }
        // PermissionGrant Principals match if equal or if they are Groups and
        // the Principals being tested are their members.  Every Principal
        // in this PermissionGrant must have a match.
        List<Principal> princp = Arrays.asList( prs );
        int matches = 0;
        for( Principal entrypal : pals )
        {
            //            Group g = null;
//            if ( entrypal instanceof Group ){
//                g = (Group) entrypal;
//            }
            // The first match breaks out of internal loop.
            for( Principal implied : princp )
            {
                if( entrypal.equals( implied ) )
                {
                    matches++;
                    break;
                }
                /* Having thought further about the following, I'm hesitant
                 * to allow a positive match for a Principal belonging to a 
                 * Group defined in PrincipalGrant, my reasoning is that
                 * a PrincipalGrant is immutable and therefore shouldn't change.
                 * Group represents a mutable component which can change the
                 * result of implies.  A PrincipalGrant, should
                 * have the same behaviour on all calls to implies.
                 * 
                 * The reason for this choice at this time; there is
                 * no way a Policy can be aware the PrincipalGrant
                 * has changed its behaviour. Since PrincpalGrant doesn't
                 * make the determination of a Permission implies, it only
                 * stores the PermissionGrant, a permission may continue to be
                 * implied after a Principal has been removed from a Group due
                 * to caching of PermissionCollections within the Policy.
                 * 
                 * Use Subject instead to group Principal's to grant additional
                 * Privileges to a user Principal.
                 */
//                if ( g != null && g.isMember(implied) ) {
//                    matches++;
//                    break;
//                }
            }
        }
        return matches == pals.size();
    }

    /**
     * Utility Method, really belongs somewhere else, but CodeSource subclasses use it.
     *
     * @deprecated will be removed when CodeSource based grants are removed.
     */
    @Deprecated
    CodeSource normalizeCodeSource( CodeSource codeSource )
    {
        if( codeSource == null )
        {
            return null;
        }
        URI codeSourceURI = null;
        try
        {
            codeSourceURI = PolicyUtils.normalizeURL( codeSource.getLocation() );
        }
        catch( URISyntaxException ex )
        {
            ex.printStackTrace( System.err );
        }
        CodeSource result = codeSource;
        try
        {
            if( codeSourceURI != null && codeSourceURI.toURL() != codeSource.getLocation() )
            {
                // URL was normalized - recreate codeSource with new URL
                CodeSigner[] signers = codeSource.getCodeSigners();
                if( signers == null )
                {
                    result = new CodeSource( codeSourceURI.toURL(), codeSource
                        .getCertificates() );
                }
                else
                {
                    result = new CodeSource( codeSourceURI.toURL(), signers );
                }
            }
        }
        catch( MalformedURLException ex )
        {
            ex.printStackTrace( System.err );
        }
        return result;
    }

    /* Dynamic grant's and file policy grant's have different semantics,
     * this class was originally abstract, it might be advisable to make it so
     * again.
     * 
     * dynamic grant's check if the contained protection domain is null first
     * and if so return true.  policy file grant's check if the passed in
     * pd is null first and if so return false.
     * 
     */
    public boolean implies( ProtectionDomain pd )
    {
        if( pals.isEmpty() )
        {
            return true;
        }
        if( pd == null )
        {
            return false;
        }
        Principal[] hasPrincipals = getPrincipals( pd );
        return implies( hasPrincipals );
    }

    Principal[] getPrincipals( final ProtectionDomain pd )
    {
        if( pd instanceof SubjectDomain )
        {
            final Set<Principal> principals = ( (SubjectDomain) pd ).getSubject().getPrincipals();
            // Synchronisation would prevent modification during array creation,
            // but it also prevents multi read,
            // lets use an iterator, catch ConcurrentModificationException 
            // (which should seldom happen) sleep momentarily and try again.
            Principal[] result;
            Iterator<Principal> it;
            // This minimal synchronization ensures that array size will
            // be correct if ConcurrentModificationException is not thrown.
            synchronized( principals )
            {
                result = new Principal[ principals.size() ];
                it = principals.iterator();
            }
            boolean retry = true;
            while( retry )
            {
                try
                {
                    int i = 0;
                    while( it.hasNext() )
                    {
                        result[ i ] = it.next();
                        i++;
                    }
                    return result;
                }
                catch( ConcurrentModificationException e )
                {
                    try
                    {
                        // sleep for modifications to finish = back off.
                        Thread.sleep( 20L );
                        synchronized( principals )
                        {  // try again
                            result = new Principal[ principals.size() ];
                            it = principals.iterator();
                        }
                    }
                    catch( InterruptedException ex )
                    {
                        // ProtectionDomain.getPrincipals() instead.
                        retry = false;
                        Thread.currentThread().interrupt(); // restore interrupt.
                    }
                }
                catch( ArrayIndexOutOfBoundsException e )
                {
                    retry = false;
                    // ProtectionDomain.getPrincipals() instead.
                    System.err
                        .println( "ArrayIndexOutOfBoundsException occured during iteration of Subject Principals" );
                    e.printStackTrace( System.err );
                }
            }
        }
        return pd.getPrincipals();
    }

    public boolean implies( ClassLoader cl, Principal[] pal )
    {
        // A null ClassLoader indicates the system domain.
        return implies( pal );
    }

    public boolean implies( CodeSource codeSource, Principal[] pal )
    {
        return implies( pal );
    }

    public PermissionGrantBuilder getBuilderTemplate()
    {
        PermissionGrantBuilder pgb = PermissionGrantBuilder.newBuilder();
        Collection<Permission> perms = getPermissions();
        pgb.context( PermissionGrantBuilder.PRINCIPAL )
            .principals( pals.toArray( new Principal[ pals.size() ] ) )
            .permissions( perms.toArray( new Permission[ perms.size() ] ) );
        return pgb;
    }

    public boolean isVoid()
    {
        return getPermissions().isEmpty();
    }

    //writeReplace method for serialization proxy pattern
    private Object writeReplace()
    {
        return getBuilderTemplate();
    }

    //readObject method for the serialization proxy pattern
    private void readObject( ObjectInputStream stream )
        throws InvalidObjectException
    {
        throw new InvalidObjectException( "PermissionGrantBuilder required" );
    }
}
