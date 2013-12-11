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

import java.lang.ref.WeakReference;
import java.net.URI;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * The PermissionGrantBuilder creates Dynamic PermissionGrant's based on
 * information provided by the user.  The user must have access to the
 * system policy and have permission to grant permissions.
 *
 * A PermissionGrantBuilder implementation should also be used as the serialized form
 * for PermissionGrant's, the implementation of PermissionGrant's should
 * remain package private.
 *
 * This prevents the serialized form becoming part of the public api.
 *
 * Single Thread use only.
 *
 * @see PermissionGrant
 */
public abstract class PermissionGrantBuilder
{

    /**
     * The PermissionGrant generated will apply to all classes loaded by
     * the ClassLoader
     */
    public static final int CLASSLOADER = 0;

    /**
     * The PermissionGrant generated will apply to all classes belonging to
     * the ProtectionDomain.  This is actually a simplification for the
     * programmer the PermissionGrant will apply to the CodeSource and the
     * ClassLoader combination, the reason for this is the DomainCombiner may
     * create new instances of ProtectionDomain's from those that exist on
     * the stack.
     *
     * @see java.security.AccessControlContext
     * @see java.security.DomainCombiner
     * @see javax.security.auth.SubjectDomainCombiner
     */
    public static final int PROTECTIONDOMAIN = 1;
    /**
     * The PermissionGrant generated will apply to all classes loaded from
     * CodeSource's that have at a minimum the defined array Certificate[]
     */
    public static final int CODESOURCE_CERTS = 2;
    /**
     * The PermissionGrant generated will apply to the Subject that has
     * all the principals provided.
     *
     * @see javax.security.auth.Subject
     */
    public static final int PRINCIPAL = 3;

    /**
     * The PermissionGrant generated will apply to the ProtectionDomain or
     * CodeSource who's URL is implied by the given URI.  This behaves
     * similarly to CodeSource.implies(CodeSource), except no DNS lookup is
     * performed, nor file system access to verify the file exists.
     *
     * The DNS lookup is avoided for security and performance reasons,
     * DNS is not authenticated and therefore cannot be trusted.  Doing so,
     * could allow an attacker to use DNS Cache poisoning to escalate
     * Permission, by imitating a URL with greater privileges.
     */
    public static final int URI = 4;

    public static PermissionGrantBuilder newBuilder()
    {
        return new PermissionGrantBuilderImp();
    }

    /**
     * resets the state for reuse, identical to a newly created
     * PermissionGrantBuilder.
     */
    public abstract PermissionGrantBuilder reset();

    /**
     * Sets the context of the PermissionGrant to on of the static final
     * fields in this class.
     *
     * @return PermissionGrantBuilder
     *
     * @throws IllegalStateException
     */
    public abstract PermissionGrantBuilder context( int context )
        throws IllegalStateException;

    public abstract PermissionGrantBuilder uri( URI uri );

    /**
     * Extracts ProtectionDomain
     * from the Class for use in the PermissionGrantBuilder.  The ClassLoader
     * and ProtectionDomain are weakly referenced, when collected any
     * created PermissionGrant affected will be voided.
     *
     * @return PermissionGrantBuilder.
     *
     */
    public abstract PermissionGrantBuilder clazz( Class cl );

    /**
     * Sets the Certificate[] a CodeSource must have to receive the PermissionGrant.
     *
     */
    public abstract PermissionGrantBuilder certificates( Certificate[] certs );

    /**
     * Sets the Principal[] that a Subject must have to be entitled to receive
     * the PermissionGrant.
     *
     */
    public abstract PermissionGrantBuilder principals( Principal[] pals );

    /**
     * Sets the Permission's that will be granted.
     *
     */

    public abstract PermissionGrantBuilder permissions( Permission[] perm );

    /**
     * Build the PermissionGrant using information supplied.
     *
     * @return an appropriate PermissionGrant.
     */
    public abstract PermissionGrant build();

    public abstract PermissionGrantBuilder setDomain( WeakReference<ProtectionDomain> domain );
}
