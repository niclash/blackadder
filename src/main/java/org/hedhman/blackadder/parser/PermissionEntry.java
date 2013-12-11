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
 * Compound token representing <i>permission </i> entry of a <i>grant </i>
 * clause. See policy format
 * {@code org.apache.river.api.security.ConcurrentPolicyFile } description for details.
 *
 * @see DefaultPolicyParser
 * @see DefaultPolicyScanner
 */
class PermissionEntry
{

    /**
     * The classname part of permission clause.
     */
    private final String klass;

    /**
     * The name part of permission clause.
     */
    private final String name;

    /**
     * The actions part of permission clause.
     */
    private final String actions;

    /**
     * The signers part of permission clause. This is a comma-separated list
     * of certificate aliases.
     */
    private final String signers;

    PermissionEntry( String klass, String name, String actions, String signers )
    {
        if( klass == null )
        {
            throw new NullPointerException();
        }
        this.klass = klass;
        this.name = name == null ? "" : name;
        this.actions = actions == null ? "" : actions;
        this.signers = signers;
    }

    public String toString()
    {
        String endline = "\n";
        int l = getKlass() == null ? 0 : getKlass().length();
        l = l + ( getName() == null ? 0 : getName().length() );
        l = l + ( getActions() == null ? 0 : getActions().length() );
        l = l + ( getSigners() == null ? 0 : getSigners().length() );
        l = l + 8;
        StringBuilder sb = new StringBuilder( l );
        if( getKlass() != null )
        {
            sb.append( getKlass() ).append( endline );
        }
        if( getName() != null )
        {
            sb.append( getName() ).append( endline );
        }
        if( getActions() != null )
        {
            sb.append( getActions() ).append( endline );
        }
        if( getSigners() != null )
        {
            sb.append( getSigners() ).append( endline );
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

    /**
     * @return the actions
     */
    String getActions()
    {
        return actions;
    }

    /**
     * @return the signers
     */
    String getSigners()
    {
        return signers;
    }
}
