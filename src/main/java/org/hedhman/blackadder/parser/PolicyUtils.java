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

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Collection;

/**
 * This class consist of a number of static methods, which provide a common functionality
 * for various policy and configuration providers.
 */
public class PolicyUtils
    implements Constants
{

    // No reason to instantiate
    private PolicyUtils()
    {
    }

    //  Segment has a bug where if the closing bracket is missing it gets caught
//  endlessly creating new Segments and calling them.
//    public static String expand(String str, Properties properties) throws ExpansionFailedException{
//        Segment s = new Segment(str, null);
//        for (int i = 0; i < 3; i++){ //nested properies 3 deep.
//            s.divideAndReplace("${", "}", null, properties);
//        }
//        s.hasNext(); // There will be at least one result
//        return s.next(); // Don't bother checking for more, not split into array.
//    }

    /**
     * Normalizes URLs to standard ones, eliminating pathname symbols.
     *
     * @param codebase -
     *                 the original URL.
     *
     * @return - the normalized URL.
     *
     * @throws java.net.URISyntaxException
     */
    static URI normalizeURL( URL codebase )
        throws URISyntaxException
    {
        if( codebase == null )
        {
            return null;
        }
        if( "file".equals( codebase.getProtocol() ) )
        {
            try
            {
                if( codebase.getHost().length() == 0 )
                {
                    String path = codebase.getFile();

                    if( path.length() == 0 )
                    {
                        // codebase is "file:"
                        path = "*";
                    }
                    return UriString.normalisation( filePathToURI( new File( path ).getAbsolutePath() ) );
                }
                else
                {
                    // codebase is "file://<smth>"
                    return UriString.normalisation( codebase.toURI() );
                }
            }
            catch( Exception e )
            {
                if( e instanceof SecurityException )
                {
                    throw (SecurityException) e;
                }
                // Ignore
            }
        }
        return UriString.normalisation( codebase.toURI() );
    }

    /**
     * Converts a file path to URI without accessing file system
     * (like {File#toURI()} does).
     *
     * @param path -
     *             file path.
     *
     * @return - the resulting URI.
     *
     * @throws java.net.URISyntaxException
     */
    static URI filePathToURI( String path )
        throws URISyntaxException
    {
        if( path == null )
        {
            throw new IllegalArgumentException( "File path is null." );
        }
        if( File.separatorChar == '\\' )
        {
            path = path.replace( File.separatorChar, '/' );
            path = path.toUpperCase();
        }
        if( !path.startsWith( "/" ) )
        {
            return new URI( "file", null, "/" + path, null, null );
        }
        return new URI( "file", null, path, null, null );
    }

    /**
     * Converts common-purpose collection of Permissions to PermissionCollection.
     *
     * @param perms a collection containing arbitrary permissions, may be null
     *
     * @return mutable heterogeneous PermissionCollection containing all Permissions
     * from the specified collection
     */
    static PermissionCollection toPermissionCollection( Collection<Permission> perms )
    {
        PermissionCollection pc = new Permissions();
        if( perms != null )
        {
            for( Permission element : perms )
            {
                pc.add( element );
            }
        }
        return pc;
    }

    // Empty set of arguments to default constructor of a Permission.
    private static final Class[] NO_ARGS = { };

    // One-arg set of arguments to default constructor of a Permission.
    private static final Class[] ONE_ARGS = { String.class };

    // Two-args set of arguments to default constructor of a Permission.
    private static final Class[] TWO_ARGS = { String.class, String.class };

    /**
     * Tries to find a suitable constructor and instantiate a new Permission
     * with specified parameters.
     *
     * @param targetType    class of expected Permission instance
     * @param targetName    name of expected Permission instance
     * @param targetActions actions of expected Permission instance
     *
     * @return a new Permission instance
     *
     * @throws IllegalArgumentException if no suitable constructor found
     */
    static Permission instantiatePermission( Class<?> targetType,
                                             String targetName, String targetActions
    )
        throws InstantiationException, IllegalAccessException,
               IllegalArgumentException, InvocationTargetException
    {

        // let's guess the best order for trying constructors
        Class[][] argTypes;
        Object[][] args;
        if( targetActions != null )
        {
            argTypes = new Class[][]{ TWO_ARGS, ONE_ARGS, NO_ARGS };
            args = new Object[][]{
                { targetName, targetActions },
                { targetName }, { }
            };
        }
        else if( targetName != null )
        {
            argTypes = new Class[][]{ ONE_ARGS, TWO_ARGS, NO_ARGS };
            args = new Object[][]{
                { targetName },
                { targetName, null }, { }
            };
        }
        else
        {
            argTypes = new Class[][]{ NO_ARGS, ONE_ARGS, TWO_ARGS };
            args = new Object[][]{
                { }, { null },
                { null, null }
            };
        }

        // finally try to instantiate actual permission
        for( int i = 0; i < argTypes.length; i++ )
        {
            try
            {
                Constructor<?> ctor = targetType.getConstructor( argTypes[ i ] );
                return (Permission) ctor.newInstance( args[ i ] );
            }
            catch( NoSuchMethodException ignore )
            {
            }
        }
        throw new IllegalArgumentException(
            "No suitable constructors found in permission class : " + targetType + ". Zero, one or two-argument constructor is expected" );
    }

    /**
     * Checks whether the objects from <code>what</code> array are all
     * presented in <code>where</code> array.
     *
     * @param what  first array, may be <code>null</code>
     * @param where second array, may be <code>null</code>
     *
     * @return <code>true</code> if the first array is <code>null</code>
     * or if each and every object (ignoring null values)
     * from the first array has a twin in the second array; <code>false</code> otherwise
     */
    public static boolean matchSubset( Object[] what, Object[] where )
    {
        if( what == null )
        {
            return true;
        }

        for( Object aWhat : what )
        {
            if( aWhat != null )
            {
                if( where == null )
                {
                    return false;
                }
                boolean found = false;
                for( Object clause : where )
                {
                    if( aWhat.equals( clause ) )
                    {
                        found = true;
                        break;
                    }
                }
                if( !found )
                {
                    return false;
                }
            }
        }
        return true;
    }
}
