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
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.security.SecurityPermission;
import java.security.UnresolvedPermission;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Properties;
import junit.framework.TestCase;
import org.hedhman.blackadder.expander.ExpansionFailedException;
import org.hedhman.blackadder.expander.GeneralExpansionHandler;
import org.hedhman.blackadder.expander.PropertyExpander;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Tests for <code>PolicyUtils</code> class fields and methods.
 */

public class PolicyUtilsTest extends TestCase
{
    private static Properties system;

    @BeforeClass
    public static void setUpClass()
        throws Exception
    {
        system = new Properties( System.getProperties() );
    }

    @AfterClass
    public static void tearDownClass()
        throws Exception
    {
        System.setProperties( system );
        system = null;
    }
//       @Before
//    public void setUp() {
//           system = new Properties(System.getProperties());
//    }
//    
//    @After
//    public void tearDown() {
//        System.setProperties(system);
//        system = null;
//    }

    /**
     * Tests valid expansion of ${key} entries.
     */
    public void testExpand()
        throws Exception
    {
        String[] input = new String[]{
            "${key.1}", "abcd${key.1}",
            "a ${key.1} b ${$key$}${key.2}", "$key.1", "${}"
        };
        String[] output = new String[]{
            "value1", "abcdvalue1",
            "a value1 b ${${${${${${value.2", "$key.1", ""
        };
        Properties props = new Properties();
        props.put( "key.1", "value1" );
        props.put( "key.2", "value.2" );
        props.put( "$key$", "${${${${${${" );
        props.put( "", "" );
        PropertyExpander propertyExpander = new PropertyExpander( props );
        for( int i = 0; i < output.length; i++ )
        {
            assertEquals( output[ i ], propertyExpander.expand( input[ i ] ) );
        }
    }

    /**
     * Tests ExpansionFailedException for missing keys of ${key} entries.
     */
    public void testExpandFailed()
        throws Exception
    {
        try
        {
            PropertyExpander propertyExpander = new PropertyExpander( new Properties() );
            propertyExpander.expand( "${key.123}" );
            fail( "Should throw ExpansionFailedException" );
        }
        catch( ExpansionFailedException ok )
        {
        }
    }

    /**
     * Tests valid URL-specific expansion.
     */
    public void testExpandURL()
        throws Exception
    {
        String input = "file:/${my.home}" + File.separator + "lib/extensions/";
        Properties props = new Properties();
        String q = File.separator + "drl" + File.separator + "tools1.2";
        props.put( "my.home", q );
        PropertyExpander propertyExpander = new PropertyExpander( props );
        assertEquals( "file://drl/tools1.2/lib/extensions/", propertyExpander.expandURL( input ) );
    }

    /**
     * Tests valid expansion of ${{protocol:data}} entries.
     */
    public void testExpandGeneral()
        throws Exception
    {
        String[] input = new String[]{
            "${{a:b}}", "a ${{self}}${{a: made}}",
            "${{}}"
        };
        String[] output = new String[]{ "b", "a this made", "" };
        GeneralExpansionHandler handler = new GeneralExpansionHandler()
        {

            public String resolve( String protocol, String data )
            {
                if( "a".equals( protocol ) )
                {
                    return data;
                }
                if( "self".equals( protocol ) )
                {
                    return "this";
                }
                if( "".equals( protocol ) )
                {
                    return protocol;
                }
                return null;
            }
        };
        PropertyExpander propertyExpander = new PropertyExpander();
        for( int i = 0; i < output.length; i++ )
        {
            assertEquals( output[ i ], propertyExpander.expandGeneral( input[ i ], handler ) );
        }
    }

    /**
     * Tests ExpansionFailedException for undefined protocol
     * of ${{protocol:data}} entries.
     */
    public void testExpandGeneralFailed()
        throws Exception
    {
        try
        {
            PropertyExpander propertyExpander = new PropertyExpander();
            propertyExpander.expandGeneral( "${{c}}",
                                            new GeneralExpansionHandler()
                                            {

                                                public String resolve( String protocol, String data )
                                                    throws ExpansionFailedException
                                                {
                                                    throw new ExpansionFailedException( "" );
                                                }
                                            } );
            fail( "Should throw ExpansionFailedException" );
        }
        catch( ExpansionFailedException ok )
        {
        }
    }

    /**
     * Tests positive/negative/invalid/missing values of
     * &quot;policy.expandProperties&quot; security property.
     */
    public void testCanExpandProperties()
    {
        PropertyExpander propertyExpander = new PropertyExpander();
        final String key = "policy.expandProperties";
        String OLD = Security.getProperty( key );
        try
        {
            Security.setProperty( key, "true" );
            assertTrue( propertyExpander.canExpandProperties() );
            Security.setProperty( key, "false" );
            assertFalse( propertyExpander.canExpandProperties() );
            Security.setProperty( key, "" );
            assertTrue( propertyExpander.canExpandProperties() );
            Security.setProperty( key, "laejhg" );
            assertTrue( propertyExpander.canExpandProperties() );
        }
        finally
        {
            Security.setProperty( key, OLD );
        }
    }

    /**
     * Tests conversion of null, empty and non-empty heterogeneous collections.
     */
    public void testToPermissionCollection()
    {
        Permission p1 = new SecurityPermission( "abc" );
        Permission p2 = new AllPermission();
        Collection<Permission> c1 = Arrays.asList( p1, p2 );

        PermissionCollection pc = PolicyUtils.toPermissionCollection( null );
        assertNotNull( pc );
        assertFalse( pc.elements().hasMoreElements() );

        pc = PolicyUtils.toPermissionCollection( Collections.<Permission>emptySet() );
        assertNotNull( pc );
        assertFalse( pc.elements().hasMoreElements() );

        pc = PolicyUtils.toPermissionCollection( c1 );
        assertNotNull( pc );
        Collection<Permission> c2 = new HashSet<Permission>();
        Enumeration<Permission> en = pc.elements();
        while( en.hasMoreElements() )
        {
            c2.add( en.nextElement() );
        }
        assertFalse( en.hasMoreElements() );
        assertTrue( c2.contains( p1 ) );
        assertTrue( c2.contains( p2 ) );
    }

    public void testInstantiatePermission()
        throws Throwable
    {
        String name = "abc";
        Permission expected = new SecurityPermission( name );
        //test valid input
        assertEquals( expected, PolicyUtils.instantiatePermission( SecurityPermission.class, name, null ) );
        assertEquals( expected, PolicyUtils.instantiatePermission( SecurityPermission.class, name, "4t46" ) );

        //test invalid class
        try
        {
            PolicyUtils.instantiatePermission( UnresolvedPermission.class, null, null );
            fail( "IllegalArgumentException expected on invalid class argument" );
        }
        catch( IllegalArgumentException ok )
        {
        }
    }

    /**
     * Tests various combinations of arrays:
     * null/empty/containing null/containing real objects.
     */
    public void testMatchSubset()
    {
        assertTrue( PolicyUtils.matchSubset( null, null ) );
        assertTrue( PolicyUtils.matchSubset( new Object[]{ }, null ) );
        assertTrue( PolicyUtils.matchSubset( new Object[]{ null }, null ) );
        assertTrue( PolicyUtils.matchSubset( new Object[]{ },
                                             new Object[]{ null } ) );
        assertTrue( PolicyUtils.matchSubset( new Object[]{ "1", "2" },
                                             new Object[]{ "3", "2", "1" } ) );
        assertTrue( PolicyUtils.matchSubset( new Object[]{ "1", null },
                                             new Object[]{ "3", "2", "1" } ) );
        assertFalse( PolicyUtils.matchSubset( new Object[]{ "1", null },
                                              new Object[]{ "3", "2", } ) );
    }
}
