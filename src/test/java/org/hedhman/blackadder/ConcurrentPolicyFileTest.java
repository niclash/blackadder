package org.hedhman.blackadder;

import java.net.URL;
import java.security.Security;
import java.util.Properties;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ConcurrentPolicyFileTest
{
    /**
     * Tests cases of enabled/disabled system URL.
     */
    @Test
    public void testGetPolicyURLs01()
        throws Throwable
    {
        final String KEY_DYNAMIC = "policy.allowSystemProperty";
        String OLD_DYNAMIC = Security.getProperty( KEY_DYNAMIC );

        final String KEY = "dsfvdf";
        System.setProperty( KEY, "http://foo.bar.com" );
        try
        {
            Security.setProperty( KEY_DYNAMIC, "true" );
            URL[] result = ConcurrentPolicyFile.getPolicyURLs( KEY, "" );
            assertNotNull( result );
            assertEquals( 1, result.length );
            assertEquals( new URL( "http://foo.bar.com" ), result[ 0 ] );

            Security.setProperty( KEY_DYNAMIC, "false" );
            result = ConcurrentPolicyFile.getPolicyURLs( KEY, "" );
            assertNotNull( result );
            assertEquals( 0, result.length );

            Security.setProperty( KEY_DYNAMIC, "" );
            result = ConcurrentPolicyFile.getPolicyURLs( KEY, "" );
            assertNotNull( result );
            assertEquals( 1, result.length );
            assertEquals( new URL( "http://foo.bar.com" ), result[ 0 ] );
        }
        finally
        {
            Security.setProperty( KEY_DYNAMIC, OLD_DYNAMIC );
        }
    }

    /**
     * Tests finding algorithm for numbered locations in security properties.
     */
    @Test
    public void testGetPolicyURLs02()
        throws Throwable
    {
        final String PREFIX = "testGetPolicyURLs02.";
        String[] OLD = new String[ 5 ];
        for( int i = 0; i < OLD.length; i++ )
        {
            OLD[ i ] = Security.getProperty( PREFIX + i );
        }

        try
        {
            Security.setProperty( PREFIX + 0, "http://foo0.bar.com" );
            Security.setProperty( PREFIX + 1, "http://foo1.bar.com" );
            Security.setProperty( PREFIX + 2, "http://foo2.bar.com" );
            Security.setProperty( PREFIX + 4, "http://foo4.bar.com" );
            URL[] result = ConcurrentPolicyFile.getPolicyURLs( "abc", PREFIX );
            assertNotNull( result );
            assertEquals( 2, result.length );  //Fails, result contains "http://foo4.bar.com"
            for( URL out : result )
            {
                System.out.println( out.toString() );
            }
            assertEquals( new URL( "http://foo1.bar.com" ), result[ 0 ] );
            assertEquals( new URL( "http://foo2.bar.com" ), result[ 1 ] );

            Security.setProperty( PREFIX + 1, "slkjdfhk/svfv*&^" );
            Security.setProperty( PREFIX + 3, "dlkfjvb3lk5jt" );
            System.err.println( "The two malformed warnings below are expected." );
            result = ConcurrentPolicyFile.getPolicyURLs( "abc", PREFIX );
            assertNotNull( result );
            assertEquals( 2, result.length );
            assertEquals( new URL( "http://foo2.bar.com" ), result[ 0 ] );
            assertEquals( new URL( "http://foo4.bar.com" ), result[ 1 ] );
        }
        finally
        {
            for( int i = 0; i < OLD.length; i++ )
            {
                Security.setProperty( PREFIX + i, ( OLD[ i ] == null ) ? "" : OLD[ i ] );
            }
        }
    }

    /**
     * Tests expansion in system and security URLs.
     */
    @Test
    public void testGetPolicyURLs03()
        throws Throwable
    {
        final String KEY_DYNAMIC = "policy.allowSystemProperty";
        final String OLD_DYNAMIC = Security.getProperty( KEY_DYNAMIC );
        final String KEY_EXP = "policy.expandProperties";
        final String OLD_EXP = Security.getProperty( KEY_EXP );
        final String PREFIX = "testGetPolicyURLs03.";
        String[] OLD = new String[ 5 ];
        for( int i = 0; i < OLD.length; i++ )
        {
            OLD[ i ] = Security.getProperty( PREFIX + i );
        }

        final String KEY = "dsfvdf";
        Properties arg = System.getProperties();
        arg.put( KEY, "file://${foo.path}/${foo.name}" );
        arg.put( "foo.path", "path" );
        arg.put( "foo.name", "name" );
        arg.put( "foo", "acme" );
        Security.setProperty( KEY_DYNAMIC, "true" );
        Security.setProperty( KEY_EXP, "true" );
        Security.setProperty( PREFIX + 1, "http://foo0.${foo}.org" );
        Security.setProperty( PREFIX + 2, "http://${bar}.com" );
        Security.setProperty( PREFIX + 3,
                              "http://foo2.bar.com/${foo.path}/${foo.name}" );
        try
        {
            System.err.println( "The two \"Unknown key: bar\" below are expected." );
            URL[] result = ConcurrentPolicyFile.getPolicyURLs( KEY, PREFIX );
            assertNotNull( result );
            assertEquals( 3, result.length );
            assertEquals( new URL( "http://foo0.acme.org" ), result[ 0 ] );
            assertEquals( new URL( "http://foo2.bar.com/path/name" ), result[ 1 ] );
            assertEquals( new URL( "file://path/name" ), result[ 2 ] );

            //expansion here cannot be switched off
            Security.setProperty( KEY_EXP, "false" );
            result = ConcurrentPolicyFile.getPolicyURLs( KEY, PREFIX );
            assertNotNull( result );
            assertEquals( 3, result.length );
            assertEquals( new URL( "http://foo0.acme.org" ), result[ 0 ] );
            assertEquals( new URL( "http://foo2.bar.com/path/name" ), result[ 1 ] );
            assertEquals( new URL( "file://path/name" ), result[ 2 ] );
        }
        finally
        {
            Security.setProperty( KEY_DYNAMIC, OLD_DYNAMIC );
            Security.setProperty( KEY_EXP, OLD_EXP );
            for( int i = 0; i < OLD.length; i++ )
            {
                Security
                    .setProperty( PREFIX + i, ( OLD[ i ] == null ) ? "" : OLD[ i ] );
            }
        }
    }
}
