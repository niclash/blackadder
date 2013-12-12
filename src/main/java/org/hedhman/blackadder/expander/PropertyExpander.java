package org.hedhman.blackadder.expander;

import java.io.File;
import java.security.AccessController;
import java.util.Properties;
import org.hedhman.blackadder.parser.Constants;
import org.hedhman.blackadder.parser.PolicyUtils;
import org.hedhman.blackadder.parser.SecurityPropertyAccessor;

public class PropertyExpander
    implements Constants
{
    private final Properties properties;

    /**
     * System properties will be used for the property expansion.
     */
    public PropertyExpander()
    {
        this( System.getProperties() );
    }

    /**
     * @param properties available key-value mappings
     */
    public PropertyExpander( Properties properties )
    {
        this.properties = properties;
    }

    /**
     * Substitutes all entries like ${some.key}, found in specified string,
     * for specified values.
     * If some key is unknown, throws ExpansionFailedException.
     *
     * @param str the string to be expanded
     *
     * @return expanded string
     *
     * @throws ExpansionFailedException
     */
    public String expand( String str )
        throws ExpansionFailedException
    {
        if( str == null )
        {
            return null;
        }

        final String START_MARK = "${";
        final String END_MARK = "}";
        final int START_OFFSET = START_MARK.length();
        final int END_OFFSET = END_MARK.length();

        StringBuilder result = new StringBuilder( str );
        int start = result.indexOf( START_MARK );
        while( start >= 0 )
        {
            int end = result.indexOf( END_MARK, start );
            if( end >= 0 )
            {
                String key = result.substring( start + START_OFFSET, end );
                String value = properties.getProperty( key );
                if( value != null )
                {
                    result.replace( start, end + END_OFFSET, value );
                    start += value.length();
                }
                else
                {
                    throw new ExpansionFailedException( "Unknown key: " + key );
                }
            }
            start = result.indexOf( START_MARK, start );
        }
        return result.toString();
    }

    /**
     * Handy shortcut for
     * <code>expand(str, properties).replace(File.separatorChar, '/')</code>.
     *
     * @see #expand(String)
     */
    public String expandURL( String str )
        throws ExpansionFailedException
    {
        return expand( str ).replace( File.separatorChar, '/' );
    }

    /**
     * Substitutes all entries like ${{protocol:data}}, found in specified string,
     * for values resolved by passed handler.
     * The data part may be empty, and in this case expression
     * may have simplified form, as ${{protocol}}.
     * If some entry cannot be resolved, throws ExpansionFailedException;
     *
     * @param str     the string to be expanded
     * @param handler the handler to resolve data denoted by protocol
     *
     * @return expanded string
     *
     * @throws ExpansionFailedException
     */
    public String expandGeneral( String str, GeneralExpansionHandler handler )
        throws ExpansionFailedException
    {
        final String START_MARK = "${{";
        final String END_MARK = "}}";
        final int START_OFFSET = START_MARK.length();
        final int END_OFFSET = END_MARK.length();

        StringBuilder result = new StringBuilder( str );
        int start = result.indexOf( START_MARK );
        while( start >= 0 )
        {
            int end = result.indexOf( END_MARK, start );
            if( end >= 0 )
            {
                String key = result.substring( start + START_OFFSET, end );
                int separator = key.indexOf( ':' );
                String protocol = ( separator >= 0 ) ? key
                    .substring( 0, separator ) : key;
                String data = ( separator >= 0 ) ? key.substring( separator + 1 )
                                                 : null;
                String value = handler.resolve( protocol, data );
                result.replace( start, end + END_OFFSET, value );
                start += value.length();
            }
            start = result.indexOf( START_MARK, start );
        }
        return result.toString();
    }

    /**
     * Returns false if current security settings disable to perform
     * properties expansion, true otherwise.
     *
     * @see #expand(String)
     */
    public boolean canExpandProperties()
    {
        return !FALSE.equalsIgnoreCase(
            AccessController.doPrivileged( new SecurityPropertyAccessor( PolicyUtils.POLICY_EXPAND ) ) );
    }
}
