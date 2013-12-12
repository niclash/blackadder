package org.hedhman.blackadder.expander;

/**
 * Instances of this interface are intended for resolving
 * generalized expansion expressions, of the form ${{protocol:data}}.
 * Such functionality is applicable to security policy files, for example.
 * @see PropertyExpander#expandGeneral(String, GeneralExpansionHandler)
 */
public interface GeneralExpansionHandler
{

    /**
     * Resolves general expansion expressions of the form ${{protocol:data}}.
     *
     * @param protocol denotes type of resolution
     * @param data     data to be resolved, optional (may be null)
     *
     * @return resolved value, must not be null
     *
     * @throws ExpansionFailedException if expansion is impossible
     */
    String resolve( String protocol, String data )
        throws ExpansionFailedException;
}
