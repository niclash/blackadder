package org.hedhman.blackadder.parser;

import java.net.URI;
import java.net.URL;
import java.security.PrivilegedExceptionAction;

class NormaliseURLAction
    implements PrivilegedExceptionAction<URI>
{
    private final URL codesource;

    NormaliseURLAction( URL codebase )
    {
        codesource = codebase;
    }

    @Override
    public URI run()
        throws Exception
    {
        return PolicyUtils.normalizeURL( codesource );
    }
}
