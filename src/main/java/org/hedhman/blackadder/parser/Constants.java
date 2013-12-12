package org.hedhman.blackadder.parser;

public interface Constants
{
    /**
     * A key to security properties, deciding whether usage of
     * dynamic policy location via system properties is allowed.
     *
     * @see org.hedhman.blackadder.ConcurrentPolicyFile#getPolicyURLs(String, String)
     */
    String POLICY_ALLOW_DYNAMIC = "policy.allowSystemProperty";

    /**
     * A key to security properties, deciding whether expansion of
     * system properties is allowed
     * (in security properties values, policy files, etc).
     *
     * @see org.hedhman.blackadder.expander.PropertyExpander#expand(String)
     */
    String POLICY_EXPAND = "policy.expandProperties";

    /**
     * Positive value of switching properties.
     */
//    static final String TRUE = "true";

    /**
     * Negative value of switching properties.
     */
    String FALSE = "false";

}
