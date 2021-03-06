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

import java.util.Properties;
import org.hedhman.blackadder.expander.ExpansionFailedException;
import org.junit.Before;
import org.junit.Test;

/**
 *
 *
 */
public class SegmentTest
{
    Properties p;

    public SegmentTest()
    {
    }

    @Before
    public void setup()
    {
        p = System.getProperties();
        p.setProperty( "java.ext.dirs", "tests:foo:bar:${jini.home}" );
        p.setProperty( "jini.home", "${river.apache.org}" );
        p.setProperty( "river.apache.org", "/opt/src/river" );
    }

    @Test
    public void divideAndReplace()
        throws ExpansionFailedException
    {
        System.out.println( "Test divideAndReplace" );
        System.out.println( p.toString() );
        String policyGrantln = "file:${{java.ext.dirs}}/*";
        System.out.println( policyGrantln );
        Segment seg = new Segment( policyGrantln, null, System.getProperties() );
        String startMark = "${{";
        String endMark = "}}";
        seg.divideAndReplace( startMark, endMark, ":" );
        while( seg.hasNext() )
        {
            System.out.println( seg.next() );
        }
    }

    @Test
    public void divideAndReplaceTwice()
        throws ExpansionFailedException
    {
        System.out.println( "Test nested divideAndReplace" );
        System.out.println( p.toString() );
        String policyGrantln = "file:${{java.ext.dirs}}/*";
        System.out.println( policyGrantln );
        Segment seg = new Segment( policyGrantln, null, System.getProperties() );
        String startMark = "${{";
        String endMark = "}}";
        seg.divideAndReplace( startMark, endMark, ":" );
        seg.divideAndReplace( "${", "}", null );
        while( seg.hasNext() )
        {
            System.out.println( seg.next() );
        }
    }

    @Test
    public void divideAndReplaceThrice()
        throws ExpansionFailedException
    {
        System.out.println( "Test duplicate nested divideAndReplace" );
        System.out.println( p.toString() );
        String policyGrantln = "file:${{java.ext.dirs}}/*";
        System.out.println( policyGrantln );
        Segment seg = new Segment( policyGrantln, null, System.getProperties() );
        String startMark = "${{";
        String endMark = "}}";
        seg.divideAndReplace( startMark, endMark, ":" );
        seg.divideAndReplace( "${", "}", null );
        seg.divideAndReplace( "${", "}", null );
        while( seg.hasNext() )
        {
            System.out.println( seg.next() );
        }
    }

    @Test
    public void divideAndReplaceNoArray()
        throws ExpansionFailedException
    {
        System.out.println( "Test divideAndReplace" );
        System.out.println( p.toString() );
        String policyGrantln = "file:${jini.home}/*";
        System.out.println( policyGrantln );
        Segment seg = new Segment( policyGrantln, null, System.getProperties() );
        String startMark = "${";
        String endMark = "}";
        seg.divideAndReplace( startMark, endMark, null );
        while( seg.hasNext() )
        {
            System.out.println( seg.next() );
        }
    }
}
