package com.soffid.iam.sync.agent.test;

import java.io.IOException;
import java.io.InputStream;

import net.sf.cglib.proxy.Enhancer;

import com.soffid.iam.sync.agent.ShellTunnel;

import junit.framework.TestCase;

public class ShellTest extends TestCase {

	public void test1 () throws IOException 
	{
		ShellTunnel t = new ShellTunnel("/bin/bash", true, "EOF");
		
		InputStream is = t.execute("find /tmp/.ICE-unix -print; printf EOF");
		int b;
		while ( (b = is.read()) > 0 )
		{
			System.out.write(b);
			System.out.flush();
		}
		System.out.println("END1");
		is = t.execute("find /tmp/.ICE-unix -print; printf EOF");
		while ( (b = is.read()) > 0 )
		{
			System.out.write(b);
			System.out.flush();
		}
		System.out.println("END2");
	}
	
}
