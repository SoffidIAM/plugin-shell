package com.soffid.iam.sync.agent.test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.LoggerFactory;

import com.jcraft.jsch.JSchException;
import com.soffid.iam.sync.agent.ShellTunnel;
import com.soffid.iam.sync.agent.SshConnection;

import es.caib.seycon.ng.comu.Password;
import junit.framework.TestCase;

public class ShellTest extends TestCase {

	
	public void testRegExp ()
	{
		Pattern.compile("[a-z]+");
		Pattern p = Pattern.compile("[a-zA-Z0-9\\.]+");
		String s = "\rTest# ";
		assertTrue(s.matches("\\r[a-zA-Z0-9\\.]+# "));
		String text = "show run user\r\nusername admin password IXKiIgK5CoIah80o encrypted privilege 15\r\n"
				+ "username Soffid password 1jUfcuR.4.NGMIlK encrypted privilege 3\r\n"
				+ "username Soffid attributes\r\n"
				+ " service-type nas-prompt\r\n";
		
		System.out.println ("Finding on "+text);
		Pattern pattern = Pattern.compile("username ([^ ]+) password.*privilege (\\d+)$");
		pattern = Pattern.compile("username ([^ ]+) password.* (\\d+)$");
		Matcher matcher = pattern.matcher(text);
		while (matcher.find())
		{
			System.out.println ("Found on position "+matcher.start());
			int count = matcher.groupCount();
			String row [] = new String[count+1];
			for (int i = 0; i <= count; i++)
				System.out.println (" Region "+i+" = "+matcher.group(i));
		}


	}
	
	public void test1 () throws IOException 
	{
		ShellTunnel t = new ShellTunnel("/bin/bash", true, "EOF");
		t.setLog(LoggerFactory.getLogger(getClass()));
		t.setDebug(true);
		
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
	
	void dumpThreads ()
	{
		System.out.println("THREADS");
		System.out.println("------------------------------");
		Map<Thread, StackTraceElement[]> st = Thread.getAllStackTraces();
		for (Thread t: st.keySet())
		{
			StackTraceElement[] te = st.get(t);
			System.out.println(t.toString());
			if (te.length > 0)
				System.out.println("  >> "+te[0].toString());
		}
	}
	
	public void test2 () throws IOException, JSchException, InterruptedException 
	{
		Password p = null;
		p = new Password("geheim01");
		if (p != null)
		{
			dumpThreads();
			SshConnection t = new SshConnection("forge.dev.lab", "bbuades", "/home/gbuades/.ssh/id_dsa", p, "pwd");
			t.close();
			dumpThreads();
		}
	}
}
