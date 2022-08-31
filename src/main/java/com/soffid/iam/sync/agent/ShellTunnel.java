package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;

import com.soffid.iam.sync.agent.shell.AbstractTunnel;
import com.soffid.iam.sync.agent.shell.ConsumeErrorThread;
import com.soffid.iam.sync.agent.shell.ConsumeInputThread;
import com.soffid.iam.sync.agent.shell.ExitOnPromptInputStream;

public class ShellTunnel implements AbstractTunnel {
	
	static Thread timeoutThread = null;
	static List<ShellTunnel> tunnels = new LinkedList<ShellTunnel>();
	
	String shell;
	boolean persistent;
	String prompt;
	
	private Long idleTimeout;
	
	Process process = null;
	private ConsumeInputThread inputThread;
	private ConsumeErrorThread errorThread;
	private Object notifier;
	private boolean debug = false;
	private boolean closed = false;
	
	public boolean isClosed() {
		return closed;
	}

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public ShellTunnel (String shell, boolean persistent, String prompt)
	{
		this.shell = shell;
		this.persistent = persistent;
		this.prompt = prompt;
	}

	Logger log;
	private long timeout;
	private String exitCommand;
	private String encoding;
	private String restartWord;
	private long expiration = 0;
	private String name;
	
	public String toString() {
		return "Tunnel "+ hashCode() +": "+name;
	}
	
	public ExitOnPromptInputStream execute (String cmd) throws IOException
	{
		name = ("Executing "+cmd);
		if (encoding == null)
		{
			setEncoding( Charset.defaultCharset().name() );
		}
		
		if (expiration > 0 && System.currentTimeMillis() > expiration && persistent && process != null) {
			log.info("Closing expired shell");
			process.getOutputStream().close();
			process.getInputStream().close();
			process.getErrorStream().close();
			process.destroyForcibly();
			process = null;
		}
		
		if (shell == null || shell.trim().length() == 0)
		{
			process = Runtime.getRuntime().exec(split(cmd)) ;
			if (debug)
				log.info ("EXECUTING PROCESS: "+cmd);
			process.getOutputStream().close();
			notifier = new Object ();
			inputThread = new ConsumeInputThread (process.getInputStream(), prompt, notifier, encoding);
			if (debug)
			{
				inputThread.setDebug(true);
				inputThread.setLog(log);
			}
			errorThread = new ConsumeErrorThread (process.getErrorStream(), notifier, encoding);
			if (debug)
			{
				errorThread.setDebug(true);
				errorThread.setLog(log);
			}
			inputThread.start ();
			errorThread.start();
		}
		else if (! persistent || process == null)
		{
			if (debug)
				log.info ("Executing shell: "+shell);
			process = File.separatorChar == '\\' ? Runtime.getRuntime().exec(splitCmdLine(shell)) : Runtime.getRuntime().exec(shell) ;
			notifier = new Object ();
			inputThread = new ConsumeInputThread (process.getInputStream(), prompt, notifier, encoding);
			if (debug)
			{
				inputThread.setDebug(true);
				inputThread.setLog(log);
			}
			errorThread = new ConsumeErrorThread (process.getErrorStream(), notifier, encoding);
			if (debug)
			{
				errorThread.setDebug(true);
				errorThread.setLog(log);
			}
			inputThread.start ();
			errorThread.start();
			closed = false;
			startTimeoutThread ();
		}
		if (shell != null && shell.trim().length() > 0)
		{
			if (debug)
				log.info ("Sending: ["+encoding+"]"+cmd);
			process.getOutputStream().write(cmd.getBytes(encoding));
			process.getOutputStream().write('\n');
			process.getOutputStream().flush();
			if (!persistent)
				process.getOutputStream().close();
			idle();
//			idleTimeout = null;
		}
		return new ExitOnPromptInputStream (inputThread, errorThread, notifier, this, persistent, debug, log);
	}

	private String[] splitCmdLine(String shell2) {
		List<String> s = new LinkedList<String>();
		boolean quote = false;
		String last = "";
		for (int i = 0; i < shell2.length(); i++) {
			char ch = shell2.charAt(i);
			if (ch == '\"') {
				quote = ! quote;
			}
			if (ch != ' ' || quote)
				last += ch;
			else {
				if (!last.isEmpty())
				s.add(last);
				last = "";
			}
		}
		if (last.length() > 0)
			s.add(last);
		
		return s.toArray(new String[s.size()]);
	}

	private String[] split(String cmd) {
		StringBuffer sb = new StringBuffer ();
		List<String> cmds = new LinkedList<String>();
		boolean openQuote = false;
		boolean openTilde = false;
		boolean openEscape = false;
		boolean empty = true;
		for (char ch: cmd.toCharArray())
		{
			if (openEscape)
			{
				sb.append(ch);
				openEscape = false;
			}
			else if (openTilde)
			{
				if (ch == '\'')
					openTilde = false;
				else
					sb.append(ch);
			}
			else if (openQuote)
			{
				if (ch == '\"')
					openQuote = false;
				else if (ch == '\\')
					openEscape = true;
				else
					sb.append(ch);
			}
			else switch ( ch)
			{
			case '\'':
				openTilde = true;
				empty = false;
				break;
			case '\"':
				openQuote = true;
				empty = false;
				break;				
			case '\\':
				openEscape = true;
				break;
			case ' ':
				if (! empty || sb.length() > 0)
				{
					cmds.add (sb.toString());
				}
				sb = new StringBuffer();
				empty = true;
				break;
			default:
				sb.append(ch);
			}
		}
		if (! empty || sb.length() > 0)
		{
			cmds.add (sb.toString());
		}
		return cmds.toArray(new String[cmds.size()]);
	}

	private void startTimeoutThread() {
		if (timeoutThread == null)
		{
			log.info("Creating timeout thread");
			timeoutThread = new Thread ( new Runnable() {
				
				public void run() {
					try {
						log.info("Timeout thread started");
						while (true)
						{
							synchronized (tunnels) {
								log.info("Cleaning unused threads");
								for (ShellTunnel st: new LinkedList<ShellTunnel>(tunnels))
								{
									if (st.isClosed())
									{
										log.info("Shell "+st.toString()+" is closed");
										tunnels.remove(st);
									}
									else
										st.checkTimeout();
								}
							}
							Thread.sleep(60000);
						}
					} catch (InterruptedException e) {
					} catch (Throwable e) {
						log.info("Error processing timeout thread", e);
					} finally {
						log.info("Timeout thread is finished");
						timeoutThread = null;
					}
				}
			});
			timeoutThread.setName("Shell timeout detector");
			timeoutThread.start();
		}
		synchronized (tunnels)
		{
			tunnels.add(this);
		}
	}

	public long getTimeout() {
		return timeout;
	}

	public String getExitCommand() {
		return exitCommand;
	}

	public void closeShell() {
		synchronized (tunnels)
		{
			tunnels.remove(this);
		}
		if (exitCommand != null)
		{
			try {
				process.getOutputStream().write(exitCommand.getBytes(encoding));
				process.getOutputStream().write('\n');
				process.getOutputStream().flush();
			} catch (IOException e) {
			}
		}
		try {
			process.getOutputStream().close();
		} catch (IOException e) {
		}
		process.destroy();
		inputThread.finish();
		errorThread.finish();
		process = null;
		closed = true;
	}

	public void setLog(Logger log) {
		this.log = log;
		
	}

	public void setExitCommand(String exitCommand) {
		this.exitCommand = exitCommand;
		
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	
	public void checkTimeout ()
	{
		if (idleTimeout != null && idleTimeout.longValue() < System.currentTimeMillis())
		{
			if (debug)
			{
				log.warn("Timeout detected for shell tunnel "+toString());
			}
			closeShell();
		}
		else if (idleTimeout == null)
			log.info("Tunnel "+toString()+" has no timeout");
		else
			log.info("Tunnel "+toString()+" is still alive ["+new Date(idleTimeout)+" vs "+new Date()+"]");
	}
	
	public void idle ()
	{
		if (timeout > 0)
			idleTimeout = new Long(System.currentTimeMillis() + timeout);
	}

	public void setEncoding(String string) {
		log.info("Setting encoding "+string);
		this.encoding = string;
		
	}

	public void setRestartWord(String word)
	{
		this.restartWord = word;
		if (errorThread != null)
			errorThread.setRestartWord(word);
		if (inputThread != null)
			inputThread.setRestartWord(word);
	}

	public void setMaxDuration(long d) {
		expiration  = System.currentTimeMillis() + d;
	}
}
