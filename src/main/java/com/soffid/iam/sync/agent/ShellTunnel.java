package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

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
	
	public ExitOnPromptInputStream execute (String cmd) throws IOException
	{
		if (shell == null || shell.trim().length() == 0)
		{
			process  = Runtime.getRuntime().exec(cmd);
			if (debug)
				log.info ("Executing process: "+cmd);
			process.getOutputStream().close();
			notifier = new Object ();
			inputThread = new ConsumeInputThread (process.getInputStream(), prompt, notifier);
			if (debug)
			{
				inputThread.setDebug(true);
				inputThread.setLog(log);
			}
			errorThread = new ConsumeErrorThread (process.getErrorStream(), notifier);
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
				log.info ("Executing process: "+shell);
			process = Runtime.getRuntime().exec(shell);
			notifier = new Object ();
			inputThread = new ConsumeInputThread (process.getInputStream(), prompt, notifier);
			if (debug)
			{
				inputThread.setDebug(true);
				inputThread.setLog(log);
			}
			errorThread = new ConsumeErrorThread (process.getErrorStream(), notifier);
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
				log.info ("Sending: "+cmd);
			process.getOutputStream().write(cmd.getBytes());
			process.getOutputStream().write('\n');
			process.getOutputStream().flush();
			if (!persistent)
				process.getOutputStream().close();
			idleTimeout = null;
		}
		return new ExitOnPromptInputStream (inputThread, errorThread, notifier, this, persistent, debug, log);
	}

	private void startTimeoutThread() {
		if (timeoutThread == null)
		{
			timeoutThread = new Thread ( new Runnable() {
				
				public void run() {
					try {
						while (true)
						{
							synchronized (tunnels) {
								for (Iterator<ShellTunnel> it = tunnels.iterator();
										it.hasNext();)
								{
									ShellTunnel st = it.next();
									if (st.isClosed())
										it.remove();
									else
										st.checkTimeout();
								}
							}
							Thread.sleep(1000);
						}
					} catch (InterruptedException e) {
					}
					
				}
			});
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
				process.getOutputStream().write(exitCommand.getBytes());
				process.getOutputStream().write('\n');
				process.getOutputStream().flush();
			} catch (IOException e) {
			}
		}
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
				log.info("Auto closing tunnel");
			}
			closeShell();
		}
	}
	
	public void idle ()
	{
		if (timeout > 0)
			idleTimeout = new Long(System.currentTimeMillis() + timeout);
	}
 }
