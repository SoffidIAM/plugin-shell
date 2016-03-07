package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;

import com.soffid.iam.sync.agent.shell.ConsumeErrorThread;
import com.soffid.iam.sync.agent.shell.ConsumeInputThread;
import com.soffid.iam.sync.agent.shell.ExitOnPromptInputStream;

public class ShellTunnel {
	
	String shell;
	boolean persistent;
	String prompt;
	
	Process process = null;
	private ConsumeInputThread inputThread;
	private ConsumeErrorThread errorThread;
	private Object notifier;
	private boolean debug = false;
	
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
	
	public InputStream execute (String cmd) throws IOException
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
		}
		return new ExitOnPromptInputStream (inputThread, errorThread, notifier, this, persistent, debug, log);
	}

	public void closeShell() {
		inputThread.finish();
		errorThread.finish();
		process = null;
	}

	public void setLog(Logger log) {
		this.log = log;
		
	}
}
