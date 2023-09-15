package com.soffid.iam.sync.agent.shell;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;

import com.soffid.iam.config.Config;
import com.soffid.iam.sync.agent.ShellTunnel;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.pool.AbstractPool;

public class PowerShellTunnelPool extends AbstractPool<ShellTunnel> {
	String exitCommand;
	String shell;
	String prompt;
	long timeout;
	protected Logger log;
	protected boolean debugEnabled;
	protected boolean persistentShell;
	protected String initialCommand;
	protected String restartWord;

	@Override
	protected void closeConnection(ShellTunnel tunnel) throws Exception {
		tunnel.closeShell();
	}

	static int counter = 1;
	@Override
	protected ShellTunnel createConnection() throws Exception {
		ShellTunnel shellTunnel = new ShellTunnel(shell, persistentShell, prompt+"\r\n");
		shellTunnel.setDebug(debugEnabled);
		shellTunnel.setLog (log);
		shellTunnel.setEncoding("CP850");
		shellTunnel.setTimeout(timeout);  
		shellTunnel.setMaxDuration( 2 * 60 * 60 * 1000);
		shellTunnel.setExitCommand(exitCommand);
		shellTunnel.setRestartWord(restartWord);
		shellTunnel.idle();
		try {
			log.info("Initializing shell");
			int c;
			synchronized (this) {
				c = counter ++;
			}
			File tmpDir = new File( Config.getConfig().getHomeDir(), "tmp" );
			tmpDir = new File(tmpDir, "s-"+c);
			tmpDir.mkdirs();
			shellTunnel.setLabel("s-"+counter);
			shellTunnel.setTemp(tmpDir);
			log.info("Temporary dir "+tmpDir.getAbsolutePath());
			if (initialCommand != null &&
					!initialCommand.trim().isEmpty())
				shellTunnel.execute(initialCommand + "\n");
			shellTunnel.execute("$env:TMP='"+tmpDir.getAbsolutePath()+"'");
			InputStream in = shellTunnel.execute("function prompt{\"\"};  echo \""+prompt+"\"\r\n");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int b;
			while ((b = in.read()) >= 0) {
				System.out.write (b);
				out.write(b);
			}
			shellTunnel.idle();
		} catch (IOException e) {
			System.exit(1);
			throw new InternalErrorException ("Unable to open power shell");
			
		}
		return shellTunnel;
	}

	public String getExitCommand() {
		return exitCommand;
	}

	public void setExitCommand(String exitCommand) {
		this.exitCommand = exitCommand;
	}

	public String getShell() {
		return shell;
	}

	public void setShell(String shell) {
		this.shell = shell;
	}

	public String getPrompt() {
		return prompt;
	}

	public void setPrompt(String prompt) {
		this.prompt = prompt;
	}

	public long getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

	public Logger getLog() {
		return log;
	}

	public void setLog(Logger log) {
		this.log = log;
	}

	public boolean isDebugEnabled() {
		return debugEnabled;
	}

	public void setDebugEnabled(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
	}

	public boolean isPersistentShell() {
		return persistentShell;
	}

	public void setPersistentShell(boolean persistentShell) {
		this.persistentShell = persistentShell;
	}

	public String getInitialCommand() {
		return initialCommand;
	}

	public void setInitialCommand(String initialCommand) {
		this.initialCommand = initialCommand;
	}

	protected boolean isConnectionValid(ShellTunnel connection) throws Exception
	{
		return ! connection.isClosed();
	}

	public void setRestartWord(String string) {
		this.restartWord = string;
	}
}

