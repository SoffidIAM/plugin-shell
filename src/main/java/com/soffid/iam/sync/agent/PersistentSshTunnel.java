package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import org.slf4j.Logger;

import com.jcraft.jsch.JSchException;
import com.soffid.iam.sync.agent.shell.AbstractTunnel;
import com.soffid.iam.sync.agent.shell.ConsumeInputThread;
import com.soffid.iam.sync.agent.shell.ExitOnPromptInputStream;

import es.caib.seycon.ng.comu.Password;

public class PersistentSshTunnel implements AbstractTunnel {
	
	protected ConsumeInputThread inputThread;
	protected Object notifier;
	protected boolean debug = false;
	
	public boolean isDebug() {
		return debug;
	}
	
	public void onConnect () throws UnsupportedEncodingException, IOException
	{
		
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	protected String host;
	protected String user;
	protected Password password;
	protected String keyFile;
	protected String prompt;
	protected SshConnection connection = null;

	private void init () throws IOException, JSchException
	{
	}
	
	public void close ()
	{
		if (connection != null)
			connection.close();
		connection = null;
		
	}

	public PersistentSshTunnel(String host, String user, String keyFile, Password password, String prompt) throws JSchException, IOException {
		this.host = host;
		this.user = user;
		this.keyFile = keyFile;
		this.password = password;
		this.prompt = prompt;
		init ();
	}


	Logger log;
	
	public InputStream execute (String cmd) throws IOException, JSchException
	{
		if ( connection == null || connection.isEof())
		{
			if (debug)
				log.info ("Opening remote shell");
			connection = new SshConnection(host, user, keyFile, password);
			notifier = new Object ();
			inputThread = new ConsumeInputThread (connection.getInputStream(), this.prompt, notifier, Charset.defaultCharset().name());
			if (debug)
			{
				inputThread.setDebug(true);
				inputThread.setLog(log);
			}
			inputThread.start ();
			onConnect ();
		}
		if (debug)
			log.info ("Sending: "+cmd);
		connection.getOutputStream().write(cmd.getBytes());
		connection.getOutputStream().write('\n');
		connection.getOutputStream().flush();
		return new ExitOnPromptInputStream (inputThread, null, notifier, this, true, debug, log);
	}

	public void closeShell() {
		inputThread.finish();
		connection = null;
	}

	public void setLog(Logger log) {
		this.log = log;
		
	}

	public void idle() {
		// TODO Auto-generated method stub
	}
}
