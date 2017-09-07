package com.soffid.iam.sync.agent;

import com.jcraft.jsch.*;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;

import java.io.*;

import org.slf4j.Logger;

public class SshConnection {
	
	private OutputStream outputStream;

	private String host;
	private String user;
	private Password password;
	private String channelName;
	private String cmdLine;
	private JSch jsch;
	private Session session;
	private Channel channel;
	private String keyFile;
	private InputStream inputStream;

	private boolean debug;

	private Logger log;

	private void init () throws IOException, JSchException
	{
		jsch = new JSch();
		if (keyFile != null && keyFile.trim().length() > 0)
			jsch.addIdentity(keyFile);
		
		String knownHosts = Config.getConfig().getHomeDir().getAbsolutePath()+File.separator+"conf"+File.separator+"known_hosts";
		
		File f = new File (knownHosts);
		if (!f.canRead())
			new FileOutputStream(f).close();
		
		jsch.setKnownHosts(knownHosts);
		session = jsch.getSession(user, host, 22);

		// username and password will be given via UserInfo interface.
		UserInfo ui = new MyUserInfo();
		session.setUserInfo(ui);
		session.connect();

		channel = session.openChannel(channelName);
		if (cmdLine != null)
			((ChannelExec) channel).setCommand(cmdLine);

		// get I/O streams for remote scp
		outputStream = channel.getOutputStream();
		inputStream = channel.getInputStream();

		channel.connect();

	}
	
	public void close ()
	{
		if (channel != null)
			channel.disconnect();
		if (session != null)
			session.disconnect();
		
	}
	/** 
	 * Interactive shell
	 * 
	 * @param host
	 * @param user
	 * @param password
	 * @throws JSchException
	 * @throws IOException
	 */
	public SshConnection(String host, String user, String keyFile, Password password) throws JSchException, IOException {
		this.host = host;
		this.user = user;
		this.keyFile = keyFile;
		this.password = password;
		this.channelName = "shell";
		this.cmdLine = null;
		init ();
	}


	/**
	 * Remote exec 
	 * 
	 * @param host
	 * @param user
	 * @param password
	 * @param cmd
	 * @throws JSchException
	 * @throws IOException
	 */
	public SshConnection(String host, String user, String keyFile, Password password, String cmd) throws JSchException, IOException {
		this.host = host;
		this.user = user;
		this.password = password;
		this.channelName = "exec";
		this.keyFile = keyFile;
		this.cmdLine = cmd;
		init ();
	}


	public class MyUserInfo implements UserInfo {
		public MyUserInfo() {
		}

		public String getPassword() {
			return password.getPassword();
		}

		public boolean promptYesNo(String str) {
			if (str.contains("WARNING"))
			{
				System.out.println ("Prompting yes/no: "+str+" NO");
				return false;
			} else {
				System.out.println ("Prompting yes/no: "+str+" YES");
				return true;
			}
		}

		public String getPassphrase() {
			return password.getPassword();
		}

		public boolean promptPassphrase(String message) {
			return true;
		}

		public boolean promptPassword(String message) {
			return true;
		}

		public void showMessage(String message) {
			System.out.println (message);
		}
	}

	public OutputStream getOutputStream() {
		return outputStream;
	}

	public InputStream getInputStream() {
		return inputStream;
	}
	
	public boolean isEof ()
	{
		return channel.isEOF();
	}
	
	public int getExitStatus ()
	{
		for (int i = 0; i < 600 && ! channel.isClosed(); i++)
		{
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
			}
		}
		return channel.getExitStatus();
	}

	public void setDebug(boolean debugEnabled) {
		this.debug = debugEnabled;
		
	}

	public void setLog(Logger log) {
		this.log = log;
	}

}
