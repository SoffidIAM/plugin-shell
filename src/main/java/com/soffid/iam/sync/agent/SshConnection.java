package com.soffid.iam.sync.agent;

import com.jcraft.jsch.*;
import com.soffid.iam.service.impl.SshKeyGenerator;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.util.Base64;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
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

	private InputStream errorStream;

	static HostKeyRepository hkrepo = new HostKeyRepository() {
		List<HostKey> keys =  new LinkedList<HostKey>();
		public void remove(String host, String type, byte[] key) {
			for (Iterator<HostKey> iterator = keys.iterator(); iterator.hasNext();)
			{
				HostKey h = iterator.next();
				if (h.getHost().equals(host))
					iterator.remove();
			}
		}
		
		public void remove(String host, String type) {
			for (Iterator<HostKey> iterator = keys.iterator(); iterator.hasNext();)
			{
				HostKey h = iterator.next();
				if (h.getHost().equals(host) && type.equals(h.getType()))
					iterator.remove();
			}
		}
		
		public String getKnownHostsRepositoryID() {
			return "soffid";
		}
		
		public HostKey[] getHostKey(String host, String type) {
			List<HostKey> r = new LinkedList<HostKey>();
			synchronized (keys) {
				for (Iterator<HostKey> iterator = keys.iterator(); iterator.hasNext();)
				{
					HostKey h = iterator.next();
					if (h != null && h.getHost() != null && h.getHost().equals(host) && 
							(type == null || type.equals(h.getType())))
						r.add(h);
				}
			}
			return r.toArray(new HostKey[r.size()]);
		}
		
		public HostKey[] getHostKey() {
			return keys.toArray(new HostKey[keys.size()]);
		}
		
		public int check(String host, byte[] key) {
			String s = Base64.encodeBytes(key, Base64.DONT_BREAK_LINES);
			for (Iterator<HostKey> iterator = keys.iterator(); iterator.hasNext();)
			{
				HostKey h = iterator.next();
				if (h.getHost().equals(host) && s.equals(h.getKey()))
					return OK;
			}
			return NOT_INCLUDED;
		}
		
		public void add(HostKey hostkey, UserInfo ui) {
			keys.add(hostkey);
		}
	};

	private void init () throws IOException, JSchException
	{
		JSch.setConfig("PreferredAuthentications", "publickey,password");
		if ("true".equals(System.getProperty("soffid.ssh.debug")))
			JSch.setLogger(new DebugLogger());
		jsch = new JSch();
		if (keyFile != null && keyFile.trim().length() > 0) {
			if (keyFile.startsWith("-----BEGIN")) {
				jsch.addIdentity("Key "+user, keyFile.getBytes(StandardCharsets.UTF_8), null, null);
			} else
				jsch.addIdentity(keyFile);
		}
		
		String knownHosts = Config.getConfig().getHomeDir().getAbsolutePath()+File.separator+"conf"+File.separator+"known_hosts";
		
		File f = new File (knownHosts);
		try {
			if (!f.canRead())
				new FileOutputStream(f).close();
			
			jsch.setKnownHosts(knownHosts);
		} catch (Exception e) {
			jsch.setHostKeyRepository(hkrepo);
		}
		session = jsch.getSession(user, host, 22);

		// username and password will be given via UserInfo interface.
		UserInfo ui = new MyUserInfo();
		session.setUserInfo(ui);
		session.setTimeout(30000);  // 30 seconds timeout for connection
		session.connect();

		channel = session.openChannel(channelName);
		if (cmdLine != null)
			((ChannelExec) channel).setCommand(cmdLine);
		

		// get I/O streams for remote scp
		outputStream = channel.getOutputStream();
		inputStream = channel.getInputStream();
		errorStream = channel.getExtInputStream();
		channel.connect();

		session.setTimeout(0); // No timeout after connection
	}
	
	public void close ()
	{
		if (channel != null) {
			channel.disconnect();
			try {
				channel.getOutputStream().close();
			} catch (IOException e) {
			}
			try {
				channel.getInputStream().close();
			} catch (IOException e) {
			}
			if (channel instanceof ChannelExec)
				try {
					((ChannelExec) channel).getErrStream().close();
				} catch (IOException e) {
				}
		}
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
//				System.out.println ("Prompting yes/no: "+str+" NO");
				return false;
			} else {
//				System.out.println ("Prompting yes/no: "+str+" YES");
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
//			System.out.println (message);
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
	
	public int getExitStatus () throws IOException
	{
		for (int i = 0; i < 600 && ! channel.isClosed(); i++)
		{
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
			}
		}
		if (!channel.isClosed())
			throw new IOException("Timeout. No response from server");
		return channel.getExitStatus();
	}

	public void setDebug(boolean debugEnabled) {
		this.debug = debugEnabled;
		
	}

	public void setLog(Logger log) {
		this.log = log;
	}

	public InputStream getErrorStream() {
		return errorStream;
	}

	public void exec(String cmdLine) throws JSchException, IOException {
		if (channel != null)
			channel.disconnect();
		channel = session.openChannel("exec");
		if (cmdLine != null)
			((ChannelExec) channel).setCommand(cmdLine);

		// get I/O streams for remote scp
		outputStream = channel.getOutputStream();
		inputStream = channel.getInputStream();
		errorStream = channel.getExtInputStream();
		channel.connect();
	}

	public boolean isConnected() {
		return session.isConnected();
	}
}
