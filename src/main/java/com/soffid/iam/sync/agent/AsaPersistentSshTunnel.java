package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

import com.jcraft.jsch.JSchException;
import com.soffid.iam.sync.agent.shell.ExitOnPromptInputStream;

import es.caib.seycon.ng.comu.Password;

public class AsaPersistentSshTunnel extends PersistentSshTunnel {

	private Password enablePassword;

	public AsaPersistentSshTunnel(String host, String user, String keyFile,
			Password password, Password enablePassword) throws JSchException, IOException {
		super(host, user, keyFile, password, "\\r[a-zA-Z0-9\\.]+# ");
		this.enablePassword = enablePassword;
	}

	@Override
	public void onConnect() throws UnsupportedEncodingException, IOException {
		super.onConnect();
		OutputStream out = connection.getOutputStream();
		if (debug)
			log.info("Executing: enable");
		out.write("enable\n".getBytes("UTF-8"));
		try {
			Thread.sleep(500);
		} catch (InterruptedException e) {
			throw new IOException("Error waiting for password prompt", e);
		}
		if (debug)
			log.info("Sending enable password");
		out.write(enablePassword.getPassword().getBytes("UTF-8"));
		out.write('\n');
		out.flush ();
		ExitOnPromptInputStream in = new ExitOnPromptInputStream (inputThread, null, notifier, this, true, debug, log);
		while (in.read() >= 0)
		{
			// Nothing to do
		}
	}

}
