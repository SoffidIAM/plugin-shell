package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.rmi.RemoteException;

import com.jcraft.jsch.JSchException;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agent to manage relational databases
 * 
 * Parameters:
 * 
 * 0 User name
 * 1 Password
 * 2 JDBC URL
 * 3 Password hash alogithm
 * 4 Password hash prefix
 * 5 Debug
 * 6 Driver type: Oracle / MySQL / PostgreSql / SQLServer
 * <P>
 */

public class SSHAgent extends AbstractShellAgent   implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
	AuthoritativeIdentitySource, MailAliasMgr
{
	String user;
	Password password;
	String server;
	String keyFile;
	String charSet;
	SshConnection tunnel = null;
	
	public SSHAgent() throws RemoteException {
	}

	@Override
	public void finalize() {
		if (tunnel != null)
			tunnel.close();
	}
	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SSH Agent agent on {}", getDispatcher().getCodi(),
				null);
		user = getDispatcher().getParam0();
		keyFile = getDispatcher().getParam1();
		password = Password.decode(getDispatcher().getParam2());
		server = getDispatcher().getParam3();
		charSet = getDispatcher().getParam6();
		if (charSet == null || charSet.trim().length() == 0)
			charSet = "UTF-8";
		
		debugEnabled = "true".equals(getDispatcher().getParam7());

		super.init ();
	}



	@Override
	protected String actualExecute(String parsedSentence) throws InternalErrorException {
		if (debugEnabled)
		{ 
			log.info("Executing "+parsedSentence);
		}
		
		try {
			if (tunnel == null || ! tunnel.isConnected())
				tunnel = new SshConnection(this.server, user, keyFile, password, parsedSentence);
			else
				tunnel.exec(parsedSentence);
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		}
		InputStream in = null;
		InputStream error = null;
		try {
			in = tunnel.getInputStream();
			error = tunnel.getErrorStream();
			final OutputStream out = tunnel.getOutputStream();
			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
			
			InputStreamConsumer ic = new InputStreamConsumer(in, buffer, outputBuffer); ic.start();
			InputStreamConsumer ec = new InputStreamConsumer(error, buffer, null); ec.start();
			out.close();
			if (tunnel.getExitStatus() != 0)
			{
				ic.end();
				ec.end();
				throw new InternalErrorException("SSH command returned "+tunnel.getExitStatus()+"\n"+
						buffer.toString(charSet));
			}
			return outputBuffer.toString(charSet);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} finally {
			if (in != null)
				try {
					in.close();
				} catch (IOException e1) {
				}
			if (error != null)
				try {
					error.close();
				} catch (IOException e) {
				}
			tunnel.close();
		}
	}
}
	