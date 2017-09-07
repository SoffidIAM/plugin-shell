package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.jcraft.jsch.JSchException;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class ASAAgent extends AbstractShellAgent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
	AuthoritativeIdentitySource
{

	private String user;
	private String keyFile;
	private Password password;
	private String server;
	private String charSet;
	private AsaPersistentSshTunnel shellTunnel;
	private Password enablePassword;

	public ASAAgent() throws RemoteException {
		super();
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting ASA Agent agent on {}", getDispatcher().getCodi(),
				null);
		
		log.info("Starting SSH Agent agent on {}", getDispatcher().getCodi(),
				null);
		user = getDispatcher().getParam0();
		keyFile = getDispatcher().getParam1();
		password = Password.decode(getDispatcher().getParam2());
		server = getDispatcher().getParam3();
		charSet = getDispatcher().getParam6();
		if (charSet == null || charSet.trim().length() == 0)
			charSet = "UTF-8";
		
		
		hashType = null;
		passwordPrefix = "";
		
		debugEnabled = "true".equals(getDispatcher().getParam7());
		if (getDispatcher().getParam8() == null ||
				getDispatcher().getParam8().trim().length() == 0)
			enablePassword = password;
		else
			enablePassword = Password.decode(getDispatcher().getParam8());

		try {
			shellTunnel = new AsaPersistentSshTunnel(this.server, user, keyFile, password, enablePassword);
		} catch (JSchException e) {
			throw new InternalErrorException("Unable to connect to "+this.server, e);
		} catch (IOException e) {
			throw new InternalErrorException("Unable to connect to "+this.server, e);
		}
		shellTunnel.setDebug(debugEnabled);
		shellTunnel.setLog (log);
	}

	@Override
	protected String actualExecute(String parsedSentence) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();

		try {
			InputStream in = shellTunnel.execute( parsedSentence);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int i  = in.read(); i >= 0; i = in.read())
			{
				buffer.write(i);
			}
			String text = buffer.toString(charSet);
			return text;
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		}
	}
}
