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
import es.caib.seycon.ng.sync.intf.ExtensibleObject;

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

public class SSHAgent extends AbstractShellAgent 
{
	String user;
	Password password;
	String server;
	String keyFile;
	String charSet;
	
	public SSHAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SSH Agent agent on {}", getDispatcher().getCodi(),
				null);
		user = getDispatcher().getParam0();
		keyFile = getDispatcher().getParam1();
		password = Password.decode(getDispatcher().getParam2());
		server = getDispatcher().getParam3();
		hashType = getDispatcher().getParam4();
		passwordPrefix = getDispatcher().getParam5();
		charSet = getDispatcher().getParam6();
		if (charSet == null || charSet.trim().length() == 0)
			charSet = "UTF-8";
		
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		
		
		debugEnabled = "true".equals(getDispatcher().getParam7());

		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}
	}



	protected List<String[]> executeSentence(String sentence, ExtensibleObject obj, String parseExpression) throws InternalErrorException {
		List<String[]> result = new LinkedList<String[]>();
		StringBuffer b = new StringBuffer ();

		parseSentence(sentence, obj, b);
		
		String parsedSentence = b.toString().trim();
		
		if (debugEnabled)
		{ 
			log.info("Executing "+parsedSentence);
		}
		
		SshTunnel tunnel;
		try {
			tunnel = new SshTunnel(this.server, user, keyFile, password, parsedSentence);
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command "+sentence+":"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command "+sentence+":"+e.getMessage(), e);
		}
		try {
			tunnel.getOutputStream().close();
			InputStream in = tunnel.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int i  = in.read(); i >= 0; i = in.read())
			{
				buffer.write(i);
			}
			if (tunnel.getExitStatus() != 0)
				throw new InternalErrorException("SSH command "+sentence+" returned "+tunnel.getExitStatus());
			if ( parseExpression != null && parseExpression.trim().length() > 0)
			{
				Pattern pattern = Pattern.compile(parseExpression);
				Matcher matcher = pattern.matcher(buffer.toString(charSet));

				while (matcher.find())
				{
					int count = matcher.groupCount();
					String row [] = new String[count+1];
					for (int i = 0; i <= count; i++)
						row[i] = matcher.group(i);
					result.add(row);
				}
			}
			else
			{
				result.add(new String[] {buffer.toString()});
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command "+sentence+":"+e.getMessage(), e);
		} finally {
			tunnel.close();
		}
		
		return result;
		
	}

}
	