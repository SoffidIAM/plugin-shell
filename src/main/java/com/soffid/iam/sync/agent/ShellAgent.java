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

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
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

public class ShellAgent extends AbstractShellAgent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
	AuthoritativeIdentitySource {

	String shell;

	boolean persistentShell;
	ShellTunnel shellTunnel;

	String prompt;

	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public ShellAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting Shell Agent agent on {}", getDispatcher().getCodi(),
				null);
		shell = getDispatcher().getParam0();
		persistentShell = "true".equals(getDispatcher().getParam1());
		prompt = getDispatcher().getParam2();
		
		hashType = getDispatcher().getParam3();
		passwordPrefix = getDispatcher().getParam4();
		
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		
		
		debugEnabled = "true".equals(getDispatcher().getParam5());

		if (debugEnabled)
			log.info ("Enabled DEBUG mode");
			
		
		shellTunnel = new ShellTunnel(shell, persistentShell, prompt);
		shellTunnel.setDebug(debugEnabled);
		shellTunnel.setLog (log);
		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}
	}



	private List<String[]> executeSentence(String sentence, ExtensibleObject obj) throws InternalErrorException {
		return executeSentence(sentence, obj, null);
	}
	
	
	
	List<String[]> executeSentence(String sentence, ExtensibleObject obj, 
			String parseExpression) throws InternalErrorException {
		List<String[]> result = new LinkedList<String[]>();
		StringBuffer b = new StringBuffer ();

		parseSentence(sentence, obj, b);
		
		String parsedSentence = b.toString().trim();
		
		if (debugEnabled)
		{ 
			log.info("Executing "+parsedSentence);
		}
		
		
		try {
			InputStream in = shellTunnel.execute( parsedSentence);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int i  = in.read(); i >= 0; i = in.read())
			{
				buffer.write(i);
			}
			if ( parseExpression != null && parseExpression.trim().length() > 0)
			{
				Pattern pattern = Pattern.compile(parseExpression);
				Matcher matcher = pattern.matcher(buffer.toString());

				while (matcher.find())
				{
					int count = matcher.groupCount();
					String row [] = new String[count+1];
					row[0] = matcher.group();
					for (int i = 1; i <= count; i++)
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
		}
		
		return result;
		
	}
}
	