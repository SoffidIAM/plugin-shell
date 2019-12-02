package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;

import org.apache.commons.io.output.ByteArrayOutputStream;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ExchangeAgent extends PowerShellAgent {

	private static final int TIMEOUT = 15;
	private String exchangeDir;
	private String user;
	private Password password;
	private String exchangeServer;
	private String version;
	private String startupScript;
	private String hostName;
	static int count = 0;
	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public ExchangeAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		count ++;
		if (count > 50)
			restart();
		log.info("Starting Power Shell Agent agent on {}: {}", getDispatcher().getCodi(),
				count);
//		exchangeServer = getDispatcher().getParam6();
		exchangeDir = getDispatcher().getParam7();
		if (exchangeDir == null)
			throw new InternalErrorException("Missing exchange script file");
		user = getDispatcher().getParam8();
		password =  getDispatcher().getParam9() == null ? null: Password.decode( getDispatcher().getParam9() );
		hostName = getDispatcher().getParam2();
		if (hostName == null || hostName.trim().isEmpty())
		{
			try {
				hostName = InetAddress.getLocalHost().getCanonicalHostName();
			} catch (UnknownHostException e) {
				try {
					hostName = Config.getConfig().getHostName();
				} catch (IOException e1) {
					throw new InternalErrorException ("Unable to guess local host name", e);
				}
			}
		}
		version = getDispatcher().getParam0();
		startupScript = getDispatcher().getParam6();
		
		if ("2007".equals(version))
		{
			if (!exchangeDir.endsWith("psc1"))
				throw new InternalErrorException("Exchange server ps scrict should end with .psc1, usually exshell.psc1");
		}
		if (exchangeDir.endsWith("psc1"))
		{
			pscFile = exchangeDir;
			exchangeDir = null;
		}
		super.init();
	}

	protected void initTunnel() throws InternalErrorException {
		if (shellTunnel != null)
			shellTunnel.closeShell();
		shellTunnel = new ShellTunnel(shell, persistentShell, prompt+"\r\n");
		shellTunnel.setDebug(debugEnabled);
		shellTunnel.setLog (log);
		shellTunnel.setEncoding("CP850");
		shellTunnel.setTimeout( TIMEOUT * 60 * 1000); //30 mins max idle time for a power shell
		shellTunnel.setRestartWord("watson");
		String loadScript = exchangeDir != null  && !exchangeDir.trim().isEmpty() ? ". '"+exchangeDir+"';" : "";
		try {
			InputStream in ;
			
			if (pscFile != null)
			{
				if ("2010".equals(version))
				{
					File dir = new File(pscFile).getParentFile();
					File ps1 = new File(dir, "RemoteExchange.ps1");
					if (ps1.canRead())
					{
						shellTunnel.execute(loadScript+
								". \""+ps1.getPath()+"\";");
						shellTunnel.execute(
								"Connect-ExchangeServer -auto;");
						
					}
				}
			}
			else if (user == null || user.trim().isEmpty())
			{
				shellTunnel.execute("$User = \""+user+"\" ;"+
						"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://"+
								hostName+"/PowerShell/ -Authentication Kerberos;" +
						"Import-PSSession $Session; "+
						loadScript);

			}
			else 
			{
				shellTunnel.execute("$User = \""+user+"\" ;"+
					"$PWord = ConvertTo-SecureString -String \""+password.getPassword()+"\" -AsPlainText -Force;"+
					"$C = New-Object -TypeName \"System.Management.Automation.PSCredential\" -ArgumentList $User, $PWord;"+
					"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://"+
							hostName+"/PowerShell/ -Authentication Kerberos -Credential $C;" +
					"Import-PSSession $Session; "+
					loadScript);
			}
			
			if ( startupScript != null && ! startupScript.trim().isEmpty())
				shellTunnel.execute(startupScript);
			in = shellTunnel.execute(
					"echo \""+prompt+"\"");
			int b;
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			while ((b = in.read()) >= 0) {
				out.write(b);
//				System.out.write (b);
			}
			if (out.toString().contains("Windows PowerShell terminated"))
			{
				restart();
			}
			shellTunnel.idle();
		} catch (IOException e) {
			System.exit(1);
			throw new InternalErrorException ("Unable to open power shell", e);
		}
	}
	
	public void close () {
		shellTunnel.closeShell();
		super.close();
	}


}
