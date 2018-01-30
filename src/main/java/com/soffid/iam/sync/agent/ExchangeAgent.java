package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.rmi.RemoteException;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ExchangeAgent extends PowerShellAgent {

	private String exchangeDir;
	private String user;
	private Password password;
	private String exchangeServer;
	private String version;

	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public ExchangeAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting Power Shell Agent agent on {}", getDispatcher().getCodi(),
				null);
//		exchangeServer = getDispatcher().getParam6();
		exchangeDir = getDispatcher().getParam7();
		if (exchangeDir == null)
			throw new InternalErrorException("Missing exchange script file");
		user = getDispatcher().getParam8();
		password = Password.decode( getDispatcher().getParam9() );
		version = getDispatcher().getParam0();
		
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
		shellTunnel.setTimeout(30 * 60 * 1000); //30 mins max idle time for a power shell 
		String loadScript = exchangeDir != null ? ". '"+exchangeDir+"';" : "";
		try {
			String hostName = InetAddress.getLocalHost().getCanonicalHostName();
			InputStream in ;
			
			if (pscFile != null)
			{
//				shellTunnel.execute(". '"+exchangeDir+"';");
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
				shellTunnel.execute(loadScript+
						"Connect-ExchangeServer -ServerFQDN "+hostName+";");
			else
				shellTunnel.execute("$User = \""+user+"\" ;"+
					"$PWord = ConvertTo-SecureString -String \""+password.getPassword()+"\" -AsPlainText -Force;"+
					"$C = New-Object -TypeName \"System.Management.Automation.PSCredential\" -ArgumentList $User, $PWord;"+
					"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://"+
							hostName+"/PowerShell/ -Authentication Kerberos -Credential $C;" +
					"Import-PSSession $Session; "+
					loadScript+
					"Connect-ExchangeServer -ServerFQDN "+hostName+";");
			in = shellTunnel.execute(
//					"function prompt{\"\"}; " +
					"echo \""+prompt+"\"");
			int b;
			while ((b = in.read()) >= 0) {
//				System.out.write (b);
			}
		} catch (IOException e) {
			System.exit(1);
			throw new InternalErrorException ("Unable to open power shell", e);
		}
	}

}
