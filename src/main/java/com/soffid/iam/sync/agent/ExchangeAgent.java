package com.soffid.iam.sync.agent;

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
		user = getDispatcher().getParam8();
		password = Password.decode( getDispatcher().getParam9() );
		
		super.init();
	}

	protected void initTunnel() throws InternalErrorException {
		if (shellTunnel != null)
			shellTunnel.closeShell();
		shellTunnel = new ShellTunnel(shell, persistentShell, prompt+"\r\n");
		shellTunnel.setDebug(debugEnabled);
		shellTunnel.setLog (log);
		try {
			String hostName = InetAddress.getLocalHost().getCanonicalHostName();
			InputStream in ;
			
			if (user == null || user.trim().isEmpty())
				shellTunnel.execute(". '"+exchangeDir+"';"+
						"Connect-ExchangeServer -ServerFQDN "+hostName+";");
			else
				shellTunnel.execute("$User = \""+user+"\" ;"+
					"$PWord = ConvertTo-SecureString -String \""+password.getPassword()+"\" -AsPlainText -Force;"+
					"$C = New-Object -TypeName \"System.Management.Automation.PSCredential\" -ArgumentList $User, $PWord;"+
					"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://"+
							hostName+"/PowerShell/ -Authentication Kerberos -Credential $C;" +
					"Import-PSSession $Session; "+
					". '"+exchangeDir+"';"+
					"Connect-ExchangeServer -ServerFQDN "+hostName+";");
			in = shellTunnel.execute(
//					"function prompt{\"\"}; " +
					"echo \""+prompt+"\"");
			int b;
			while ((b = in.read()) >= 0) {
//				System.out.write (b);
			}
		} catch (IOException e) {
			throw new InternalErrorException ("Unable to open power shell");
		}
	}

}
