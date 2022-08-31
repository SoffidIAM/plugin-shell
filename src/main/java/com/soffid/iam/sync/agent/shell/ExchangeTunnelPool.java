package com.soffid.iam.sync.agent.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import com.soffid.iam.api.Password;
import com.soffid.iam.sync.agent.ShellTunnel;

import es.caib.seycon.ng.exception.InternalErrorException;

public class ExchangeTunnelPool extends PowerShellTunnelPool {
	private String exchangeDir;
	private String pscFile;
	private String version;
	private String user;
	private String hostName;
	private Password password;
	private String startupScript;

	@Override
	protected ShellTunnel createConnection() throws Exception {
		ShellTunnel shellTunnel = super.createConnection();
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
						if ( startupScript != null && !startupScript.contains("Connect-ExchangeServer"))
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
				log.info("Detected severe error. Restarting");
				new Thread(new Runnable() {
					public void run() {
						try {
							Thread.sleep(2000);
						} catch (InterruptedException e) {}
						System.exit(1);
					}
					
				}).start();
			}
			shellTunnel.idle();
		} catch (IOException e) {
			System.exit(1);
			throw new InternalErrorException ("Unable to open power shell", e);
		}
		return shellTunnel;
	}

	public String getExchangeDir() {
		return exchangeDir;
	}

	public void setExchangeDir(String exchangeDir) {
		this.exchangeDir = exchangeDir;
	}

	public String getPscFile() {
		return pscFile;
	}

	public void setPscFile(String pscFile) {
		this.pscFile = pscFile;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public Password getPassword() {
		return password;
	}

	public void setPassword(Password password) {
		this.password = password;
	}

	public String getStartupScript() {
		return startupScript;
	}

	public void setStartupScript(String startupScript) {
		this.startupScript = startupScript;
	}

}
