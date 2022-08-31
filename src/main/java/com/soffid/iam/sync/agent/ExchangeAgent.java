package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;

import org.apache.commons.io.output.ByteArrayOutputStream;

import com.soffid.iam.sync.agent.shell.ExchangeTunnelPool;
import com.soffid.iam.sync.agent.shell.PowerShellTunnelPool;

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
//		count ++;
//		if (count > 50)
//			restart();
		log.info("Starting Exchange Agent agent on {}: {}", getDispatcher().getCodi(),
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

	protected void initPool() throws InternalErrorException {
		final String poolName = getTunnelPoolName();
		PowerShellTunnelPool p = pools.get(poolName);
		if (p == null) {
			ExchangeTunnelPool pool = new ExchangeTunnelPool();
			pool.setShell(shell);
			pool.setPersistentShell(persistentShell);
			pool.setPrompt(prompt);
			pool.setDebugEnabled(debugEnabled);
			pool.setLog(log);
			pool.setInitialCommand(initialCommand);
			pool.setTimeout(TIMEOUT * 60  * 1000); //30 mins max idle time for a power shell
			pool.setMaxUnusedTime(60 * 60 * 1000); // 1 hour not used timeout
			pool.setRestartWord("watson");
			pool.setExchangeDir(exchangeDir);
			pool.setPscFile(pscFile);
			pool.setVersion(version);
			pool.setUser(user);
			pool.setHostName(hostName);
			pool.setPassword(password);
			pool.setStartupScript(startupScript);
			pools.put(poolName, pool);
		}
	}

	@Override
	public void close() {
		count --;
		super.close();
	}
	
	

}
