package com.soffid.iam.sync.agent.shell;


import com.soffid.iam.sync.agent.ShellTunnel;

import es.caib.seycon.ng.sync.engine.pool.AbstractPool;

public class TunnelPool extends AbstractPool<ShellTunnel> {
	String exitCommand;
	String shell;
	String prompt;
	long timeout;

	@Override
	protected void closeConnection(ShellTunnel tunnel) throws Exception {
		tunnel.closeShell();
	}

	@Override
	protected ShellTunnel createConnection() throws Exception {
		ShellTunnel tunnel = new ShellTunnel(shell, true, prompt);
		tunnel.setExitCommand (exitCommand);
		tunnel.setTimeout(timeout);
		return tunnel;
	}

}
