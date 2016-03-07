package com.soffid.iam.sync.agent.shell;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;

import com.soffid.iam.sync.agent.ShellTunnel;

public class ExitOnPromptInputStream extends InputStream {

	Logger log = null;
	private boolean eof;
	private ShellTunnel shellTunnel;
	private ConsumeErrorThread errorThread;
	private Object notifier;
	private ConsumeInputThread inputThread;
	byte [] buffer;
	int offset;
	private boolean persistent;
	private boolean debug;
	
	public boolean isDebug() {
		return debug;
	}


	public void setDebug(boolean debug) {
		this.debug = debug;
	}


	@Override
	public int read() throws IOException {
		if (eof)
			return -1;

		while (buffer == null || offset >= buffer.length)
		{
			offset = 0;
			buffer = null;
			
			if (buffer == null)
			{
				buffer = errorThread.getLine();
				if (debug && buffer != null && buffer.length > 0)
					log.info("ERROR: "+stringify(buffer));
			}
			if (buffer == null)
			{
				buffer = inputThread.getLine();
				if (debug && buffer != null && buffer.length > 0)
					log.info("OUTPUT: "+stringify(buffer));
			}
			if (buffer == null && inputThread.isPromptFound())
			{
				if (debug)
					log.info("[PROMPT]");
				eof = true;
			}
			if (buffer == null && inputThread.isClosed())
			{
				if (debug)
					log.info("[EOF]");
				eof = true;
			}
			
			if (eof)
			{
				if (!persistent)
					shellTunnel.closeShell();
				return -1;
			}
			
			if (buffer == null)
			{
				synchronized (notifier)
				{
					try {
						notifier.wait();
					} catch (InterruptedException e) {
					}
				}
			}
		}
		
		if (buffer == null || offset >= buffer.length)
			return -1;
		else
		{
			byte b = buffer[offset++];
			if (b < 0)
				return 256 + b;
			else
				return b;
		}
	}


	private String stringify(byte[] buffer2) {
		StringBuffer sb = new StringBuffer();
		for (char ch: new String(buffer2).toCharArray())
		{
			if (ch == 10)
				sb.append ("\\n");
			else if (ch == 13)
				sb.append ("\\r");
			else if (ch == 9)
				sb.append ("\\t");
			else if (ch >= 0 && ch < 32)
			{
				sb.append ("\\");
				sb.append ((int) ch);
			}
			else
				sb.append (ch);
		}
		return sb.toString();
	}


	public ExitOnPromptInputStream(ConsumeInputThread inputThread, ConsumeErrorThread errorThread, Object notifier, ShellTunnel shellTunnel2, boolean persistent, boolean debug, Logger log) {
		this.inputThread = inputThread;
		this.errorThread = errorThread;
		this.notifier = notifier;
		this.persistent = persistent;
		this.shellTunnel = shellTunnel2;
		this.debug = debug;
		this.log =  log;
		eof = false;
		buffer = null;
		offset = 0;
		inputThread.resetPrompt();
	}
}