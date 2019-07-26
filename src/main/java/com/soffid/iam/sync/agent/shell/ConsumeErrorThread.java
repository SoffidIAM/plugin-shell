package com.soffid.iam.sync.agent.shell;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;

import org.slf4j.Logger;

public class ConsumeErrorThread extends Thread
{
	protected InputStream in;
	protected byte[] line;
	protected boolean finish;
	private String restartWord = null;


	public boolean isClosed() {
		return finish;
	}

	private Object notifier;
	protected boolean debug;
	protected Logger log;
	protected String encoding;

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public ConsumeErrorThread (InputStream errorStream, Object notifier, String encoding) 
	{
		this.encoding = encoding;
		this.in = errorStream;
		line = null;
		finish = false;
		this.notifier = notifier;
	}
	
	public synchronized byte[] getLine() {
		if (line == null)
			return null;

		byte[] previousLine = line;
		line = null;
		this.notify();
		return previousLine;
	}

	public synchronized void finish() {
		this.finish = true;
		notify();
	}

	public synchronized void setLine(byte[] b) throws InterruptedException {
		line = b;
		if ( restartWord != null)
		{
			String s = new String(line);
			if (s.toLowerCase().contains(restartWord.toLowerCase()))
			{
				log.warn("Found forbidden word ["+restartWord+"] in response text "+s);
				restart();
			}
		}
		synchronized (notifier)
		{
			notifier.notify();
		}
		if (!finish) {
			this.wait();
		}
	}
	
	public void restart() {
		new Thread(new Runnable() {
			public void run() {
				try {
					Thread.sleep(2000);
				} catch (InterruptedException e) {}
				System.exit(1);
			}
			
		}).start();
	}

	protected void closed ()
	{
		finish = true;
		synchronized (notifier)
		{
			notifier.notify();
		}
	}
	
	public void run ()
	{
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		int i;
		try {
			while ( !finish )
			{
				i = in.read();
				if ( i < 0 )
				{
					setLine ( bout.toByteArray() );
					if (debug)
						log.info("END-OF-ERROR-STREAM");
					closed ();
					return;
				}
				// Append to buffer
				bout.write(i);
//				if (debug)
//					System.out.write(i);
				if (i == '\n') {
					setLine ( bout.toByteArray() );
					bout.reset();
				}
			}
			if (debug)
				log.info("ERROR-STREAM-CLOSED");
		} catch (IOException e) {
		} catch (InterruptedException e) {
		}
	}

	public void setLog(Logger log) {
		this.log = log;
	}


	public String getRestartWord() {
		return restartWord;
	}

	public void setRestartWord(String restartWord) {
		this.restartWord = restartWord;
	}
}
