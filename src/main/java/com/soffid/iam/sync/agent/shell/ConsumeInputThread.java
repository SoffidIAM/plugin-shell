package com.soffid.iam.sync.agent.shell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConsumeInputThread extends ConsumeErrorThread {
	private boolean promptFound;
	private String prompt;
	
	public ConsumeInputThread(InputStream inputStream, String prompt, Object notifier, String encoding) {
		super (inputStream, notifier, encoding);
		this.prompt = prompt == null || prompt.trim().isEmpty() ? null: prompt;;
		promptFound = false;
	}

	public boolean isPromptFound () {
		return promptFound;
	}
	
	public void resetPrompt ()
	{
		promptFound = false;
	}

	public void run() {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		int i;
		try {
			while (!finish) {
				i = in.read();
				if (i < 0) {
					if(debug)
						log.info ("END-OF-OUTPUT-STREAM");
					setLine(bout.toByteArray());
					return;
				}
				// Append to buffer
				bout.write(i);
				if (prompt != null)
				{
					final String boutTxt = bout.toString(encoding);
					int pos = boutTxt.indexOf(prompt);
					if (pos >= 0)
					{
						// Prompt found
						if (debug)
							log.info ("[PROMPT-FOUND]");
						promptFound = true;
						byte []buffer = boutTxt.substring(0, pos).getBytes(encoding);
						setLine(buffer);
						bout.reset();
					} else if (debug) {
//						log.info (bout.toString(encoding)+"<WAITING...>");
					}
				} 
				else if (in.available() == 0 && debug)
				{
//					log.info (bout.toString()+"<WAITING...>");
				}
				if (i == '\n') {
					setLine(bout.toByteArray());
					bout.reset();
				}
			}
			if (debug)
				log.info ("OUTPUT-STREAM-CLOSED");

		} catch (IOException e) {
		} catch (InterruptedException e) {
		} finally {
			closed();
		}
	}
}