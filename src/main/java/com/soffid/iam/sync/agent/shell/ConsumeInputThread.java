package com.soffid.iam.sync.agent.shell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConsumeInputThread extends ConsumeErrorThread {
	private Pattern pattern = null;
	private boolean promptFound;

	public ConsumeInputThread(InputStream inputStream, String prompt, Object notifier) {
		super (inputStream, notifier);
		if (prompt != null && prompt.length() > 0)
			pattern = Pattern.compile(prompt);
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
					closed ();
					return;
				}
				// Append to buffer
				bout.write(i);
//				if (debug)
//					System.out.write(i);
				if (pattern != null && in.available() == 0)
				{
					Matcher m = pattern.matcher(bout.toString());
					if (m.matches())
					{
						this.sleep(100);
						if (in.available() == 0)
						{
							// Prompt found
							if (debug)
								log.info ("[PROMPT-FOUND]");
							promptFound = true;
							int pos = m.start();
							byte []buffer = Arrays.copyOfRange(bout.toByteArray(), 0, pos);
							setLine(buffer);
							bout.reset();
						}
					}
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
		}
	}
}