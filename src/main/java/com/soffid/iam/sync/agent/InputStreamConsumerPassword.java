package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;

import es.caib.seycon.ng.comu.Password;

public class InputStreamConsumerPassword extends Thread {

	private InputStream in;
	private ByteArrayOutputStream log;
	private String charSet;
	private Object sudoPrompt;
	private Password password;
	private OutputStream out;
	
	public InputStreamConsumerPassword(InputStream error, OutputStream out, ByteArrayOutputStream buffer2, String charSet,
			String sudoPrompt, Password password) {
		this.in = error;
		this.out = out;
		this.log = buffer2;
		this.charSet = charSet;
		this.sudoPrompt = sudoPrompt;
		this.password = password;
	}

	public void end() {
		try {
			while (in.available() > 0)
				Thread.sleep(10);
			in.close();
		} catch (Exception e) {
		}
	}
	
	@Override
	public void run() {
		try {
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int read = in.read(); read >= 0; read = in.read()) {
				log.write(read);
				if (read == '\n')
					buffer = new ByteArrayOutputStream();
				else {
					buffer.write(read);
					if (buffer.toString(charSet).equals(sudoPrompt)) {
						out.write(password.getPassword().getBytes(charSet));
						out.write('\n');
						out.flush();
						buffer = new ByteArrayOutputStream();
					}
				}
			}
		} catch (IOException e) {
		}
	}

	public void end(Logger log2) {
		end();
		log2.warn(log.toString());
		
	}

}
