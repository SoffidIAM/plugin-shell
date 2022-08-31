package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class InputStreamConsumer extends Thread {

	private InputStream in;
	private ByteArrayOutputStream buffer;
	boolean end;
	private ByteArrayOutputStream outputBuffer;
	
	public InputStreamConsumer(InputStream in, ByteArrayOutputStream buffer, ByteArrayOutputStream outputBuffer) {
		this.in = in;
		this.buffer = buffer;
		this.outputBuffer = outputBuffer;
		end = false;
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
			for (int i = in.read(); i >= 0; i = in.read()) {
				synchronized(buffer) {
					buffer.write(i);
					if (outputBuffer != null)
						outputBuffer.write(i);
				}
			}
		} catch (IOException e) {
			
		}
	}

}
