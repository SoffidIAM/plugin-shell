package com.soffid.iam.sync.agent.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.rmi.RemoteException;

import com.jcraft.jsch.JSchException;
import com.soffid.iam.api.Password;
import com.soffid.iam.sync.agent.SimpleSSHAgent;
import com.soffid.iam.sync.agent.SshConnection;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.exception.InternalErrorException;
import junit.framework.TestCase;

public class SimpleSSHAgentTest extends TestCase {
	public void test1() throws RemoteException, InternalErrorException, InterruptedException {
		System.out.println("Connecting");
		SshConnection tunnel;
		try {
//			tunnel = new SshConnection("forge.dev.lab", "bbuades", null, new es.caib.seycon.ng.comu.Password("geheim01"), "sudo -S -p SUDO-PASS: cat /etc/passwd");
//			tunnel = new SshConnection("forge.dev.lab", "bbuades", null, new es.caib.seycon.ng.comu.Password("geheim01"), "cat /etc/passwd");
			tunnel = new SshConnection("192.168.1.140", "kafar", null, new es.caib.seycon.ng.comu.Password("Edsco@321"), "cat /etc/passwd");
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		}
		try {
			final InputStream in = tunnel.getInputStream();
			final InputStream error = tunnel.getErrorStream();
			new Thread( new Runnable() {
				public void run() {
					try {
						for (int i  = in.read(); i >= 0; i = in.read())
						{
//							System.out.write(i);
//							System.out.flush();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}).start();
			new Thread( new Runnable() {
				public void run() {
					try {
						for (int i  = error.read(); i >= 0; i = error.read())
						{
							System.out.write(i);
							System.out.flush();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}).start();
			if (tunnel.getExitStatus() != 0)
			{
				throw new InternalErrorException("SSH command returned "+tunnel.getExitStatus()+"\n");
			}
			tunnel.getOutputStream().close();
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} finally {
			tunnel.close();
		}
	}
}
