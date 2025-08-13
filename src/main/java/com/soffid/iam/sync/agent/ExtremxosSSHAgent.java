package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.jcraft.jsch.JSchException;
import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.intf.ExtensibleObjectMgr;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.UserMgr;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ExtremxosSSHAgent extends SimpleSSHAgent  {

	public ExtremxosSSHAgent() throws RemoteException {
		super();
	}

	protected String getTestCommand() {
		return "show accounts\n";
	}

	@Override
	protected void updateAccountsMetadata() throws IOException, InternalErrorException {
		AdditionalDataService ds = ! Config.getConfig().isServer() ? 
			new RemoteServiceLocator().getAdditionalDataService() :
			ServiceLocator.instance().getAdditionalDataService();
	}

	protected boolean useSudo() {
		return false;
	}
	
	@Override
	public void updateUser(com.soffid.iam.api.Account account) throws RemoteException, InternalErrorException {
		if (onlyPassword)
			return;
		
		try {
			String level = getUserLevel(account.getName());
			com.soffid.iam.api.Password pass = getServer().getOrGenerateUserPassword(account.getName(), account.getSystem());
			executePersistent("delete account "+account.getName() + "\n"
				+ "create account "+level+" "+account.getName()+" "+pass.getPassword() + "\n"
				+ "save configuration\n"
				+ "y\n"
				+ "exit\n", 
				pass.getPassword());
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	protected String getUserLevel(String name) throws InternalErrorException {
		String level = "user";
		for (RoleGrant p: getServer().getAccountRoles(name, getAgentName()))
			if (p.getRoleName().endsWith("R/W"))
				level = "admin";
		return level;
	}

	private boolean existUser(String name) throws ExecutionException, InternalErrorException {
		String s = execute("show accounts");
		Matcher matcher = Pattern.compile(" "+name+" +(RO|R/W)", Pattern.UNIX_LINES+Pattern.MULTILINE).matcher(s);
		if (matcher.find()) 
			return true;
		else
			return false;
	}

	@Override
	public void removeUser(String userName) throws RemoteException, InternalErrorException {
		if (onlyPassword)
			return;
		
		try {
			executePersistent("delete account "+userName, "************");
			executePersistent("save configuration\n"
					+ "y\n"
					+ "exit\n", 
					"****************");
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public void updateUserPassword(String userName, User userData, com.soffid.iam.api.Password pass,
			boolean mustchange) throws RemoteException, InternalErrorException {
		try {
			Account account = getServer().getAccountInfo(userName, getAgentName());
			try {
				String level = getUserLevel(account.getName());
				executePersistent("delete account "+account.getName() + "\n"
					+ "create account "+level+" "+account.getName()+" "+pass.getPassword() + "\n"
					+ "save configuration\n"
					+ "y\n"
					+ "exit\n", 
					pass.getPassword());
			} catch (ExecutionException e) {
				throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
			}

			String privilege = (String) account.getAttributes().get("privilege");
			if (privilege == null || privilege.trim().isEmpty())
				privilege = "1";
			executePersistent("update account "+userName+"\n"
					+ password.getPassword()+"\n"
					+ password.getPassword()+"\n"
					+ "save configuration\n"
					+ "y\n"
					+ "exit\n", 
					password.getPassword());
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public boolean validateUserPassword(String userName, com.soffid.iam.api.Password password)
			throws RemoteException, InternalErrorException {
		try {
			SshConnection tunnel = new SshConnection(server, userName, null, new Password(password.getPassword()), "show configuration") ;
			tunnel.close();
			return true;
		} catch (JSchException e) {
			log.warn("Error checking password", e);
			return false;
		} catch (IOException e) {
			log.warn("Error checking password", e);
			return false;
		}
		
	}

	@Override
	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		List<String> names = new LinkedList<String>();
		try {
			String s = execute("show accounts");
			if (isDebug())
				log.info(s);
			Matcher matcher = Pattern.compile("([^ ]+) +(RO|R/W)", Pattern.UNIX_LINES+Pattern.MULTILINE).matcher(s);
			while (matcher.find()) {
				String un = matcher.group(1);
				names.add(un);
			}
			return names;
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public com.soffid.iam.api.Account getAccountInfo(String userAccount)
			throws RemoteException, InternalErrorException {
		try {
			String s = execute("show accounts");
			Matcher matcher = Pattern.compile(" "+userAccount+" +(RO|R/W)", Pattern.UNIX_LINES+Pattern.MULTILINE).matcher(s);
			while (matcher.find()) {
				String role = matcher.group(1);
				Account acc = new Account();
				acc.setName(userAccount);
				acc.setDescription(userAccount);
				acc.setSystem(getSystem().getName());
				acc.setAttributes(new HashMap<>());
				return acc;
			}
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
		return null;		
	}

	@Override
	public List<String> getRolesList() throws RemoteException, InternalErrorException {
			List<String> names = new LinkedList<String>();
			names.add("R/W");
			names.add("RO");
			return names;
	}

	@Override
	public Role getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		Role r = new Role();
		r.setName(roleName);
		r.setDescription(roleName);
		return r;
	}

	@Override
	public List<RoleGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		try {
			String s = execute("show accounts");
			Matcher matcher = Pattern.compile(" "+userAccount+" +(RO|R/W)", Pattern.UNIX_LINES+Pattern.MULTILINE).matcher(s);
			while (matcher.find()) {
				String role = matcher.group(1);
				RoleGrant rg = new RoleGrant();
				rg.setRoleName(role);
				rg.setOwnerAccountName(userAccount);
				rg.setSystem(getAgentName());
				rg.setOwnerSystem(getAgentName());
				return Arrays.asList(rg);
			}
			return new LinkedList<RoleGrant>();
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
	}

	@Override
	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	@Override
	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	};
	
	public Collection<Map<String, Object>> invoke(String verb, String command,
				Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		Collection<Map<String, Object>> l = new LinkedList<Map<String, Object>>();
		if (verb.equals("checkPassword"))
		{
		}
		else if (verb.equals("invoke")) 
		{
			String s;
			try {
				s = execute(command);
			} catch (ExecutionException e) {
				throw new InternalErrorException("Error invoking command", e);
			} catch (InternalErrorException e) {
				throw e;
			}
			HashMap<String, Object> m = new HashMap<String,Object>();
			m.put("result", s);
			l.add(m);
		}
		return l;
	}
	
	protected String executePersistent(String inputData, String secret) throws ExecutionException, InternalErrorException {
		if (isDebug())
		{ 
			String msg = password == null ? inputData: inputData.replace(secret, "*****");
			log.info("Executing persistent "+msg);
		}
		
		SshConnection persistentTunnel;
		try {
			try {
				persistentTunnel = new SshConnection(this.server, user, keyFile, password);
			} catch (JSchException e) {
				com.soffid.iam.api.Password p = getServer().getOrGenerateUserPassword(user, getAgentName());
				if (p == null || p.getPassword().equals(password.getPassword()))
					throw e;
				password = new Password( p.getPassword() );
				persistentTunnel = new SshConnection(this.server, user, keyFile, password);
			}
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		}
		
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
		try {
			final InputStream in = persistentTunnel.getInputStream();
			final InputStream error = persistentTunnel.getErrorStream();
			final OutputStream out = persistentTunnel.getOutputStream();
			if (inputData != null && inputData.length() > 0)
			{
				try {
					Thread.sleep(200);
				} catch (InterruptedException e) { }
				out.write(inputData.getBytes(charSet));
				out.close();
			}
			InputStreamConsumer ic = new InputStreamConsumer(in, buffer, outputBuffer); ic.start();
			InputStreamConsumer ec = new InputStreamConsumer(error, buffer, outputBuffer); ec.start();
			final int exitStatus = persistentTunnel.getExitStatus();
			ic.end();
			ec.end();
			if (exitStatus != 0)
			{
				throw new ExecutionException(exitStatus, outputBuffer.toString()+buffer.toString(charSet));
			}
			out.close();
			return outputBuffer.toString(charSet);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage()+"\n"+
					outputBuffer.toString()+"\n"+buffer.toString(), 
					e);
		} finally {
			persistentTunnel.close();
		}
	}

}
