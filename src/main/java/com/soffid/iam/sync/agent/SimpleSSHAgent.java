package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
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

public class SimpleSSHAgent extends Agent implements UserMgr, ReconcileMgr2, ExtensibleObjectMgr {

	private static final String SUDO_PROMPT = "TEgyFPvkiBHn+rdZwCCy9s7vjzxUllkKQBXRCbH2tj+E";
	protected String user;
	protected String keyFile;
	protected Password password;
	protected String server;
	protected String charSet;
	SshConnection tunnel = null;
	protected boolean onlyPassword;
	private String sudoprefix;
	private HashMap<String, String> extendedAttributes;
	
	@Override
	public void finalize() {
		if (tunnel != null)
			tunnel.close();
	}
	
	public SimpleSSHAgent() throws RemoteException {
		super();
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting Simple SSH Agent agent on {}", getSystem().getName(), null);
		user = getSystem().getParam0();
		keyFile = getSystem().getParam1();
		password = getSystem().getParam2() == null || getSystem().getParam2().trim().isEmpty() ? 
				new Password(""): Password.decode(getSystem().getParam2());
		server = getSystem().getParam3();
		charSet = getSystem().getParam6();
		if (charSet == null || charSet.trim().length() == 0)
			charSet = "UTF-8";
		
		parseExtendedAttributes();
		String key = extendedAttributes.get("sshKey");
		
		if (key != null && !key.trim().isEmpty())
			keyFile = key;
		
		boolean debugEnabled = "true".equals(getSystem().getParam7());
		if (debugEnabled || true) setDebug(true);
		
		onlyPassword = "true".equals(getSystem().getParam4());
		
		if (useSudo()) {
			sudoprefix = "sudo -S -p "+quote(SUDO_PROMPT)+" "; 
		} else {
			sudoprefix = "";
		}
		try {
			updateAccountsMetadata();
		} catch (IOException e) {
			throw new InternalErrorException("Error registering metadat", e);
		}
		try {
			execute(getTestCommand());
		} catch (ExecutionException e) {
			throw new InternalErrorException("Cannot stablish connection", e);
		}
	}

	private void parseExtendedAttributes() {
		extendedAttributes = new HashMap<>();
		byte[] data = getSystem().getBlobParam();
		if (data != null)
		{
			String t;
			try {
				t = new String ( data,"UTF-8");
				Map m = new HashMap();
				if (t != null)
				{
					for (String tag: t.split("&")) {
						int i = tag.indexOf("=");
						String attribute;
						String v;
						try {
							attribute = i < 0 ? tag: java.net.URLDecoder.decode(tag.substring(0, i), "UTF-8");
							v = i > 0 ? java.net.URLDecoder.decode(tag.substring(i+1), "UTF-8"): null;
							extendedAttributes.put(attribute, v);
						} catch (UnsupportedEncodingException e) {
						}
					}
				}
			} catch (UnsupportedEncodingException e1) {
			} 
		}
	}

	protected String getTestCommand() {
		return "whoami";
	}

	protected boolean useSudo() {
		return ! "root".equals(user);
	}

	protected void updateAccountsMetadata() throws IOException, InternalErrorException {
		AdditionalDataService ds = ! Config.getConfig().isServer() ? 
			new RemoteServiceLocator().getAdditionalDataService() :
			ServiceLocator.instance().getAdditionalDataService();
		checkMetadata("uid", TypeEnumeration.NUMBER_TYPE, "Internal id", ds);
		checkMetadata("gid", TypeEnumeration.NUMBER_TYPE, "Group id", ds);
		checkMetadata("home", TypeEnumeration.STRING_TYPE, "Home directory", ds);
		checkMetadata("shell", TypeEnumeration.STRING_TYPE, "Shell", ds);
	}

	long minOrder = 1;
	protected void checkMetadata(String name, TypeEnumeration type, String description, AdditionalDataService ds) throws InternalErrorException {
		if (ds.findSystemDataType(getAgentName(), name) == null) {
			log.info("Creating "+name+" on "+getAgentName());
			DataType dt = new DataType();
			dt.setBuiltin(Boolean.FALSE);
			dt.setLabel(description);
			dt.setName(name);
			dt.setType(type);
			dt.setMultiValued(false);
			dt.setRequired(false);
			dt.setUnique(false);
			dt.setSystemName(getAgentName());
			for (DataType dt2: ds.findSystemDataTypes2(getAgentName())) {
				if (dt2.getOrder().longValue() >= minOrder)
					minOrder = dt2.getOrder().longValue()+1;
				log.info(">> "+dt2.getCode()+" "+dt2.getOrder()+" -> "+dt.getOrder());
			}
			dt.setOrder( minOrder ++ );
			try {
				ds.create(dt);
			} catch (Exception e) { // Ignore
				
			}
		}
	}

	protected String execute(String parsedSentence) throws ExecutionException, InternalErrorException {
		return execute(parsedSentence, "");
	}
	
	protected String execute(String parsedSentence, String inputData) throws ExecutionException, InternalErrorException {
		try {
			if (tunnel == null || ! tunnel.isConnected()) {
				try {
					tunnel = new SshConnection(this.server, user, keyFile, password, parsedSentence);
				} catch (JSchException e) {
					com.soffid.iam.api.Password p = getServer().getOrGenerateUserPassword(user, getAgentName());
					if (p == null || p.getPassword().equals(password.getPassword()))
						throw e;
					password = new Password( p.getPassword() );
					tunnel = new SshConnection(this.server, user, keyFile, password, parsedSentence);
				}
			} else
				tunnel.exec(parsedSentence);
		} catch (JSchException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} catch (IOException e) {
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		}
		
		try {
			final InputStream in = tunnel.getInputStream();
			final InputStream error = tunnel.getErrorStream();
			final OutputStream out = tunnel.getOutputStream();
			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			final ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
			InputStreamConsumerPassword ec = new InputStreamConsumerPassword(error, out, buffer, charSet, SUDO_PROMPT, password); ec.start();
			if (inputData != null && inputData.length() > 0)
			{
				try {
					Thread.sleep(200);
				} catch (InterruptedException e) { }
				out.write(inputData.getBytes(charSet));
				out.close();
			}
			InputStreamConsumer ic = new InputStreamConsumer(in, buffer, outputBuffer); ic.start();
			final int exitStatus = tunnel.getExitStatus();
			ic.end();
			ec.end();
			if (exitStatus != 0)
			{
				throw new ExecutionException(exitStatus, outputBuffer.toString()+buffer.toString(charSet));
			}
			out.close();
			return outputBuffer.toString(charSet);
		} catch (IOException e) {
			tunnel.close();
			tunnel = null;
			throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
		} finally {
		}
	}

	void sendPassword(InputStream in, OutputStream out, OutputStream log) {
		try {
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int read = in.read(); read >= 0; read = in.read()) {
				log.write(read);
				if (read == '\n')
					buffer = new ByteArrayOutputStream();
				else {
					buffer.write(read);
					if (buffer.toString(charSet).equals(SUDO_PROMPT)) {
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

	@Override
	public void updateUser(com.soffid.iam.api.Account account, User user)
			throws RemoteException, InternalErrorException {
		updateUser(account);
	}

	@Override
	public void updateUser(com.soffid.iam.api.Account account) throws RemoteException, InternalErrorException {
		if (onlyPassword)
			return;
		
		try {
			String homedir = (String) account.getAttributes().get("homedir");
			if (homedir == null || homedir.trim().isEmpty())
				homedir = "/home/"+account.getName();
			String shell = (String) account.getAttributes().get("shell");
			if (shell == null || shell.trim().isEmpty())
				shell = "/bin/bash";
			if (account.isDisabled())
				shell = "/usr/sbin/nologin";
			try {
				execute ("groups "+quote(account.getName()));
				execute(sudoprefix+"/usr/sbin/usermod -c "+quote(account.getDescription())+" -m -d "+quote(homedir)+" --shell "+quote(shell)+" "+quote(account.getName()));
			} catch (ExecutionException e) {
				execute(sudoprefix+"/usr/sbin/useradd -c "+quote(account.getDescription())+" -k /etc/skel -m -d "+quote(homedir)+" --shell "+quote(shell)+" "+quote(account.getName()));
				com.soffid.iam.api.Password p = getServer().getOrGenerateUserPassword(account.getName(), dispatcher.getName());
				execute(sudoprefix+"chpasswd "+quote(account.getName()),
						account.getName()+":"+p.getPassword()+"\n");
			}
			Collection<RoleGrant> grants = getServer().getAccountRoles(account.getName(), account.getSystem());
			List<RoleGrant> grants0 = getAccountGrants(account.getName());
			for (Iterator<RoleGrant> it = grants.iterator(); it.hasNext();) {
				RoleGrant grant = it.next();
				boolean found = false;
				for (RoleGrant grant0: grants0) {
					if (grant0.getRoleName().equals(grant.getRoleName())) {
						found = true;
						grants0.remove(grant0);
						break;
					}
				}
				if (!found) {
					execute(sudoprefix+"usermod -a -G "+quote(grant.getRoleName())+" "+quote(account.getName()));
				}
			}
			for (RoleGrant grant0: grants0) {
				try { 
					execute(sudoprefix+"deluser "+quote(account.getName())+" "+quote(grant0.getRoleName()));
				} catch (ExecutionException e) {}
			}
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public void removeUser(String userName) throws RemoteException, InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getAgentName());
		if (account == null || account.getStatus() != AccountStatus.REMOVED)
			updateUser(account);
		else {
			try {
				try {
					execute ("groups "+quote(account.getName()));
				} catch (ExecutionException e) {
					execute(sudoprefix+"/usr/sbin/userdel -r "+quote(account.getName()));
				}
			} catch (ExecutionException e) {
				throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
			}
			
		}
	}

	@Override
	public void updateUserPassword(String userName, User userData, com.soffid.iam.api.Password password,
			boolean mustchange) throws RemoteException, InternalErrorException {
		try {
			if (isDebug()) {
				log.info(userName+":"+password.getPassword()+"\n");
			}
			execute(sudoprefix+"/usr/sbin/chpasswd "+quote(userName),
					userName+":"+password.getPassword()+"\n");
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.toString());
		}
	}

	@Override
	public boolean validateUserPassword(String userName, com.soffid.iam.api.Password password)
			throws RemoteException, InternalErrorException {
		try {
			SshConnection tunnel = new SshConnection(server, userName, null, new Password(password.getPassword()), "/bin/false") ;
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
			String s = execute("cat /etc/passwd");
			Matcher matcher = Pattern.compile("^([^:]+):", Pattern.MULTILINE+Pattern.UNIX_LINES).matcher(s);
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
			String s = execute("cat /etc/passwd");
			Matcher matcher = Pattern.compile("^([^:]+):", Pattern.MULTILINE+Pattern.UNIX_LINES).matcher(s);
			while (matcher.find()) {
				String un = matcher.group(1);
				if (un.equals(userAccount)) {
					int position = matcher.start();
					Matcher m2 = Pattern.compile("^([^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:\\n]*)").matcher(s.substring(position));
					if (m2.find()) {
						Account acc = new Account();
						acc.setName(un);
						acc.setDescription(m2.group(5));
						HashMap<String, Object> attributes = new HashMap<String, Object>();
						acc.setAttributes(attributes);
						attributes.put("uid", m2.group(3));
						attributes.put("gid", m2.group(4));
						attributes.put("home", m2.group(6));
						String shell = m2.group(7);
						if (shell.endsWith("/nologin") || shell.endsWith("/false") || shell.endsWith("/null"))
						{
							acc.setDisabled(true);
							acc.setStatus(AccountStatus.DISABLED);
						}
						else 
						{
							attributes.put("shell", shell);
							acc.setStatus(AccountStatus.ACTIVE);
						}
						return acc;
					}
				}
			}
			return null;		
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	private String quote(String t) {
		StringBuffer sb2 = new StringBuffer();
		for (char ch: t.toCharArray()) {
			switch (ch) {
				case ' ':
				case '\\':
				case '\'':
				case '\"':
				case '$':
				case '|':
				case ';':
				case '>':
				case '<':
				case '(':
				case ')':
				case '[':
				case ']':
				case '`':
				case '&':
				case '*':
				case '?':
				sb2.append('\\');
			default:
				sb2.append(ch);
					
			}
		}
		return sb2.toString();
	}

	@Override
	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		try {
			List<String> names = new LinkedList<String>();
			String s = execute("cat /etc/group");
			Matcher matcher = Pattern.compile("^([^:]+):", Pattern.MULTILINE+Pattern.UNIX_LINES).matcher(s);
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
	public Role getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		try {
			String s = execute("cat /etc/group");
			Matcher matcher = Pattern.compile("^([^:]+):", Pattern.MULTILINE+Pattern.UNIX_LINES).matcher(s);
			while (matcher.find()) {
				String un = matcher.group(1);
				if (un.equals(roleName)) {
					int position = matcher.start();
					Matcher m2 = Pattern.compile("^([^:]+):([^:]*):([^:\\n]*)").matcher(s.substring(position));
					if (m2.find()) {
						Role role = new Role();
						role.setName(un);
						role.setDescription(un);
						return role;
					}
				}
			}
			return null;		
		} catch (ExecutionException e) {
			throw new InternalErrorException("Error executing command: "+e.getErrorMessage());
		}
	}

	@Override
	public List<RoleGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		try {
			String s = execute("groups "+quote(userAccount));
			int i = s.indexOf(":");
			if (i >= 0) s = s.substring(i+1);
			i = s.indexOf('\n');
			if (i >= 0) s = s.substring(0, i);
			List<RoleGrant> grants = new LinkedList<RoleGrant>();
			for ( String group: s.split(" +")) {
				if (!group.isEmpty()) {
					RoleGrant g = new RoleGrant();
					g.setRoleName(group);
					g.setSystem(getAgentName());
					g.setOwnerAccountName(userAccount);
					g.setOwnerSystem(getAgentName());
					grants.add(g);
				}
			}
			return grants;
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
			Map<String,Object> o = new HashMap<String, Object>();
			l.add(o);
			Account account = getServer().getAccountInfo(command, getSystem().getName());
			if (account == null)
				o.put("passwordStatus", null);
			else 
			{
				com.soffid.iam.api.Password password = getServer().getAccountPassword(command, getSystem().getName());
				o.put("passwordStatus", validateUserPassword(command, password) ? PasswordValidation.PASSWORD_GOOD : PasswordValidation.PASSWORD_WRONG );
				
			}
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
		else if (verb.equals("add-group")) {
			String user = (String) params.get("user");
			String group = (String) params.get("group");
			if (user != null && group != null) {
				try {
					execute(sudoprefix+"adduser "+quote(user)+" "+quote(group));
				} catch (ExecutionException e) {
					throw new InternalErrorException("Error granting group "+group+" to "+user, e);
				}
			}
		}
		else if (verb.equals("delete-group")) {
			String user = (String) params.get("user");
			String group = (String) params.get("group");
			if (user != null && group != null) {
				try {
					execute(sudoprefix+"deluser "+quote(user)+" "+quote(group));
				} catch (ExecutionException e) {
					throw new InternalErrorException("Error granting group "+group+" to "+user, e);
				}
			}
		}
		return l;
	}

	public void removeExtensibleObject(ExtensibleObject soffidObject) throws RemoteException, InternalErrorException {
	}

	public void updateExtensibleObject(ExtensibleObject soffidObject) throws RemoteException, InternalErrorException {
	}
}
