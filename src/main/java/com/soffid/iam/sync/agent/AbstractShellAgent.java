package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.util.Base64;

public abstract class AbstractShellAgent extends Agent {

	private static final String PARSE = "Parse";
	private static final String ERROR = "Error";
	private static final String SUCCESS = "Success";
	private static final String ATTRIBUTES = "Attributes";
	
	ValueObjectMapper vom = new ValueObjectMapper();
	ObjectTranslator objectTranslator = null;
	private static final long serialVersionUID = 1L;
	protected boolean debugEnabled;
	protected boolean xmlOutput = false;
	
	/** Hash algorithm */
	MessageDigest digest = null;
	private Collection<ExtensibleObjectMapping> objectMappings;
	Date lastModification = null;
	protected String passwordPrefix;
	protected String hashType;

	public void init() throws InternalErrorException 
	{
		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}
	}
	
	private String stringify(String str) {
		if (str == null)
			return "";
		StringBuffer sb = new StringBuffer();
		for (char ch : str.toCharArray()) {
			if (ch == 10)
				sb.append("\\n");
			else if (ch == 13)
				sb.append("\\r");
			else if (ch == 9)
				sb.append("\\t");
			else if (ch >= 0 && ch < 32) {
				sb.append("\\");
				sb.append((int) ch);
			} else
				sb.append(ch);
		}
		return sb.toString();
	}

	/**
	 * Funció per obtindre transformar el password a hash per guardar a la bbdd
	 * 
	 * @param password
	 * @return
	 */
	private String getHashPassword(Password password) {
		String hash = null;
		if (digest == null)
			hash = password.getPassword();
		else {
			synchronized (digest) {
				hash = passwordPrefix
						+ Base64.encodeBytes(digest.digest(password
								.getPassword().getBytes()),
								Base64.DONT_BREAK_LINES);
			}
		}
		return hash;
	}

	private LinkedList<String> getTags(Map<String, String> sentences,
			String prefix) {
		LinkedList<String> matches = new LinkedList<String>();
		for (String tag : sentences.keySet()) {
			if (tag.startsWith(prefix) && sentences.get(tag) != null
					&& sentences.get(tag).trim().length() > 0) {
				if (tag.equals(prefix)
						|| Character.isDigit(tag.charAt(prefix.length())))
					matches.add(tag);
			}
		}
		Collections.sort(matches);
		return matches;
	}

	private void updateObject(ExtensibleObject obj, ExtensibleObject soffidObject)
			throws InternalErrorException {
		Map<String, String> properties = objectTranslator
				.getObjectProperties(obj);
		ExtensibleObject existingObject = new ExtensibleObject();
		if (exists(obj, properties, existingObject)) {
			if (preUpdate(soffidObject, obj, existingObject))
			{
				update(obj, properties);
				postUpdate(soffidObject, obj, existingObject);
			}
		} else {
			if (preInsert(soffidObject, obj))
			{
				insert(obj, properties);
				postInsert(soffidObject, obj, obj);
			}
		}
	}

	private void insert(ExtensibleObject obj, Map<String, String> properties)
			throws InternalErrorException {
		debugObject("Creating object", obj, "");
		for (String tag : getTags(properties, "insert")) {
			executeSentence(properties, tag, obj, null);
		}
	}

	protected List<String[]> executeSentence(Map<String, String> properties, String tag, ExtensibleObject obj,
			List<String> columnNames) throws InternalErrorException {
		String sentence = properties.get(tag);
		String errorExpression = properties.get(tag+ERROR);
		String successExpression = properties.get(tag+SUCCESS);
		List<String[]> result = new LinkedList<String[]>();
		if (columnNames != null)
			columnNames.clear();
		StringBuffer b = new StringBuffer ();

		parseSentence(sentence, obj, b);
		
		String parsedSentence = b.toString().trim();

		String text;
		try {
			text = actualExecute( parsedSentence);
		} catch (InternalErrorException e) {
			throw new InternalErrorException ("Error executing "+sentence, e);
		}
		
		parseExecutionResult(tag, properties, text, columnNames, result);
		
		if ( successExpression != null && ! Pattern.matches(successExpression, text))
		{
			throw new InternalErrorException ("Error executing sentence: "+text);
		}
		
		if (errorExpression != null && Pattern.matches(errorExpression, text))
		{
			throw new InternalErrorException ("Error executing sentence: "+text);
		}
		return result;
		
	}

	protected void parseExecutionResult(String tag,
			Map<String, String> properties, String text, 
			List<String> columnNames,
			List<String[]> result)
			throws InternalErrorException {
		String parseExpression = properties.get(tag+PARSE);
		if ( xmlOutput)
		{
			NodeList list;
			try {
				Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(text);
				XPath xpath = XPathFactory.newInstance().newXPath();
				if (parseExpression != null && parseExpression.trim().length() > 0)
					list = (NodeList) xpath.compile(parseExpression).evaluate(doc, XPathConstants.NODESET);
				else
					list = (NodeList) xpath.compile("/").evaluate(doc, XPathConstants.NODESET);
			} catch (XPathExpressionException e) {
				throw new InternalErrorException("Error evaluating XPATH expression "+parseExpression);
			} catch (SAXException e) {
				throw new InternalErrorException("Error parsing result "+text);
			} catch (IOException e) {
				throw new InternalErrorException("Error parsing result "+text);
			} catch (ParserConfigurationException e) {
				throw new InternalErrorException("Error parsing result: "+text);
			}
			for ( int i = 0; i < list.getLength(); i ++)
			{
				List<String> row = new LinkedList<String>();
				Node n = list.item(i);
				if (columnNames != null)
					populate (columnNames, row, "", n);
				else
					row.add(n.getTextContent());
				result.add(row.toArray(new String[row.size()]));
			}
		} 
		else if ( parseExpression != null && parseExpression.trim().length() > 0)
		{
			Pattern pattern = Pattern.compile(parseExpression);
			Matcher matcher = pattern.matcher(text);
			if (columnNames != null)
			{
				String attributes = properties.get(tag+ ATTRIBUTES);
				if (attributes != null)
				{
					for (String header : attributes .split("[ ,]+"))
					{
						columnNames.add(header);
					}
				}
			}

			while (matcher.find())
			{
				if (debugEnabled)
					log.info ("Found on position "+matcher.start());
				int count = matcher.groupCount();
				String row [] = new String[count+1];
				for (int i = 0; i <= count; i++)
					row[i] = matcher.group(i);
				result.add(row);
				if (columnNames != null)
				{
					while (columnNames.size() < row.length)
					{
						columnNames.add("" + columnNames.size());
					}
				}
			}
		}
		else
		{
			if (columnNames != null)
				columnNames.add("1");
			result.add(new String[] {text});
		}
	}

	protected void populate(List<String> columnNames, List<String> row, String name, Node n) {
		if (n instanceof Element)
		{
			for (int i = 0; i < n.getAttributes().getLength(); i++)
			{
				Attr att = (Attr) n.getAttributes().item(i);
				populate (columnNames, row, name+"@"+att.getLocalName(), att.getValue());
			}
			populate (columnNames, row, name+"/text()", n.getTextContent());
		}
	}

	protected void populate(List<String> columnNames, List<String> row, String name, String s) {
		int i = 0;
		for (i = 0; i < columnNames.size() ; i++)
		{
			if (columnNames.get(i).equals(name))
			{
				break;
			}
		}
		if (i == columnNames.size())
		{
			columnNames.add(name);
		}
		while (row.size() <= i)
			row.add(null);
		row.set(i, s);
	}

	protected abstract String actualExecute(String parsedSentence) throws InternalErrorException ;

	private void delete(ExtensibleObject obj, Map<String, String> properties, ExtensibleObject soffidObject)
			throws InternalErrorException {
		ExtensibleObject existingObject = new ExtensibleObject();
		if (exists(obj, properties, existingObject)) 
		{
			if (preDelete(soffidObject, obj))
			{
				debugObject("Removing object", obj, "");
				for (String tag : getTags(properties, "delete")) {
					executeSentence(properties, tag, obj, null);
				}
				postDelete(soffidObject, obj);
			}
		}
	}

	private void update(ExtensibleObject obj, Map<String, String> properties)
			throws InternalErrorException {
		debugObject("Updating object", obj, "");
		for (String tag : getTags(properties, "update")) {
			executeSentence(properties, tag, obj, null);
		}
	}

	private boolean exists(ExtensibleObject obj, Map<String, String> properties, ExtensibleObject existingObject)
			throws InternalErrorException {
		
		for (String tag : getTags(properties, "check")) {
			List<String> columnNames = new LinkedList<String>();
			List<String[]> rows = executeSentence(properties, tag, obj, columnNames );
			if (!rows.isEmpty()) {
				if (debugEnabled)
					log.info("Object already exists");
				String row[] = rows.get(0);
				for (int i = 0 ; i < row.length; i++)
				{
					existingObject.setAttribute(columnNames.get(i), row[i]);
				}
				return true;
			}
		}
		if (debugEnabled)
			log.info("Object does not exist");
		return false;
	}

	private boolean passFilter(String filter, ExtensibleObject eo,
			ExtensibleObject query) throws InternalErrorException {
		if (filter == null || filter.trim().length() == 0)
			return true;

		eo.setAttribute("query", query);
		Object obj = objectTranslator.eval(filter, eo);
		if (obj == null || Boolean.FALSE.equals(obj))
			return false;
		else
			return true;
	}

	protected void parseSentence(String sentence, ExtensibleObject obj,
			StringBuffer parsedSentence) {
		int position = 0;
		// First, transforma sentence into a valid SQL API sentence
		do {
			int nextBack = sentence.indexOf('\\', position);
			int nextDollar = sentence.indexOf('$', position);
			if (nextBack < 0 && nextDollar < 0) {
				parsedSentence.append(sentence.substring(position));
				position = sentence.length();
			} else if (nextBack >= 0 && nextDollar > nextBack) {
				parsedSentence.append(sentence.substring(position, nextBack));
				if (nextBack + 1 < sentence.length())
					parsedSentence.append(sentence.charAt(nextBack + 1));
				position = nextBack + 2;
			} else {
				parsedSentence.append(sentence.substring(position, nextDollar));
				int paramStart = nextDollar + 1;
				int paramEnd = paramStart;
				String param;
				if (sentence.charAt(paramEnd) == '{')
				{
					int i = 1;
					paramEnd ++;
					while (i > 0 && paramEnd < sentence.length())
					{
						if (sentence.charAt(paramEnd) == '{')
							i ++;
						else if (sentence.charAt(paramEnd) == '}')
							i --;
						paramEnd ++;
					}
					param = sentence.substring(paramStart+1, paramEnd-1);
				}
				else
				{
					while (paramEnd < sentence.length()
							&& Character.isJavaIdentifierPart(sentence
									.charAt(paramEnd))) {
						paramEnd++;
					}
					param = sentence.substring(paramStart, paramEnd);
				}
				Object paramValue = obj.getAttribute(param);
				parsedSentence.append(paramValue);
				position = paramEnd;
			}
		} while (position < sentence.length());
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);

	}

	Date lastCommitedModification = null;
	long lastChangeId = 0;
	HashSet<Long> pendingChanges = new HashSet<Long>();

	public AbstractShellAgent() {
		super();
	}

	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {

		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		ExtensibleObject emptyObject = new ExtensibleObject();
		emptyObject.setAttribute("LASTCHANGE", lastCommitedModification);

		lastModification = new Date();
		LinkedList<Long> changeIds = new LinkedList<Long>();

		for (ExtensibleObjectMapping objMapping : objectMappings) {
			if (objMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_USER)
					|| objMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE)) {
				for (String tag : getTags(objMapping.getProperties(),
						"selectAll")) {
					String filter = objMapping.getProperties().get(tag + PARSE);
					String sentence = objMapping.getProperties().get(tag);
					List<String> columnNames = new LinkedList<String>();
					List<String[]> rows = executeSentence(objMapping.getProperties(), tag, emptyObject, columnNames );
					for (Object[] row : rows) {
						ExtensibleObject resultObject = new ExtensibleObject();
						resultObject
								.setObjectType(objMapping.getSystemObject());
						for (int i = 0; i < row.length; i++) {
							String param = columnNames.get(i);
							if (resultObject.getAttribute(param) == null) {
								resultObject.setAttribute(param, row[i]);
							}
						}
						debugObject("Got authoritative change", resultObject,
								"");
						if (!passFilter(filter, resultObject, null))
							log.info("Discarding row");
						else {
							ExtensibleObject translated = objectTranslator
									.parseInputObject(resultObject, objMapping);
							debugObject("Translated to", translated, "");
							AuthoritativeChange ch = new ValueObjectMapper()
									.parseAuthoritativeChange(translated);
							if (ch != null) {
								changes.add(ch);
							} else {
								Usuari usuari = new ValueObjectMapper()
										.parseUsuari(translated);
								if (usuari != null) {
									if (debugEnabled && usuari != null)
										log.info("Result user: "
												+ usuari.toString());
									Long changeId = new Long(lastChangeId++);
									ch = new AuthoritativeChange();
									ch.setId(new AuthoritativeChangeIdentifier());
									ch.getId().setInternalId(changeId);
									ch.setUser(usuari);
									Map<String, Object> userAttributes = (Map<String, Object>) translated
											.getAttribute("attributes");
									ch.setAttributes(userAttributes);
									changes.add(ch);
									changeIds.add(changeId);
								}
							}
						}
					}
				}
			}
		}
		pendingChanges.addAll(changeIds);
		return changes;
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
		pendingChanges.remove(id.getInternalId());
		if (pendingChanges.isEmpty())
			lastCommitedModification = lastModification;
	}

	public void updateRole(Rol role) throws RemoteException,
			InternalErrorException {
		ExtensibleObject soffidObject = new RoleExtensibleObject(role,
				getServer());

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				updateObject(systemObject, soffidObject);
			}
		}
		// Next update role members

		try {
			updateRoleMembers(
					role,
					getServer().getRoleAccounts(role.getId(),
							getDispatcher().getCodi()));
		} catch (UnknownRoleException e) {
			throw new InternalErrorException("Error updating role", e);
		}
	}

	private void updateRoleMembers(Rol role, Collection<Account> initialGrants)
			throws InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setRolName(role.getNom());
		grant.setDispatcher(role.getBaseDeDades());
		grant.setOwnerDispatcher(role.getBaseDeDades());

		GrantExtensibleObject sample = new GrantExtensibleObject(grant,
				getServer());
		ValueObjectMapper vom = new ValueObjectMapper();

		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_GRANTED_ROLE)
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_ALL_GRANTED_ROLES)) {
				// First get existing roles
				LinkedList<ExtensibleObject> existingRoles = new LinkedList<ExtensibleObject>();
				boolean foundSelect = false;
				for (String tag : getTags(objectMapping.getProperties(),
						"selectByRole")) {
					existingRoles
							.addAll(selectSystemObjects(
									sample,
									objectMapping,
									tag));
					foundSelect = true;
				}
				if (foundSelect) {
					// Now get roles to have
					Collection<Account> grants = new LinkedList<Account>(
							initialGrants);
					// Now add non existing roles
					for (Iterator<Account> accountIterator = grants.iterator(); accountIterator
							.hasNext();) {
						Account account = accountIterator.next();

						// Check if this account is already granted
						boolean found = false;
						for (Iterator<ExtensibleObject> objectIterator = existingRoles
								.iterator(); !found && objectIterator.hasNext();) {
							ExtensibleObject object = objectIterator.next();
							String accountName = vom
									.toSingleString(objectTranslator
											.parseInputAttribute(
													"ownerAccount", object,
													objectMapping));
							if (accountName != null
									&& accountName.equals(account.getName())) {
								objectIterator.remove();
								found = true;
							}
						}
						if (!found) {
							RolGrant rg = new RolGrant();
							rg.setOwnerAccountName(account.getName());
							rg.setOwnerDispatcher(account.getDispatcher());
							rg.setRolName(role.getNom());
							rg.setDispatcher(role.getBaseDeDades());
							ExtensibleObject object = objectTranslator
									.generateObject(new GrantExtensibleObject(
											rg, getServer()), objectMapping);
							updateObject(object, object);
						}
					}
					// Now remove unneeded grants
					for (Iterator<ExtensibleObject> objectIterator = existingRoles
							.iterator(); objectIterator.hasNext();) {
						ExtensibleObject object = objectIterator.next();
						ExtensibleObject eo = new ExtensibleObject();
						eo.setObjectType(objectMapping.getSoffidObject().toString());
						delete(object, objectMapping.getProperties(), eo);
					}
				}
			}
		}

	}

	private Collection<? extends ExtensibleObject> selectSystemObjects(
			ExtensibleObject sample, ExtensibleObjectMapping objectMapping,
			String tag)
			throws InternalErrorException {
		List<ExtensibleObject> result = new LinkedList<ExtensibleObject>();

		List<String> columnNames = new LinkedList<String>();
		List<String[]> rows = executeSentence(objectMapping.getProperties(), tag, sample, columnNames );
		for (Object[] row : rows) {
			StringBuffer buffer = new StringBuffer();
			ExtensibleObject rowObject = new ExtensibleObject();
			rowObject.setObjectType(objectMapping.getSystemObject());
			for (int i = 0; i < row.length; i++) {
				rowObject.setAttribute(columnNames.get(i), row[i]);

				if (debugEnabled) {
					if (i == 0)
						buffer.append("ROW: ");
					else
						buffer.append(", ");
					if (row[i] == null)
						buffer.append("NULL");
					else
						buffer.append(row[i].toString());
				}
			}
			log.info(stringify(buffer.toString()));
			result.add(rowObject);
		}
		return result;
	}

	public void removeRole(String rolName, String dispatcher)
			throws RemoteException, InternalErrorException {
		Rol role = new Rol();
		role.setNom(rolName);
		role.setBaseDeDades(dispatcher);
		ExtensibleObject soffidObject = new RoleExtensibleObject(role,
				getServer());

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				delete(systemObject, objectMapping.getProperties(), soffidObject);
			}
		}
		// Next remove role members
		Collection<Account> emptyList = Collections.emptyList();
		updateRoleMembers(role, emptyList);
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {

		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> accountNames = new LinkedList<String>();
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				for (String tag : getTags(objectMapping.getProperties(),
						"selectAll")) {
					for (ExtensibleObject obj : selectSystemObjects(sample,
							objectMapping, tag)) {
						debugObject("Got system object", obj, "");
						String accountName = vom
								.toSingleString(objectTranslator
										.parseInputAttribute("accountName",
												obj, objectMapping));
						if (debugEnabled)
							log.info("Account name = " + stringify(accountName));
						if (accountName != null && ! accountName.isEmpty())
							accountNames.add(accountName);
					}
				}
			}
		}

		return accountNames;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Account acc = new Account();
		acc.setName(userAccount);
		acc.setDispatcher(getCodi());
		ExtensibleObject sample = new AccountExtensibleObject(acc, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, objectMapping);
				for (String tag : getTags(objectMapping.getProperties(),
						"selectByAccountName")) {
					for (ExtensibleObject obj : selectSystemObjects(
							translatedSample, objectMapping, tag)) {
						debugObject("Got account system object", obj, "");
						ExtensibleObject soffidObj = objectTranslator
								.parseInputObject(obj, objectMapping);
						debugObject("Translated account soffid object",
								soffidObj, "");

						if (objectMapping.getSoffidObject().equals(
								SoffidObjectType.OBJECT_ACCOUNT)) {
							Account acc2 = vom.parseAccount(soffidObj);
							if (debugEnabled) {
								log.info("Resulting account: "
										+ stringify(acc2.toString()));
							}
							return acc2;
						} else {
							Usuari u = vom.parseUsuari(soffidObj);
							Account acc2 = vom.parseAccount(soffidObj);
							acc2.setDispatcher(getCodi());
							if (acc2.getName() == null)
								acc2.setName(u.getCodi());
							if (acc2.getDescription() == null)
								acc2.setDescription(u.getFullName());
							if (acc2.getDescription() == null)
								acc2.setDescription(u.getNom() + " "
										+ u.getPrimerLlinatge());
							log.info("Resulting account: "
									+ stringify(acc2.toString()));
							return acc2;
						}
					}
				}
			}
		}

		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> roleNames = new LinkedList<String>();
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				for (String tag : getTags(objectMapping.getProperties(),
						"selectAll")) {
					for (ExtensibleObject obj : selectSystemObjects(sample,
							objectMapping,
							tag)) {
						debugObject("Got role object", obj, "");
						String roleName = vom
								.toSingleString(objectTranslator
										.parseInputAttribute("name", obj,
												objectMapping));
						if (debugEnabled)
							log.info("Role name = " + stringify(roleName));
						roleNames.add(roleName);
					}
				}
			}
		}

		return roleNames;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Rol r = new Rol();
		r.setNom(roleName);
		r.setBaseDeDades(getCodi());
		ExtensibleObject sample = new RoleExtensibleObject(r, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				ExtensibleObjectMapping eom2 = new ExtensibleObjectMapping(
						objectMapping);
				eom2.setAttributes(objectMapping.getAttributes());
				eom2.setProperties(objectMapping.getProperties());
				eom2.setCondition(null);
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, eom2);
				if (translatedSample != null) {
					for (String tag : getTags(objectMapping.getProperties(),
							"selectByName")) {
						for (ExtensibleObject obj : selectSystemObjects(
								translatedSample,
								objectMapping,
								tag)) {
							debugObject("Got system role object", obj, "");
							ExtensibleObject soffidObj = objectTranslator
									.parseInputObject(obj, objectMapping);
							debugObject("Translated soffid role object",
									soffidObj, "");
							return vom.parseRol(soffidObj);
						}
					}
				}
			}
		}

		return null;
	}

	public List<RolGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setOwnerAccountName(userAccount);
		grant.setDispatcher(getCodi());
		grant.setOwnerDispatcher(getCodi());

		GrantExtensibleObject sample = new GrantExtensibleObject(grant,
				getServer());
		ValueObjectMapper vom = new ValueObjectMapper();
		List<RolGrant> result = new LinkedList<RolGrant>();

		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_GRANTED_ROLE)
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_ALL_GRANTED_ROLES)) {
				// First get existing roles
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, objectMapping, true);
				Collection<? extends ExtensibleObject> existingRoles;
				for (String tag : getTags(objectMapping.getProperties(),
						"selectByAccount")) {
					existingRoles = selectSystemObjects(translatedSample,
							objectMapping,
							tag);
					for (Iterator<? extends ExtensibleObject> objectIterator = existingRoles
							.iterator(); objectIterator.hasNext();) {
						ExtensibleObject object = objectIterator.next();
						debugObject("Got system grant object", object, null);
						ExtensibleObject soffidObject = objectTranslator
								.parseInputObject(object, objectMapping);
						debugObject("Translated soffid grant object",
								soffidObject, null);
						grant = vom.parseGrant(soffidObject);
						if (debugEnabled)
							log.info("Resulting grant = " + grant.toString());
						result.add(grant);
					}
				}
			}
		}
		return result;
	}

	public void updateUser(String accountName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);
		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_USER)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				updateObject(systemObject, soffidObject);
			}
		}
		// Next update role members

		updateUserRoles(accountName, null,
				getServer().getAccountRoles(accountName, getCodi()),
				getServer().getAccountExplicitRoles(accountName, getCodi()));
	}

	private String getAccountPassword(String accountName)
			throws InternalErrorException {
		String password;
		Password p = getServer().getAccountPassword(accountName, getCodi());
		if (p == null) {
			p = getServer().generateFakePassword(accountName, getCodi());
		}
		password = getHashPassword(p);
		return password;
	}

	private void updateUserRoles(String accountName, Usuari userData,
			Collection<RolGrant> allGrants, Collection<RolGrant> explicitGrants)
			throws InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setOwnerAccountName(accountName);
		grant.setDispatcher(getCodi());
		grant.setOwnerDispatcher(getCodi());

		ValueObjectMapper vom = new ValueObjectMapper();

		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_GRANTED_ROLE)
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_GRANT)
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_ALL_GRANTED_ROLES)) {
				ExtensibleObject sample = objectTranslator.generateObject(
						new GrantExtensibleObject(grant, getServer()),
						objectMapping);
				// First get existing roles
				LinkedList<ExtensibleObject> existingRoles = new LinkedList<ExtensibleObject>();
				boolean foundSelect = false;
				for (String tag : getTags(objectMapping.getProperties(),
						"selectByAccount")) {
					existingRoles
							.addAll(selectSystemObjects(
									sample,
									objectMapping,
									tag));
					foundSelect = true;
				}
				if (foundSelect) {
					// Now get roles to have
					Collection<RolGrant> grants = objectMapping
							.getSoffidObject().equals(
									SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ? new LinkedList<RolGrant>(
							allGrants) : new LinkedList<RolGrant>(
							explicitGrants);
					// Now add non existing roles
					for (Iterator<RolGrant> grantIterator = grants.iterator(); grantIterator
							.hasNext();) {
						RolGrant newGrant = grantIterator.next();

						if (debugEnabled)
							log.info("Testing rol grant " + newGrant);

						// Check if this account is already granted
						boolean found = false;
						for (Iterator<ExtensibleObject> objectIterator = existingRoles
								.iterator(); !found && objectIterator.hasNext();) {
							ExtensibleObject object = objectIterator.next();
							String roleName = vom
									.toSingleString(objectTranslator
											.parseInputAttribute("grantedRole",
													object, objectMapping));
							if (roleName != null
									&& roleName.equals(newGrant.getRolName())) {
								String domainValue = vom
										.toSingleString(objectTranslator
												.parseInputAttribute(
														"domainValue", object,
														objectMapping));
								if (domainValue == null
										&& newGrant.getDomainValue() == null
										|| newGrant.getDomainValue() != null
										&& newGrant.getDomainValue().equals(
												domainValue)) {
									objectIterator.remove();
									if (debugEnabled)
										debugObject("Found rol grant "
												+ newGrant + ": ", object, "");
									found = true;
								}
							}
						}
						if (!found) {
							newGrant.setOwnerAccountName(accountName);
							newGrant.setOwnerDispatcher(getCodi());
							GrantExtensibleObject soffidObject = new GrantExtensibleObject(
									newGrant, getServer());
							ExtensibleObject object = objectTranslator
									.generateObject(soffidObject,
											objectMapping);
							debugObject("Role to grant: ", object, "");
							updateObject(object, soffidObject);
						}
					}
					// Now remove unneeded grants
					for (Iterator<ExtensibleObject> objectIterator = existingRoles
							.iterator(); objectIterator.hasNext();) {
						ExtensibleObject object = objectIterator.next();
						debugObject("Role to revoke: ", object, "");
						ExtensibleObject eo = new ExtensibleObject();
						eo.setObjectType(objectMapping.getSoffidObject().getValue());
						delete(object, objectMapping.getProperties(), eo);
					}
				}
			}
		}

	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());
		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);

		if (debugEnabled)
		{
			log.info("Updating account "+acc.toString() );
		}
		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				updateObject(systemObject, soffidObject);
			}
		}
		// Next update role members

		updateUserRoles(accountName, null,
				getServer().getAccountRoles(accountName, getCodi()),
				getServer().getAccountExplicitRoles(accountName, getCodi()));
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(null);
		acc.setDisabled(true);
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject sqlobject = objectTranslator.generateObject(
						soffidObject, objectMapping);
				delete(sqlobject, objectMapping.getProperties(), soffidObject);
			}
		}
	}

	public void updateUserPassword(String accountName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {

		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		soffidObject.put("password", getHashPassword(password));
		soffidObject.put("mustChangePassword", mustchange);

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)
					&& userData == null
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_USER) && userData != null) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				Map<String, String> properties = objectTranslator
						.getObjectProperties(systemObject);

				LinkedList<String> updatePasswordTags = getTags(properties,
						"updatePassword");
				ExtensibleObject existingObject = new ExtensibleObject();
				if (!exists(systemObject, properties, existingObject )) {
					if (preInsert(soffidObject, systemObject))
					{
						insert(systemObject, properties);
						postInsert(soffidObject, systemObject, systemObject);
					}
				}

				if ( preUpdate(soffidObject, systemObject, existingObject))
				{
							
					if (updatePasswordTags.isEmpty())
						update(systemObject, properties);
					else {
						for (String s : updatePasswordTags) {
							executeSentence(properties, s, systemObject, null);
						}
					}
					preUpdate(soffidObject, systemObject, existingObject);
				}
			}
		}
	}

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, null,
				getServer());

		soffidObject.put("password", getHashPassword(password));

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_USER)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping, true);
				Map<String, String> properties = objectTranslator
						.getObjectProperties(systemObject);

				LinkedList<String> updatePasswordTags = getTags(properties,
						"validatePassword");
				for (String s : updatePasswordTags) {
					try {
						String filter = properties.get(s + PARSE);
						List<String[]> r = executeSentence(properties, s,
								systemObject, null);
						if (filter == null || !r.isEmpty())
							return true;
						if (properties.get(s+SUCCESS) != null)
							return true;
					} catch (InternalErrorException e) {
						log.info("Unable to authenticate password for user "
								+ accountName, e);
					}
				}
			}
		}
		return false;
	}

	void debugObject(String msg, Map<String, Object> obj, String indent) {
		if (debugEnabled) {
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(indent + msg);
			for (String attribute : obj.keySet()) {
				Object subObj = obj.get(attribute);
				if (subObj == null) {
					log.info(indent + attribute.toString() + ": null");
				} else if (subObj instanceof Map) {
					log.info(indent + attribute.toString() + ": Object {");
					debugObject(null, (Map<String, Object>) subObj, indent
							+ "   ");
					log.info(indent + "}");
				} else {
					log.info(indent + attribute.toString() + ": "
							+ stringify(subObj.toString()));
				}
			}
		}
	}

	
	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject newObject,
			ExtensibleObject existingObject) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (newObject == null || newObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", newObject);
						eo.setAttribute("oldObject", existingObject);
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								if (existingObject != null)
									debugObject("old object", existingObject, "  ");
								if (newObject != null)
									debugObject("new object", newObject, "  ");
							} 
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, adObject, null);
	}

	protected boolean preDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, null, currentEntry);
	}

	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, adObject, currentEntry);
	}

	protected boolean postDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject,  null, currentEntry);
	}

}