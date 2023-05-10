package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.soffid.iam.api.HostService;
import com.soffid.iam.sync.agent.shell.ExitOnPromptInputStream;
import com.soffid.iam.sync.agent.shell.PowerShellTunnelPool;

import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agent to manage relational databases
 * 
 * Parameters:
 * 
 * 0 User name
 * 1 Password
 * 2 JDBC URL
 * 3 Password hash alogithm
 * 4 Password hash prefix
 * 5 Debug
 * 6 Driver type: Oracle / MySQL / PostgreSql / SQLServer
 * <P>
 */

public class PowerShellAgent extends AbstractShellAgent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr, MailAliasMgr,
	AuthoritativeIdentitySource {

	static String lock = new String("Lock");
	String shell;

	boolean persistentShell;
	// ShellTunnel shellTunnel;
	static Map<String,PowerShellTunnelPool> pools = new HashMap<String, PowerShellTunnelPool>();
	String xmlOutFile;
	String prompt;
	String initialCommand;
	protected String pscFile;

	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public PowerShellAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		super.init();
		log.info("Starting Power Shell Agent agent on {}", getDispatcher().getCodi(),
				null);
		if (pscFile == null)
			shell = "powershell -NonInteractive -Command -";
		else
			shell = "powershell -PSConsoleFile \""+pscFile+"\" -NonInteractive -Command -";
		persistentShell = true;
		xmlOutput = true;
		initialCommand = getDispatcher().getParam6();
		try {
			xmlOutFile = Config.getConfig().getLogDir()+"\\ps."+hashCode()+".xml";
		} catch (IOException e1) {
			throw new InternalErrorException ("Error configuring PowerShell agent", e1);
		}
		
		try {
			String s = encodeHex(MessageDigest.getInstance("SHA-1").digest(getCodi().getBytes(StandardCharsets.UTF_8)));
			prompt = "----soffid----prompt-"+s+"----";
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA-1 encryption algorithm ", e);
		}
		
		
		log.info("Prompt: "+prompt);
		hashType = null;
		passwordPrefix = null;
		
		debugEnabled = "true".equals(getDispatcher().getParam5());

		if (debugEnabled)
			log.info ("Enabled DEBUG mode");
			

		initPool();
		
		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use "+hashType+" encryption algorithm ", e);
		}
	}

	
	final static char[] HEX = "0123456789ABCDEF".toCharArray(); 
	private String encodeHex(byte[] digest) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < digest.length; i++) {
			byte b = digest[i];
			sb.append(HEX[(b >> 8) & 0x0f]);
			sb.append(HEX[b & 0x0f]);
		}
		return sb.toString();
	}

	public void close () {
		new File(xmlOutFile).delete();
		super.close();
	}


	protected void initPool() throws InternalErrorException {
		final String poolName = getTunnelPoolName();
		PowerShellTunnelPool pool = pools.get(poolName);
		if (pool == null) {
			pool = new PowerShellTunnelPool();
			pool.setShell(shell);
			pool.setPersistentShell(persistentShell);
			pool.setPrompt(prompt);
			pool.setDebugEnabled(debugEnabled);
			pool.setLog(log);
			pool.setInitialCommand(initialCommand);
			pool.setTimeout(30 * 60  * 1000); //30 mins max idle time for a power shell
			pool.setMaxUnusedTime(60 * 60 * 1000); // 1 hour not used timeout
			pools.put(poolName, pool);
		}
	}

	protected String getTunnelPoolName() {
		return getCodi()+" "+shell+" "+initialCommand;
	}

	public void restart() {
		log.info("Detected severe error. Restarting");
		new Thread(new Runnable() {
			public void run() {
				try {
					Thread.sleep(2000);
				} catch (InterruptedException e) {}
				System.exit(1);
			}
			
		}).start();
	}



	
	@Override
	protected String actualExecute(String parsedSentence) throws InternalErrorException {
		if (debugEnabled)
		{ 
			log.info("Executing "+parsedSentence);
		}
		
		final String poolName = getTunnelPoolName();
		PowerShellTunnelPool pool = pools.get(poolName);
		ShellTunnel shellTunnel;
		try {
			shellTunnel = pool.getConnection();
		} catch (Exception e2) {
			throw new InternalErrorException("Error creating power shell", e2);
		}
		File out = new File(xmlOutFile);
		try {
			try {
				out.delete();
				ExitOnPromptInputStream in;
				try {
					shellTunnel.idle();
					in = shellTunnel.execute(parsedSentence + "| Export-CliXML \""+xmlOutFile+"\" ; echo \"\"; echo \""+prompt+"\";\r\n");
				} catch (IOException e) {
					shellTunnel.closeShell();
					if (false)
					{
						log.warn("Tunnel is not working. Restarting", e);
						try {
							Thread.currentThread().sleep(1000);
						} catch (InterruptedException e1) {
						}
						System.exit(3);
					}
					throw e;
				}
				// Consume input
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();
				for (int i  = in.read(); i >= 0; i = in.read())
				{
					buffer.write(i);
				}
				shellTunnel.idle();
				
				if ((out.length() == 0 && buffer.size() > 0 ) || !out.canRead() || in.hasError())
				{
					if (buffer.toString().replaceAll("\\s", "").contains("ManagementObjectNotFoundException") &&
							parsedSentence.trim().toLowerCase().startsWith("get-"))
						return "";
					else
						throw new InternalErrorException("Error executing remote command :"+buffer.toString());
				}
				
				InputStream in2 = new FileInputStream(out);			// Consume xml file
				buffer = new ByteArrayOutputStream();
				for (int i  = in2.read(); i >= 0; i = in2.read())
				{
					buffer.write(i);
				}
				byte ba[] = buffer.toByteArray();
				if (ba.length  >= 2 && ba[0] == -2 && ba[1] == -1)
				{
					return new String(ba, 2, ba.length - 2, "UTF-16BE");
				}
				else if (ba.length  >= 2 && ba[0] == -1 && ba[1] == -2)
				{
					return new String(ba, 2, ba.length - 2, "UTF-16LE");
				}
				else
				{
	//				log.info("No header: " + ba[0] + " "+ ba[1]);
					return buffer.toString();
				}
			} catch (IOException e) {
				
				throw new InternalErrorException("Error executing remote command :"+e.getMessage(), e);
			}
		} finally {
			out.delete();
			pool.returnConnection();
		}
	}
	
	protected void parseExecutionResult(String tag,
			Map<String, String> properties, String text, 
			List<String> columnNames,
			List<String[]> result)
			throws InternalErrorException {
		
		if (text == null || text.trim().isEmpty())
			return;
		
		NodeList list;
		XPathExpression expr;
		try {
			DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
			builderFactory.setNamespaceAware(false);
			builderFactory.setValidating(false);
			builderFactory.setXIncludeAware(false);
			Document doc = builderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(text)));
			expr = XPathFactory.newInstance().newXPath().compile("Obj");
			list = (NodeList) expr.evaluate(doc.getDocumentElement(), XPathConstants.NODESET);
		} catch (XPathExpressionException e) {
			throw new InternalErrorException("Error evaluating XPATH expression: "+e.getMessage()+"\n", e);
		} catch (SAXException e) {
			log.warn("Error decoding message", e);
			throw new InternalErrorException("Error parsing result: "+e.getMessage()+"\n"+text, e);
		} catch (IOException e) {
			log.warn("Error decoding message", e);
			throw new InternalErrorException("Error parsing result: "+e.getMessage()+"\n"+text, e);
		} catch (ParserConfigurationException e) {
			log.warn("Error decoding message", e);
			throw new InternalErrorException("Error parsing result: "+e.getMessage()+"\n"+text, e);
		}
		
		for ( int i = 0; i < list.getLength(); i ++)
		{
			List<String> row = new LinkedList<String>();
			Node n = list.item(i);
			if (columnNames != null)
				fetchObject (columnNames, row, n, "");
			result.add(row.toArray(new String[row.size()]));
		}
	}

	private void fetchObject(List<String> columnNames, List<String> row, Node n, String prefix) {
		NodeList children = n.getChildNodes();
		for (int i = 0; i < children.getLength(); i++)
		{
			Node child = children.item(i);
			if (child instanceof Element)
			{
				String tag = ((Element) child).getTagName();
				String name = ((Element) child).getAttribute("N");
				String fqn = prefix + 
						( !prefix.isEmpty() && name != null && ! name.isEmpty() ? ".": "") + 
						( name != null ? name: "");
				if ("S".equals(tag) || "B".equals(tag) ||
						"I32".equals(tag) || "G".equals(tag) ||
						"BA".equals(tag) || "DT".equals(tag))
				{
					populate(columnNames, row, fqn, child.getTextContent());
				}
				else if ("Props".equals(tag) || "Obj".equals(tag) || "MS".equals(tag))
				{
					fetchObject(columnNames, row, child, fqn);					
				}
				else if ("DCT".equals(tag) || "Obj".equals(tag))
				{
					fetchEntries(columnNames, row, child, fqn);					
				}
				else if ("LST".equals(tag))
				{
					fetchList(columnNames, row, child, fqn);					
				}
			}
		}
		
	}

	private void fetchEntries(List<String> columnNames, List<String> row, Node n, String prefix) {
		NodeList children = n.getChildNodes();
		for (int i = 0; i < children.getLength(); i++)
		{
			Node child = children.item(i);
			if (child instanceof Element)
			{
				String tag = ((Element) child).getTagName();
				if ("En".equals(tag) )
				{
					fetchEntry(columnNames, row, child, prefix);
				}
			}
		}
	}

	private void fetchEntry(List<String> columnNames, List<String> row, Node n, String prefix) {
		NodeList children = n.getChildNodes();
		String key = null;
		String value = "";
		for (int i = 0; i < children.getLength(); i++)
		{
			Node child = children.item(i);
			if (child instanceof Element)
			{
				String tag = ((Element) child).getTagName();
				String name = ((Element) child).getAttribute("N");
				if ("S".equals(tag) && name.equals("Key")) 
				{
					key = child.getTextContent();
				}
				if ("S".equals(tag) && name.equals("Value")) 
				{
					value = child.getTextContent();
				}
			}
		}
		if (key != null)
		{
			String fqn = prefix + 
					( !prefix.isEmpty() && key != null && ! key.isEmpty() ? ".": "") + 
					( key != null ? key: "");
			populate(columnNames, row, fqn, value);
		}
	}


	private void fetchList(List<String> columnNames, List<String> row,
			Node n, String fqn) {
		StringBuffer sb = new StringBuffer ();
		
		NodeList children = n.getChildNodes();
		for (int i = 0; i < children.getLength(); i++)
		{
			Node child = children.item(i);
			if (child instanceof Element)
			{
				if (sb.length() > 0 )
					sb.append(",");
				sb.append (child.getTextContent());
			}
		}
		populate(columnNames, row, fqn, sb.toString());
	}

	@Override
	public void getConnection() throws InternalErrorException {
		try {
			pools.get(getTunnelPoolName()).getConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Error creating shell", e);
		}
	}

	@Override
	public void releaseConnection() throws InternalErrorException {
		try {
			pools.get(getTunnelPoolName()).returnConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Error creating shell", e);
		}
	}

}

