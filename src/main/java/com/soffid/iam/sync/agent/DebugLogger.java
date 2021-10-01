package com.soffid.iam.sync.agent;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.jcraft.jsch.Logger;

public class DebugLogger implements Logger {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	public boolean isEnabled(int level) {
		return true;
	}

	@Override
	public void log(int level, String message) {
		log.info(message);
	}

}
