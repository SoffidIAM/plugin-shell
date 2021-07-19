package com.soffid.iam.sync.agent;

public class ExecutionException extends Exception {
	int status;
	String errorMessage;
	public ExecutionException(int status, String errorMessage) {
		super();
		this.status = status;
		this.errorMessage = errorMessage;
	}
	public int getStatus() {
		return status;
	}
	public String getErrorMessage() {
		return errorMessage;
	}
}
