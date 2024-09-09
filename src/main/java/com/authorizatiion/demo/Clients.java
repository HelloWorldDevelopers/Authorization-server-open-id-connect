package com.authorizatiion.demo;

public class Clients {
	private Long id;

	private String clientName;

	private String secretId;

	private String redirectUri;
	
	public Clients(Long id, String clientName, String secretId, String redirectUri) {
        this.id = id;
        this.clientName = clientName;
        this.secretId = secretId;
        this.redirectUri = redirectUri;
    }

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getSecretId() {
		return secretId;
	}

	public void setSecretId(String secretId) {
		this.secretId = secretId;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

}
