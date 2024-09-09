package com.authorizatiion.demo;

public class ClientForm {
 	    private String clientName;
	    private String clientSecret;
	    private String redirectUri;

	    // Getters and setters
	    public String getClientName() {
	        return clientName;
	    }

	    public void setClientName(String clientName) {
	        this.clientName = clientName;
	    }

	    public String getClientSecret() {
	        return clientSecret;
	    }

	    public void setClientSecret(String clientSecret) {
	        this.clientSecret = clientSecret;
	    }

	    public String getRedirectUri() {
	        return redirectUri;
	    }

	    public void setRedirectUri(String redirectUri) {
	        this.redirectUri = redirectUri;
	    
	}    
}
