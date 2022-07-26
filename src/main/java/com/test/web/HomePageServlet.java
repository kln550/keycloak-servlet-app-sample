package com.test.web;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.TokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;


public class HomePageServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private String tokenString;
	private AccessToken accessToken;

	public void init() throws ServletException {
		tokenString = "Http Servlet Demo";
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();

		// Keycloak context
		KeycloakSecurityContext keycloakSecurityContext =  (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
		this.accessToken = keycloakSecurityContext.getToken();
		this.tokenString = keycloakSecurityContext.getTokenString();
		
		out.println("<h1> AccessToken = " + this.tokenString + "</h1>");
		out.println("<h1> Authorization Context = " + keycloakSecurityContext.getAuthorizationContext().toString()
				+ "</h1>");
		try {
			out.println("<p> IsLogged " + this.isLoggedInKeycloak(keycloakSecurityContext) + "</p>");
			out.println("<p> User Name= " + this.accessToken.getFamilyName() + ' ' + this.accessToken.getGivenName()
					+ "</p>");
			out.println("<p> User Email = " + this.accessToken.getEmail() + "</p>");
			out.println("<p> Subject  = " + this.accessToken.getSubject() + "</p>");
			out.println("<p> Expiration  = " + this.accessToken.getExpiration() + "</p>");
		} catch (VerificationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/*
		out.println("<h1> </h1>");
		out.println("<h1> Authenticating User using AuthZClient</h1>");
		File jsonFile = new File("C://Apps//keycloak.json");
		final InputStream jsonFileStream = new DataInputStream(new FileInputStream(jsonFile));
		AuthzClient authzClient = AuthzClient.create(jsonFileStream);
		AuthorizationRequest authorizationRequest = new AuthorizationRequest();
		AuthorizationResponse authorizationResponse = authzClient.authorization("login_name", "password")
				.authorize(authorizationRequest);
		String tokenUsingClient = authorizationResponse.getToken();
		out.println("<h2> AccessToken(Client AuthZClient) = " + tokenUsingClient + "</h2>");
		*/
	}

	/**
	 * Verify if user is logged in keycloak by validating token in request
	 */
	private boolean isLoggedInKeycloak(KeycloakSecurityContext keycloakSecurityContextToken) throws VerificationException {
		AccessToken token = TokenVerifier.create(keycloakSecurityContextToken.getTokenString(), AccessToken.class)
				.getToken();
		if (!token.isExpired()) {
			System.out.println("User token is expired..." + token);
			return true;
		}
		return false;
	}

}