package com.documaster.oauth2.test.unit;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.documaster.oauth2.entities.AuthorizationGrant;
import com.documaster.oauth2.entities.ClientCredentials;
import com.documaster.oauth2.entities.PasswordCredentials;
import com.documaster.oauth2.entities.RefreshToken;
import org.junit.Assert;
import org.junit.Test;

public class TestAuthorizationGrantTypes {

	@Test
	public void TestClientCredentials() throws UnsupportedEncodingException {

		String clientId = "cid";
		String clientSecret = "cs";
		String scope = "sc";

		Map<String, String> expectedParameters = new HashMap<>();
		expectedParameters.put("grant_type", "client_credentials");
		expectedParameters.put("client_id", clientId);
		expectedParameters.put("client_secret", clientSecret);

		ClientCredentials cl = new ClientCredentials(clientId, clientSecret);
		AssertParamsResult(expectedParameters, cl);

		cl = new ClientCredentials(clientId, clientSecret, scope);
		expectedParameters.put("scope", scope);
		AssertParamsResult(expectedParameters, cl);
	}

	@Test
	public void TestPasswordCredentials() throws UnsupportedEncodingException {

		String clientId = "cid";
		String clientSecret = "cs";
		String username = "us";
		String password = "pass";
		String scope = "sc";

		Map<String, String> expectedParameters = new HashMap<>();
		expectedParameters.put("grant_type", "password");
		expectedParameters.put("username", username);
		expectedParameters.put("password", password);
		expectedParameters.put("client_id", clientId);
		expectedParameters.put("client_secret", clientSecret);

		PasswordCredentials cl = new PasswordCredentials(clientId, clientSecret, username, password);
		AssertParamsResult(expectedParameters, cl);

		cl = new PasswordCredentials(clientId, clientSecret, username, password, scope);
		expectedParameters.put("scope", scope);
		AssertParamsResult(expectedParameters, cl);
	}

	@Test
	public void TestRefreshToken() throws UnsupportedEncodingException {

		String clientId = "cid";
		String clientSecret = "cs";
		String token = "token";
		String scope = "sc";

		Map<String, String> expectedParameters = new HashMap<>();
		expectedParameters.put("grant_type", "refresh_token");
		expectedParameters.put("refresh_token", token);
		expectedParameters.put("client_id", clientId);
		expectedParameters.put("client_secret", clientSecret);

		RefreshToken cl = new RefreshToken(token, clientId, clientSecret);
		AssertParamsResult(expectedParameters, cl);

		cl =  new RefreshToken(token, clientId, clientSecret, scope);
		expectedParameters.put("scope", scope);
		AssertParamsResult(expectedParameters, cl);
	}

	private void AssertParamsResult(Map<String, String> expected, AuthorizationGrant grant) {

		Map<String, String> actualMap = grant.GetAsParams().stream().collect(
				Collectors.toMap(nameValuePair -> nameValuePair.getName(), nameValuePair -> nameValuePair.getValue()));

		for (String expectedParamName : expected.keySet()){

			Assert.assertTrue(actualMap.containsKey(expectedParamName));
			Assert.assertEquals(expected.get(expectedParamName), actualMap.get(expectedParamName));
		}
	}
}
