package com.documaster.oauth2.test.unit;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import com.documaster.oauth2.OAuth2HttpClient;
import com.documaster.oauth2.entities.AccessTokenResponse;
import com.documaster.oauth2.entities.ClientCredentials;
import com.documaster.oauth2.entities.PasswordCredentials;
import com.documaster.oauth2.entities.RefreshToken;
import io.specto.hoverfly.junit.core.Hoverfly;
import io.specto.hoverfly.junit.core.HoverflyMode;
import io.specto.hoverfly.junit.core.SimulationSource;
import io.specto.hoverfly.junit.core.config.LocalHoverflyConfig;
import io.specto.hoverfly.junit.dsl.HttpBodyConverter;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static io.specto.hoverfly.junit.dsl.HoverflyDsl.service;
import static io.specto.hoverfly.junit.dsl.ResponseCreators.success;
import static io.specto.hoverfly.junit.verification.HoverflyVerifications.times;

public class TestRequest {

	private final static String HOST = "http://localhost";
	private final static int PORT = 8157;
	private final static String OAUTH2_SERVICE_ADDRESS = String.format("%s:%s", HOST, PORT);
	private final static String TOKEN_ENDPOINT = "/token";

	private static Hoverfly hoverfly;
	private OAuth2HttpClient client;

	private AccessTokenResponse accessTokenResponse;

	@BeforeClass
	public static void setupHoverfly() throws IOException {

		LocalHoverflyConfig localHoverflyConfig = new LocalHoverflyConfig().asWebServer();
		hoverfly = new Hoverfly(localHoverflyConfig.proxyPort(PORT), HoverflyMode.SIMULATE);
		hoverfly.start();
	}

	@AfterClass
	public static void closeHoverfly() {

		hoverfly.close();
	}

	@Before
	public void setup() throws Exception {

		client = new OAuth2HttpClient(OAUTH2_SERVICE_ADDRESS);

		accessTokenResponse = new AccessTokenResponse("at", "Bearer", 1000L, "rt", "openid");

		hoverfly.simulate(SimulationSource.dsl(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.anyBody()
						.anyQueryParams()
						.willReturn(success(HttpBodyConverter.json(accessTokenResponse)))));

	}

	@Test
	public void GetTokenWithPasswordCredentialsAsFormDataTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String username = "us";
		String password = "pass";
		String scope = "sc";

		PasswordCredentials passwordCredentials =
				new PasswordCredentials(clientId, clientSecret, username, password, scope);

		AccessTokenResponse response = client.getToken(passwordCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "password"));
								expectedParams.add(new BasicNameValuePair("username", username));
								expectedParams.add(new BasicNameValuePair("password", password));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", scope));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithPasswordCredentialsWithMultipleScopesTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String username = "us";
		String password = "pass";
		List<String> scopes = Arrays.asList("A", "X");

		PasswordCredentials passwordCredentials =
				new PasswordCredentials(clientId, clientSecret, username, password, scopes);

		AccessTokenResponse response =
				client.getToken(passwordCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								String joinedScopes = scopes != null
													  ? scopes.stream().collect(Collectors.joining("+"))
													  : null;

								expectedParams.add(new BasicNameValuePair("grant_type", "password"));
								expectedParams.add(new BasicNameValuePair("username", username));
								expectedParams.add(new BasicNameValuePair("password", password));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", joinedScopes));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithPasswordCredentialsWithNoScopeTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String username = "us";
		String password = "pass";

		PasswordCredentials passwordCredentials = new PasswordCredentials(clientId, clientSecret, username, password);

		AccessTokenResponse response = client.getToken(passwordCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "password"));
								expectedParams.add(new BasicNameValuePair("username", username));
								expectedParams.add(new BasicNameValuePair("password", password));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithPasswordCredentialsAsHeadersTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String username = "us";
		String password = "pass";
		String scope = "sc";

		PasswordCredentials passwordCredentials =
				new PasswordCredentials(clientId, clientSecret, username, password, scope);

		AccessTokenResponse response =
				client.getTokenWithAuthorizationHeaders(passwordCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.header("grant_type", passwordCredentials.getGrantType().getName())
						.header("username", passwordCredentials.getUsername())
						.header("password", passwordCredentials.getPassword())
						.header("client_id", passwordCredentials.getClientId())
						.header("client_secret", passwordCredentials.getClientSecret())
						.header("scope", passwordCredentials.getScope())
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithClientCredentialsAsFormDataTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String scope = "sc";

		ClientCredentials clientCredentials =
				new ClientCredentials(clientId, clientSecret, scope);

		AccessTokenResponse response = client.getToken(clientCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "client_credentials"));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", scope));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithClientCredentialWitMultipleScopesTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		List<String> scopes = Arrays.asList("R", "S", "T");

		ClientCredentials clientCredentials = new ClientCredentials(clientId, clientSecret, scopes);

		AccessTokenResponse response = client.getToken(clientCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								String joinedScopes = scopes != null
													  ? scopes.stream().collect(Collectors.joining("+"))
													  : null;

								expectedParams.add(new BasicNameValuePair("grant_type", "client_credentials"));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", joinedScopes));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithClientCredentialWitNoScopeTest() {

		String clientId = "cid";
		String clientSecret = "cs";

		ClientCredentials clientCredentials = new ClientCredentials(clientId, clientSecret);

		AccessTokenResponse response = client.getToken(clientCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "client_credentials"));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void GetTokenWithClientCredentialsAsHeadersTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String scope = "sc";

		ClientCredentials clientCredentials = new ClientCredentials(clientId, clientSecret, scope);

		AccessTokenResponse response =
				client.getTokenWithAuthorizationHeaders(clientCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.header("grant_type", clientCredentials.getGrantType().getName())
						.header("client_id", clientCredentials.getClientId())
						.header("client_secret", clientCredentials.getClientSecret())
						.header("scope", clientCredentials.getScope())
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void RefreshTokenAsFormDataTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String scope = "sc";
		String token = "rtoken";

		RefreshToken refreshTokenCredentials =
				new RefreshToken(token, clientId, clientSecret, scope);

		AccessTokenResponse response = client.getToken(refreshTokenCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "refresh_token"));
								expectedParams.add(new BasicNameValuePair("refresh_token", token));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", scope));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void RefreshTokenWithMultipleScopesTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		List<String> scopes = Arrays.asList("A", "B");
		String token = "rtoken";

		RefreshToken refreshTokenCredentials =
				new RefreshToken(token, clientId, clientSecret, scopes);

		AccessTokenResponse response = client.getToken(refreshTokenCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								String joinedScopes = scopes != null
													  ? scopes.stream().collect(Collectors.joining("+"))
													  : null;

								expectedParams.add(new BasicNameValuePair("grant_type", "refresh_token"));
								expectedParams.add(new BasicNameValuePair("refresh_token", token));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));
								expectedParams.add(new BasicNameValuePair("scope", joinedScopes));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void RefreshTokenWithNoScopeTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String token = "rtoken";

		RefreshToken refreshTokenCredentials =
				new RefreshToken(token, clientId, clientSecret);

		AccessTokenResponse response = client.getToken(refreshTokenCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.body(new HttpBodyConverter() {

							@Override
							public String body() {

								List<NameValuePair> expectedParams = new ArrayList<>();

								expectedParams.add(new BasicNameValuePair("grant_type", "refresh_token"));
								expectedParams.add(new BasicNameValuePair("refresh_token", token));
								expectedParams.add(new BasicNameValuePair("client_id", clientId));
								expectedParams.add(new BasicNameValuePair("client_secret", clientSecret));

								String body = "";

								for (NameValuePair param : expectedParams) {
									body = String.format("%s&%s=%s", body, param.getName(), param.getValue());
								}

								return body.substring(1);
							}

							@Override
							public String contentType() {

								return "application/x-www-form-urlencoded";
							}
						})
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

	@Test
	public void RefreshTokenAsHeadersTest() {

		String clientId = "cid";
		String clientSecret = "cs";
		String scope = "sc";
		String token = "rtoken";

		RefreshToken refreshTokenCredentials =
				new RefreshToken(token, clientId, clientSecret, scope);

		AccessTokenResponse response =
				client.getTokenWithAuthorizationHeaders(refreshTokenCredentials);

		hoverfly.verify(
				service(OAUTH2_SERVICE_ADDRESS)
						.post(TOKEN_ENDPOINT)
						.header("grant_type", refreshTokenCredentials.getGrantType().getName())
						.header("client_id", refreshTokenCredentials.getClientId())
						.header("client_secret", refreshTokenCredentials.getClientSecret())
						.header("refresh_token", refreshTokenCredentials.getRefreshToken())
						.header("scope", refreshTokenCredentials.getScope())
						.anyQueryParams(),
				times(1));

		Assert.assertEquals(accessTokenResponse.getAccessToken(), response.getAccessToken());
	}

}
