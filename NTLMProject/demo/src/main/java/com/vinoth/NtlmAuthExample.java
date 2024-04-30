package com.vinoth;

import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Base64;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

public class NtlmAuthExample {
    public static void main(String[] args) throws IOException {
        String username = "user";
        String password = "pass";
        String domain = "authenticationtest.com";
        String url = "https://authenticationtest.com/HTTPAuth/";

        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            // Step 1: Send a request without credentials to get the NTLM challenge
            HttpHost target = new HttpHost("example.com", 80, "http");
            AuthScope authScope = new AuthScope(target.getHostName(), target.getPort());
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(authScope, new NTCredentials(username, password, "vinoth-macbook", domain));
            httpClient = HttpClients.custom()
                    .setDefaultCredentialsProvider(credsProvider)
                    .build();

            HttpGet httpGet = new HttpGet(url);
            try (CloseableHttpResponse response1 = httpClient.execute(httpGet)) {
                // Step 2: Retrieve NTLM challenge from the response headers
                Header[] headers = response1.getAllHeaders();
        for (Header header : headers) {
            System.out.println(header.getName() + ": " + header.getValue());
        }
                String ntlmChallenge = response1.getFirstHeader("WWW-Authenticate").getValue();
                System.out.println("ntlmchallend "+ntlmChallenge);
                String challengeMessage = ntlmChallenge.substring(ntlmChallenge.indexOf("NTLM") + 5).trim();
                System.out.println("ntlmchallchallengeMessageend "+challengeMessage);
                // Step 3: Send a request with NTLM challenge response
                Type2Message type2Message = new Type2Message(Base64.decode(challengeMessage));
                Type3Message type3Message = new Type3Message(type2Message, password, username, domain, "vinothmacbook", NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_SEAL);
                String ntlmResponse = "NTLM " + Base64.encode(type3Message.toByteArray());
                httpGet.setHeader("Authorization", ntlmResponse);

                try (CloseableHttpResponse response2 = httpClient.execute(httpGet)) {
                    // Handle response here
                    System.out.println(EntityUtils.toString(response2.getEntity()));
                }
            }
        } finally {
            httpClient.close();
        }
    }
}
