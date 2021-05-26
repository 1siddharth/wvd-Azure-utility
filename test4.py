"""
The configuration file would look like this (sans those // comments):

{
    "authority": "https://login.microsoftonline.com/Enter_the_Tenant_Name_Here",
    "client_id": "your_client_id",
    "scope": ["https://graph.microsoft.com/.default"],
        // For more information about scopes for an app, refer:
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate"

    "secret": "The secret generated by AAD during your confidential app registration",
        // For information about generating client secret, refer:
        // https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Client-Credentials#registering-client-secrets-using-the-application-registration-portal

    "endpoint": "https://graph.microsoft.com/v1.0/users"

}

You can then run this sample with a JSON configuration file:

    python sample.py parameters.json
"""

import sys  # For simplicity, we'll read config file from 1st CLI param sys.argv[1]
import json
import logging

import requests
import msal
client_id = ""
authorityurl = ""
secret=""
scope= ["https://graph.microsoft.com/.default"]
subscriptionId = ""

resourceGroupName = "Siddharth1"
endpoint = "https://management.azure.com/subscriptions/021488cc-117c-4e47-82f8-62bb7e88d7d8/resourceGroups/Siddharth1/providers/Microsoft.DesktopVirtualization/hostPools/try1234?api-version=2019-12-10-preview"
# Optional logging
# logging.basicConfig(level=logging.DEBUG)


# Create a preferably long-lived app instance which maintains a token cache.
app = msal.ConfidentialClientApplication(
   client_id, authority=authorityurl,
    client_credential=secret,
    # token_cache=...  # Default cache is in memory only.
                       # You can learn how to use SerializableTokenCache from
                       # https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
    )

# The pattern to acquire a token looks like this.
result = None

# Firstly, looks up a token from cache
# Since we are looking for token for the current app, NOT for an end user,
# notice we give account parameter as None.
result = app.acquire_token_silent(scope, account=None)


if not result:
    logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
    result = app.acquire_token_for_client(scopes=scope)

if "access_token" in result:
    # Calling graph using the access token
    print("acess token present in result")
    body = {
    "location": "centralus",
     "tags": {
    "tag1": "value1",
    "tag2": "value2"
    },
    "properties": {
    "friendlyName": "friendly",
    "description": "des1",
    "hostPoolType": "Pooled",
    "personalDesktopAssignmentType": "Automatic",
    "customRdpProperty": None,
    "maxSessionLimit": 999999,
    "loadBalancerType": "BreadthFirst",

    "vmTemplate": "{json:json}",
    "ssoContext": "KeyVaultPath",
    "preferredAppGroupType": "Desktop"
    }
    }
    token1 = " Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtnMkxZczJUMENUaklmajRydDZKSXluzOCIsImtpZCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kNzkzNWY1OC0xODkwLTRjYmMtODRjNC1hNTY0NDBhODUxMzEvIiwiaWF0IjoxNjAzNTk1ODY2LCJuYmYiOjE2MDM1OTU4NjYsImV4cCI6MTYwMzU5OTc2NiwiYWNyIjoiMSIsImFpbyI6IkFVUUF1LzhSQUFBQWEyKzRuOFJWenNuRWdGVnJBUVlZa0p1alhXOEN2b2ZUSHMxaTVDUnMxSXcxdEcxKysyMWdERGo3eEhlSjZFRmRWUVV2OVE3V0xYa1kyYWtXUVd1b0FBPT0iLCJhbHRzZWNpZCI6IjE6bGl2ZS5jb206MDAwNjAwMDAxMDFERjA1RSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiI3ZjU5YTc3My0yZWFmLTQyOWMtYTA1OS01MGZjNWJiMjhiNDQiLCJhcHBpZGFjciI6IjIiLCJlbWFpbCI6InhvZnQyQGhvdG1haWwuY29tIiwiZmFtaWx5X25hbWUiOiJUZWNoIiwiZ2l2ZW5fbmFtZSI6IlhvZnQiLCJncm91cHMiOlsiMWY1ZmVhYzUtYTZjYy00YzhiLTgwMTUtYjVjMzc4MTMyNjZkIl0sImlkcCI6ImxpdmUuY29tIiwiaXBhZGRyIjoiMTAzLjkxLjEyNy4zNCIsIm5hbWUiOiJYb2Z0IFRlY2giLCJvaWQiOiJiNDM0MjQyOS1kMmMxLTQyNmItYjZlMS0xMGRhOTFhNTM1N2EiLCJwdWlkIjoiMTAwMzIwMDBFQ0FFNTkxQiIsInJoIjoiMC5BQUFBV0YtVDE1QVl2RXlFeEtWa1FLaFJNWE9uV1gtdkxweENvRmxRX0Z1eWkwUnhBTlEuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoiOC1SbHY1VnRkZlowTUtDWFNGeWFvMk1IWlRGV0h0enJ3NEo5N19NcExuSSIsInRpZCI6ImQ3OTM1ZjU4LTE4OTAtNGNiYy04NGM0LWE1NjQ0MGE4NTEzMSIsInVuaXF1ZV9uYW1lIjoibGl2ZS5jb20jeG9mdDJAaG90bWFpbC5jb20iLCJ1dGkiOiIyUmVLQ3BpODlVdUdsTVc5M1NrdUFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyI2MmU5MDM5NC02OWY1LTQyMzctOTE5MC0wMTIxNzcxNDVlMTAiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX3RjZHQiOjE2MDI1MTAwNTR9.gDIzSzSr1tvvlrZlawb3TkuorS2IC806kXIL_hN9YjjXbP0e9JwuP7AcUknUvXezbS9ry6Vnm8J8mM-MOgoGrPi2Nm1HNoRz1UBwrCONIHP9Cjc0Np-3vV6AR_QweVWOnyiDxt0vrYppIe25sUJoFEbVgwWsdTN3-RmBhq1sqZMvM6BW87l8nHr9WPxbFfpXi4OPYJ0oC89rpM7JCARiAQkQDPyQZKf9pkCwrePoZJh0qDz01vYBwr15SUslwaZ2gg7ZkR8GNCOuySU-rYlpCvmraQke90eL_Pl4-rngX8S2vekH-Fn7pPDGxSMaPbCdH2hZxfvdm_bI0q7AFFfPDg"
    graph_data = requests.put(  # Use token to call downstream service
        endpoint,
        headers={'Authorization': 'Bearer ' + result['access_token'],
       
        
        "Content-Type":"application/json",} , json =body
         ).json()
    print(graph_data)
else:
    print(result.get("error"))
    print(result.get("error_description"))
    print(result.get("correlation_id"))  # You may need this when reporting a bu
