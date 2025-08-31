# Permiter  

Permiter is a Burp Suite Extension that automatically tests for Authorization issues using either your proxy history or site map. Multiple roles can be configured and use regex to swap out the session identifier(s) used by the application. Multiple regex patterns can be set for each role. Unauthenticated tests can be configured but are disabled by default.  

Results can be exported in CSV or HTML format. Exporting as HTML embeds each request/response page for easy review.  

## Install  

Burp Suite needs the Python environment configured. Add the reference to the Jython JAR file in extension settings.  

From the Extensions setting, in the Installed tab, select `add` and choose Python as the extension type. Then load `permiter.py`. That is all there is. 

## HOW TO USE:  

The OWASP JuiceShop at `https://juice-shop.herokuapp.com` was used to demonstrate usage.  

### Configuration  

To use Permiter, you will need to set the target scope and define each role to be tested.  

![Permiter](/images/main.png)  

#### Scope  

Permiter can pull from the target history or regex can be used to define the scope.  

![Scope](/images/scope.png)  

When using the target history, select `Refresh Targets` and then select a target.  

![Targets](/images/targets.png)  

Add any endpoints that should be excluded during the test and set the delay for each request (Default is 10 milliseconds).  

#### Roles  

Add each role that is being tested. Assign a name for the role. Then set a regex pattern to replace the session token with a valid session token for the role being tested. Select `Save` to add the role.   

![Roles](/images/roles.png)  

Roles will populate in the `Roles:` selector. Modifications can be made after the roles have been added.  

![All Roles](/images/all_roles.png)  

### Testing  

To start testing, select either `Use Proxy History` or `Use Site Map`.  

![Options](/images/buttons.png)  

Additionally, the option to save and load a previous configuration is available. Select `Include Unauth` for checks for unauthenticated access. By default, duplicate endpoints are excluded. Check `Use Entire History` to disable and use the entire history. This may be needed to fully test some applications.  

The results will populate in Permiter.  

![Results](/images/status.png)  

### Exporting  

Results can be exported as either a CSV file or HTML file.  

![Exported Results](/images/export.png)  

The HTML export contains the request/response. Select the `Show Request/Response` button to further review the results.  
