When a Webserver allows users to upload files to its filesystem without sufficiently validating. 

Failing to validate and enforce restrictions could mean even image uploads can be used to upload arbitrary and potentially dangerous files.

In some cases simple file upload is enough, Other attacks require an http request for the file after to trigger the execution

## Impact 

Dependent on which aspects the website fails to validate IE size, type, contents and what the file can do once it has been uploaded 

in the worst case, the file type is not validated or bypassed and the server allows .php files to be executed, In this case an attacker could upload server side code that can create a reverse shell and command line access on the server 

Failing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.

filename isn't validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations


## How Do File upload vulns arise

Given the dangers, its rare to see no restrictions. If file upload capabilities are possible then they have extremely strict validation.

It is also common to use a blacklist for certain file types. As with blacklists they are prone to forgetting to add certain files *(why not use a whitelist?)*

even robust validation measures may be applied inconsistently across the network of hosts and directories that form the website, resulting in discrepancies that can be exploited.

## How do servers handle reqs for static files.'

Historically websites were all static files. as a result you could map the path of each request with the directories and files on the file system. 

Now websites are dynamic and the path of a request has no direct relationship to the filesystem

the server parses the path in the request to identify the file extension. It then uses this to determine the type of the file being requested, what happens next depends on the server and configuration 

- **If this file type is non-executable**, such as an image or a static HTML page, the server may just send the file's contents to the client in an HTTP response.
-
- If the file type is executable, such as a PHP file, **and** the server is configured to execute files of this type, it will assign variables based on the headers and parameters in the HTTP request before running the script. The resulting output may then be sent to the client in an HTTP response.
-
- If the file type is executable, but the server **is not** configured to execute files of this type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text. Such misconfigurations can occasionally be exploited to leak source code and other sensitive information. You can see an example of this in our information disclosure learning materials. -Note


## File upload vulns to get a shell
`the worst case` scenario is when the site allows you to upload server side scripts and execute them, Getting a shell is trivial.



For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:

`<?php echo file_get_contents('/home/carlos/secret'); ?>`

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:

`<?php echo system($_GET['command']); ?>`

This script enables you to pass an arbitrary system command via a query parameter as follows:

`GET /example/exploit.php?command=id HTTP/1.1



We upload RCE_via_fileUpload.php with the payload `echo file_get_contents('/home/carlos/secret')` this php code will execute on the server and echo the contents of the specified file in the http response 
