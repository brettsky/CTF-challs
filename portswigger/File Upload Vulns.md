
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

`GET /example/exploit.php?command=id HTTP/1.1`



## Exploiting flawed validation 
Its rare to find a website with no protection against file upload attacks, It does not mean all the security in place is good.

### Flawed file type validation

When submitting HTML forms, the browser typically sends the provided data in a `POST` request with the content type `application/x-www-form-urlencoded`. This is fine for sending simple text like your name or address. However, it isn't suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type `multipart/form-data` is preferred.

Consider a form containing fields for uploading an image, providing a description of it, and entering your username. Submitting such a form might result in a request that looks something like this:

```
POST /images HTTP/1.1 Host: normal-website.com Content-Length: 12345 Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456 --------------------------

Content-Disposition: form-data; name="image"; filename="example.jpg"
 Content-Type: image/jpeg [...binary content of example.jpg...] 
 ---------------------------012345678901234567890123456 
 Content-Disposition: form-data; name="description" 
 This is an interesting description of my image.
  ---------------------------012345678901234567890123456
   Content-Disposition: form-data; name="username" 
   
   wiener 
   
   ---------------------------012345678901234567890123456--
```

The message is split into separate parts for each of the forms inputs. In other words,  when you need to upload large amounts of data to a webserver multipart/form-data is preferred. This req will allow for the content to be separated into multiple parts. Each individual part will have its own MIME type in a `Content-Type` header

Validation of this content type header might occur. the server might check to ensure it matches an expected MIME type,  Problems can occur if the value of the headerr is implicitly trusted by the server for validation.IE it may only allow types like `image/jpeg` and `image/png`
this defense can be easily bypassed using tools like Burp Repeater.


To solve this challenge we used the same payload `<?php echo file_get_contents('/home/carlos/secret'); ?>` we get a deny message with the error message `Sorry, file type application/octet-stream is not allowed Only image/jpeg and image/png are allowed Sorry, there was an error uploading your file.`

So we send this request to burp repeater and change the content type in the multi part form data for the php file to image/jpeg. This allows the file to be uploaded. Navigating to /files/avatars/RCE_via_fileUpload.php gives us the contents of the file in the response.

## Directory Traversal vulnerabilities

It is common for directories where user supplied files can be uploaded to be very restricted. However if we are able to escape these directories and upload to others we can potentially run the file again. 

Web servers often use the filename field in multipart/form-data requests to determine the name and location where the file should be saved.

In order to escape this lab we add ..%2f to obfuscate our forward slash. %2f is interpreted as a forward slash on the server causing the file to be uploaded to files/ rather than files/avatars

The directory for files is vulnerable and runs the php code giving us the secret text in the carlos directory `<?php echo file_get_contents('/home/carlos/secret'); ?>`


## Insufficient Blacklisting

Easiest way to prevent these vulns, just dont allow a php file to be uploaded. 

Although blacklisting is flawed. It is very hard to blacklist every possible file extension, It may be possible to work around a black list by using lesser known file extensions


## Override Server config

Servers will not execute files unless configed to do so. 

Ie an apache server will not execute PHP files unless a config file like this is added `/etc/apache2/apache2.conf`
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so AddType application/x-httpd-php .php
```

Config files can be created for individual directories.
Apache servers load a directory config from a file called .htaccess

In IIS Servers a directory specific conf file is web.config

This might include directives such as the following, which in this case allows JSON files to be served to users:

`<staticContent> <mimeMap fileExtension=".json" mimeType="application/json" /> </staticContent>`

Web servers use these conf files when present but typically are not allowed to be access via an http request. However on occasion servers mail fail to stop a malicious config file from being uploaded. 

In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type

## Lab: Web shell upload via extension blacklist bypass

Tip you need to upload two files to pass this lab. We uploaded a shell but we see it is being evaluated as plain text not code, we need to access the config file to get this to execute as code

Config files can be created for individual directories.
Apache servers load a directory config from a file called .htaccess

This server is `Apache/2.4.41 (Ubuntu) Server at 1f6ce7885fc3 Port 80`

I first try to upload my php shell in via the vulnerable image upload but it gets blocked. I then forward the request to repeater and change the file extension to php5 and it works. 

Navigating to the file shows it is not executing i just see the contents of the file. 

To get around this I go back to my repeater tab and update my file. I change the name to .htaccess and the contents to `AddType application/x-httpd-php .php5` I also change the content type to text/plain. All of this will over write the config figle for this directory and allow php5 files to be executed. The server will know it is php. 

We navigate back to the file and get the secret. 


## Obfuscating file extensions 
Black lists can potentially be bypassed using obfuscation techniques- if the validation code is not case sensitive and allows pHp to be uploaded the server may also run pHp as php code. This also can be done through

	Provide multiple extensions
 the following file may be interpreted as either a PHP file or JPG image: `exploit.php.jpg`
 - Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`
- Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes.\
- Add semicolons or URL-encoded null byte characters before the file extension If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: `exploit.asp;.jpg` or `exploit.asp%00.jpg`
- - Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.


Other defenses mighht strip dangerous file extensions 

 if you strip `.php` from the following filename:

`exploit.p.phphp` you get .php and potentially an executable shell 


## Lab: Web shell upload via obfuscated file extension

Based on the previous lesson and name of the lab we will have to obfuscate the file extension with some of the techniques we learned

I first try a double file name attack. This bypasses the filter and allows the file to be uploaded, but the file is being interpreted as a jpg. We get a blank page with the icon showing the image could not be loaded correctly. 

We switch obfuscation techniques to url encode a null byte changing our file name to 'filename=RCE_via_fileUpload.php%00.jpg'
This null byte caused a discrepancy in the file validation and what the server runs. The server sees the file ends in .jpg and assumes it safe. The code that actually runs the file sees %00 and assumes thats the end of the file extension and runs it as php instead of jpg



## Flawed validation of file contents 

Secure servers are typically configured to verify tthe contents of the file rather than trusting `Content-Type` . In the examples previously the server may look at the file contents for certain information to prove its an image like dimensions. Since our php code looks nothing like an image the server knows its not and denies it accordingly

Certain files always have a fingerprint in the header or footer bytes JPEG files always begin with the bytes `FF D8 FF`.

 Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata.


## Lab: Remote code execution via polyglot web shell upload

We are going to use exiftool to create a polyglot webshell

to create this we can use Exiftool this allows us to add comments and byte sequences to files. 
`exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" thelastairbender.jpeg -o polyglot7.php`

This line adds the comment and php shell payload to the thelastairbender.jpeg and outputs it to polyglot7.php. The file validation still sees the file as a jpeg file but it actually contains the PHP code. We see in the output when navigating to the file that there is a <START> and <End> tag which show us where the code is executed and we get the secret file info

## Exploit file upload race conditions 

Modern frameworks are resistant to common attack vectors. IE renaming files. Polygot files. Sandboxes, random names all work to prevent these attacks

Devs sometimes implement their own file uploader outside of a frame work which can have race conditions 

For example a file may exist on a server for a short time while it is scanned by an antivirus. For that short time it can be checked

Examples include a file upload that takes a URL, The server has to fetch the file before it can perform validation.

As the file is loaded, their own processes for loading the file temporarily may not be secure. 

If the file is uploaded to a directory with a randomized name it would be difficult to exploit race conditions. If they dont know where it is they will be unable to request it so it can be executed. Sometimes brute forcing is used to try and guess the directory along with a large file full of padding bytes to make scanning take as long as possible 


## Exploitinmg file upload without RCE

1. Uploading malicious client side scripts. 
   
   Although code execution might be disabled  you may be able to upload scripts for client side attacks,
	IE if you can upload html you may be able to use a <script> tag  </script> 
1.Parsing of file uploads. If the file is stored and served securly
	Exploit the parsing of different file types. IE the server parses XML based files like .doc or .xls. these files might be a potential vector for XXE
	



## Uploads using PUT request 

If defenses aren't in place this can be another method of attacking a server file upload. 

```
PUT /images/exploit.php HTTP/1.1 Host: vulnerable-website.com Content-Type: application/x-httpd-php Content-Length: 49 <?php echo file_get_contents('/path/to/file'); ?>

```

## How to prevent.

1 Check file extensions against a whitelist. Do not bother maintaining a blacklist

2. Make sure no substrings or potential path traversial seq
3. Do not upload un verified files
4. Use an established and maintained framework for file validation
