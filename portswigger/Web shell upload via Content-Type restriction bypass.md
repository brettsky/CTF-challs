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