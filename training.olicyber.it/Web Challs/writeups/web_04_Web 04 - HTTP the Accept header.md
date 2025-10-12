The term "resource" in HTTP is a very abstract concept. A resource doesn't necessarily refer to a file on a disk, but could just as easily be a hardware device, the contents of a database, the output of a program, or more generally anything that can be abstractly represented as a collection of data.

When we "request a resource" via HTTP, we are not actually receiving the original resource (which in some cases is not even physically transferable over the network, think of the example of a hardware device), but rather a representation of it.

Resources served by a server typically have a single representation, but in some cases you can request (and receive) multiple equivalent representations, allowing you to choose the format that is easiest for the client to process.

The header Acceptsent as part of the request specifies a list of formats that the client considers "acceptable" in order of preference, using a classification system called MIME types (a complete list of available MIME types can be found on the official website of the IANA organization that assigns them).

Sometimes, for example due to carelessness related to the different characteristics of the various formats, the various representations of a resource are not truly equivalent, and an alternative representation may reveal additional information that was thought to be secret.

The goal of this challenge is to request the resource http://web-04.challs.olicyber.it/usersusing the alternative representation application/xmlinstead of the default one application/json.

It is recommended to try getting the resource normally, and then specifying a different representation type ( application/xml) via the header Accept.

#https://www.iana.org/assignments/media-types/media-types.xhtml Complete list of media types 



This challenge we have to request a specific resource from the server and accept it as XML instead of JSON


```
headers = {"Accept": "application/xml"}
```

In this challenge we learned about the accept header. Without adding the accept header we saw output just by sending a get request but it did not contain the XML user comment that contained the flag
