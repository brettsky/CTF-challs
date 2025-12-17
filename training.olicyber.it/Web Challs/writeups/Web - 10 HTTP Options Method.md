So far, we've seen various ways to interact with the resources an HTTP server provides, in the form of the GET, HEAD, and POST verbs, but not all of these operations are supported by all resource types. For example, it makes no sense to issue a POST request to a read-only resource. To find out what operations a given resource supports, HTTP provides the OPTIONS verb. An OPTIONS request returns a list of supported verbs within the header Allow.

Sometimes it can be interesting to intentionally try using an unsupported verb. Normally, a server should handle unsupported requests gracefully, but if there are misconfigurations or programming errors, using an unexpected method can cause a crash. Crashes, and more generally, unexpected operations, can reveal interesting information that is hidden in the normal use of a web service.

The goal of this challenge is to determine the set of supported verbs for the resource http://web-10.challs.olicyber.it/, try using an uncommon and unexpected one, and observe the response. The library also requestsprovides functions similar to the function getfor less common verbs, such as putand patch.'


### Challenge walk thru

1. First we send and http options request, and see that the POST method is not supported 

'''
url = "http://web-10.challs.olicyber.it/"

response = requests.options(url)

print(response.headers)
'''

'{'Allow': 'HEAD, OPTIONS, GET', 'Content-Length': '0', 'Content-Type': 'text/html; charset=utf-8', 'Date': 'Wed, 17 Dec 2025 01:49:56 GMT', 'Server': 'nginx/1.21.6'}'

Next we modify 'options' to be 'post', sending it off later we get an error and the headers contain our flag 
'{'Content-Length': '21', 'Content-Type': 'text/plain; charset=utf-8', 'Date': 'Wed, 17 Dec 2025 01:48:43 GMT', 'Server': 'nginx/1.21.6', 'X-Flag': 'flag{br34king_7h3_ru135}'}'