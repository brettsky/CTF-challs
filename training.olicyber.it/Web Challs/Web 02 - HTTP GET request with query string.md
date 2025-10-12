Requests for some resources can be parameterized to return specific versions of the resource in question. For example, a blog might use a single resource to represent all published posts (which are all structurally identical, differing only in content) by identifying the specific content desired via a numeric parameter id.

The goal of this challenge is to obtain the resource http://web-02.challs.olicyber.it/server-recordsby specifying the parameter id with the value flag. 


The goal of this challenge is to learn how to use the requests module to send a specific parameter to the server


```
params = {"id": "flag"} # this line sets the params variable to the server

response = requests.get(url, params=params) # this line sends a get request to the server with the params
```

Those two lines are the only difference from level 1. We set the params varaible equal to 