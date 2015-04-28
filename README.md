Description
===========
This tool exploits XXE to retrieve files from a target server. It obtains directory listings and recursively downloads file contents.

__Usage:__ 

The script has to be slightly modified to work with different web sites / web services:
*   Set ```HOST``` and ```URL``` according to your target
*   Change the XML data and the URL of your evil.dtd in the ```REQUEST_BODY```
*   Modify the ```_parse_response()``` method to parse the file content from the response.
*   For https: Change the ```_issue_request``` method to use ```HTTPSConnection```.

Also, make sure you make the DTD ```evil.dtd``` available to the server:
```python -m SimpleHTTPServer 5678```

```
python xxeclient.py -h
usage: xxeclient.py [-h] path [path ...]

Retrieves files via XXE

positional arguments:
  path        path(s) to the retrieve (e.g. /etc/)

optional arguments:
  -h, --help  show this help message and exit
```

Vulnerable Example Web Service
==============================
The files in ```xxe-example/``` contain a sample vulnerable RESTful web service written in Java using Jersey (inspired by [1]).

To compile and run it using maven run:
```mvn jetty:run```

__Debugging:__ 

The JSON and XML files in ```sample-payloads/``` can be used to debug the web service with curl:

```
curl -v -H "Content-Type:application/json" --upload-file initial.json http://localhost:8080/api/user
curl -v -H "Content-Type:application/xml" --upload-file cdata.xml http://localhost:8080/api/user
```

[1] https://github.com/rgerganov/xxe-example