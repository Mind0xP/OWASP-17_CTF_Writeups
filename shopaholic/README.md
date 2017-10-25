# Shopaholic
**Vector Type:** Web

**Description:** 

> Are you a shopaholic?
> Visit http://smartstore.owaspctf17.pro/ and shop some flags.
> Hint 1: Try looking for main.go
> Hint 2: Look at the attached image 

**Goal:** 

Grabbing our flag via usage of a web vulnerability (or maybe some more, who knows?) within the application, while sticking to provided hints.

## Looking for a new TV

Let's go and access the web application via "http://smartstore.owaspctf17.pro". Looks like a normal shopping website that has some decent products to offer, but does it offer any flags?! we shall see.

![Main web page](https://gyazo.com/36061c4b9a79de80a91e61c365ae4934.png)

Wandering around the website and checking some features led us to "Products" page, that contains every product that is available on the website, well most of it :)
On each product we have two available functions: "View Product", and "Download PDF". So let's ignite our proxy interceptor and test each one of these functions.

Starting off with "Download PDF" on our desired TV, revealed us some interesting endpoint. 

![Download PDF TV product](https://gyazo.com/128fd40b03d94ce50ebd7c402f987016.png)

As we can already identify, a GET request is being sent to "/downloadFile" endpoint with a very interesting parameter, which is `file`, and it actually specifies a file that is stored on the webserver. Usually applications should validate user input, so when a page receives the given input to an unauthorized desired path, a directory traversal attack will not execute as of removing `..`, `../`, `.././`. 

Our first hint was to try and look for "main.go" file that is probablly located somewhere on the server, so let's do it.
We will try some traditional directory traversal patterns, adding `../` just before "main.go" in order to go back one folder.

![Testing file param](https://gyazo.com/43079f57389c26f370a0f7e339b7e813.png)

Checking the presented response it looks like we are on the same folder ("downloads"), so it seems that there is some user input validation here, which filters out `../`. lets try and bypass it with encoded traversal strings.

![Got our LFI](https://gyazo.com/c0fa593feec6e2c9eea6a9ee1f182c2a.png)

Vwalla! we got 200 OK sent back from the server, following "main.go" source code as promised. Now we must analyze and understand this piece of code, so we can find some flaws.

## Analysing the main piece of code

We will go step by step on each relevant piece of code in order to seek our flaws, and get to know the application better.

```
var (
	RESOURCE_SERVER = "http://127.0.0.1"
	DOWNLOAD_DIRECTORY = "./downloads/"
	ILLEGAL_CHARS = []string {
		"../",
		"<!--",
		"-->",
		"<",
		">",
		"'",
		"\"",
		"&",
		"$",
		"#",
		"{", "}", "[", "]", "=",
		";", "?", "%20", "%22",
		"%3c",   // <
		"%253c", // <
		"%3e",   // >
		"",   // > -- fill in with % 0 e - without spaces in between
		"%28",   // (
		"%29",   // )
		"%2528", // (
		"%26",   // &
		"%24",   // $
		"%3f",   // ?
		"%3b",   // ;
		"%3d",   // =
	}
	CALCULATION_SERVER = "http://10.0.0.185:8080/calc"
)
```

We can see that there are some interesting declarations of global variables, which are used within the application. What are they?

`RESOURCE_SERVER` - stores the localhost web URL.

`CALCULATION_SERVER` - stores an **internal** URL for a calculation service at "10.0.0.185:8080/calc".

Focusing on the `main()` function shows us the path of each page following their functions.

```
func main() {
	r := mux.NewRouter()

	// Dynamic Pages
	r.HandleFunc("/getResource", getResource).Queries("path", "{path}")
	r.HandleFunc("/downloadFile", downloadFile).Queries("file", "{file}")
	r.HandleFunc("/calc", calc)
	r.HandleFunc("/login", login)
```

The first function we are going to investigate is the `getResource()` function that is set under "/getResource" page.

```
func getResource(w http.ResponseWriter, r *http.Request) {
	path := mux.Vars(r)["path"]
	path = strings.Replace(path, " ", "%20", -1)
	req, err := http.NewRequest("POST", RESOURCE_SERVER + path, nil)
	req.Header.Set("Host", strings.Split(RESOURCE_SERVER, "//")[1])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		errorHandler(w, r, http.StatusInternalServerError, "")
		return
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		errorHandler(w, r, http.StatusInternalServerError, "Resource Server Connection Error")
		return
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	response := string(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Golang HTTP Server")
	fmt.Fprint(w, response)
}
```

The function takes two arguments: `http.ResponseWriter` value assembles the HTTP server's response, and http.Request is a data structure that represents the client HTTP request. when invoking this function by accessing "/getResource" endpoint with a `path` parameter, a new `POST` request will be sent to `RESOURCE_SERVER` which is 127.0.0.1, following the `path` value afterwards. If we set `path` as "/test", then we will trigger the next request : 

```
POST http://127.0.0.1/test HTTP/1.1
```

Wait a minute... we can now send an HTTP request to any external and internal targets! and we got an interesting **internal calcuation server**, if the bell doesn't ring stay tuned for the next part.

## Testing SSRF

We will try and send a request with an empty `path` value, and see what we get.

![SSRF trying localhost](https://gyazo.com/c01f284672f9277be6bed89dc585b0ad.png)

Server response seems like an SSRF, so we can just specify any IP and access it, and we do have an internal IP to check, give it a try? 



