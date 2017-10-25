# Shopaholic
**Vector Type:** Web

**Description:** 

> Are you a shopaholic?
> Visit http://smartstore.owaspctf17.pro/ and shop some flags.
> Hint 1: Try looking for main.go
> Hint 2: Look at the attached image 

**Goal:** 

Grabbing our flag via usage of a web vulnerability (or maybe some more, who knows?) within the application, while sticking to provided hits.

## Looking for a new TV

Let's go and access the web application via "http://smartstore.owaspctf17.pro". Looks like a normal shopping website that has some decent products to offer, but does it offer any flags?! we shall see.

![Main web page](https://gyazo.com/36061c4b9a79de80a91e61c365ae4934.png)

Wandering around the website and checking some features lead us to "Products" page, that contains every product that is available on the website, well most of it :)
On each product we have two available functions: "View Product", and "Download PDF". So let's ignite our proxy interceptor and test each one of these functions.

Starting off with "Download PDF" on our desired TV, revealed us some interesting endpoint. 

![Download PDF TV product](https://gyazo.com/128fd40b03d94ce50ebd7c402f987016.png)

As we can already identify, a GET request is being sent to "/downloadFile" endpoint with a very interesting parameter, which is `file`, and it actually specifies a file that is stored on the webserver. Usually applications should validate user input, so when a page receives the given input to an unauthorized desired path, a directory traversal attack will not execute as of removing `..`, `../`, `.././`. 

Our first hint was to try and look for "main.go" file that is probablly located somewhere on the server, so let's do it.

![Testing file param](https://gyazo.com/43079f57389c26f370a0f7e339b7e813.png)

