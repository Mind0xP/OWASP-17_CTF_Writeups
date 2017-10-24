# Eternal Sunshine
**Vector Type:** Web and Cryptography

**Description:** 

> Simple -
> Login as admin and get the flag
> http://sunshine.owaspctf17.pro/

**Goal:** 

The challenge was pretty simple: "Login as admin and get the flag”. 
Now we must understand how to break down the authentication mechanism in order to login as the admin. 

## Initial analysis

First we would like to access the web application on "http://sunshine.owaspctf17.pro/“, and check each component within the application. as you may already have assumed by now, there is a login page, or registration form, we shall understand what the form actually do before going deeper.

![Main login/registration page](https://gyazo.com/e9afba87e5fb54dad6a5533072276a99.png)

When analyzing the source code of the form, we can understand that its a registration form that sends a POST request to “/register” endpoint with two parameters: username as **[username]** and password as **[psw]**. 

![Registeration form source code](https://gyazo.com/476fc2dd447d9d75de7405403d9930c9.png)

Let’s intercept the request with a proxy to inspect every raw header, and get to know the authentication mechanism better. 

![Form intercept](https://gyazo.com/8d05da89c2457d2ddf802cccdf9b1a6d.png)

Within the response, we can see that a new cookie named **[session_id]** is generated, and a cookie named **[user]** containing the user we have registered with. 