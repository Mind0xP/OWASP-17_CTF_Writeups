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

![Time for some cookies](https://gyazo.com/fc683dc1a688486d96f756348868442c.png)

But may a regular user login to an administrative page? I doubt it. let’s try and reach the admin page with my current cookies by just accessing the “/admin” endpoint.

![Admin - Access Denied](https://gyazo.com/5e562516225b23734c9cee6916d3dc4f.png)

we have received access denied. It is absolutely not polite to reject your guests that way.

Maybe we can register as the “admin”? that would be nice, but not possible. That’s the only account we cannot register, remember it.

So let’s try and change the value of cookie **[user]** to “admin” and see what we get. 

![Juicy error page](https://gyazo.com/22b3966c9eed41b33e9cf74896449440.png)

That is one serious error page, we can see that something failed within the application right under the <title> tag. 

## Getting to know the lock mechanism

By reading the error above, we can identify how the application authorizes users from its cache. So let’s break down the exception and understand how can we manipulate it for our malicious use. Now we will focus on the following code:

```
authorization_cache.isInCache(hash(sessionid, user))
```

Starting off with **authorization_cache[]** which looks like a **list/array/dict** that holds the current hashes of the registered/logged users, by using **isInCache()** function followed by calculating the hash using given **[sessionid]** and **[user]** cookies.

![Auth flow](https://gyazo.com/8fbc68d574e12486aa1ba2623f80d746.png)

So each time a user registers, the server will generate a **[sessionid]** following the chosen **[user]**, and store it in **authorization_cache[]** using **hash()** function on the given parameters. then each time a user provides **[sessionid]** and **[user]** the server will use **hash()** function and compare the result to one of its stored hashes within **authorization_cache[]**.
The ability to produce hashes using **hash()** function allows us to manipulate **[sessionid]** and adjust it to the desired user.

## Quick Scramble 

The hash function receives two arguments which is **[s]** that stands for **[session_id]** and **[u1]** that stands for **[user]**, so each time we will insert a new **[session_id]** and **[user]** we should get a different hash. but how do we calculate the **[session_id]**? That's our main goal. 


in order to fuzz around with the function, I have added some user input and removed the unnecessary html output.

![cache python script](https://gyazo.com/54823219ef083d9f5b742040f4e60035.png)

First We’ll try fuzzing with the account (“user”) we have created at first place. Running the python script with the given parameters, **hash(“user”, session_id[user])**, and received the following hash. 

![User cache script](https://gyazo.com/b6f8138354005d6f4a62f2a318877d96.png)

We would like to investigate more about this function, how can we manipulate it in order to generate **[session_id]** to a specific user.

So in order to minimize our work on comparing two hashes, we will create a user which is almost identical to our original user. We will do so by changing the last character “r” of our original user to the next letter in the alphabet which is “s”, and came up with “uses”.

Next we will create a new user named “uses” via “/register” endpoint, and ran my script on the newly given **[session_id]** cookie, by executing **hash(“uses”, session_id[uses])**.

![uses cache script](https://gyazo.com/f2d69c448800ee6cf4ac03ce027a07f7.png)

Wait, but the generated hash is totally different from the “user” one, so what are we going to compare? We do know that our main goal is to login into admin page and get our flag, but how are we going to achieve it? By creating a valid **[session_id]** for user “admin”. In the following steps we are going to try and calculate **[session_id]** of “user” with “uses” **[session_id]** using the hash function, confused? Let’s dig in. 

## Playing around with Hashes

So we will calculate **hash(“user”, session_id[uses])**, In case you are asking yourselfs why, just remember that we are trying to create **[session_id]** for “user” with “uses” **[session_id]**.

![uses with diff sessionid cache script](https://gyazo.com/254eaff91f84a4d3d5bccb7b4ed3ae5d.png)

By comparing both “uses” and “user” generated hash we can notice a small but significant difference! 

![hash compare](https://gyazo.com/e048b002e370069116eb48be16d8a2fb.png)

Why did “1” changed to “0”? Well it’s pretty simple, in the alphabet the letter “S” comes after “R” so it means that when we ran our hash function the hash result will be lower, due to decreasing one letter from our user string. 
But how can we calculate the **[session_id]** for “user”? try and decrease the last value in “uses" **[session_id]** and check what hash we get. 

![changing sessionid param](https://gyazo.com/254eaff91f84a4d3d5bccb7b4ed3ae5d.png)

Wait… is it the same hash that “uses” has?! Christmas came early this year!
So if we wrap everything around, we can try and replicate these steps on users “admin” and “admim”, so we can get “admin” **[session_id]** and eventually access “/admin” endpoint. 

Finally, we get our little flag of happiness. 

![changing sessionid param](https://gyazo.com/ed6c0b5c2fa8820bf6f213c32b6bd4cd.png)



