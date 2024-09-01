# coolEncryptMsg

### How to run

```sh
docker build -t cool-encrypt-msg:1.0 .
docker run -d -p 8080:8080 --name cool-msg-container cool-encrypt-msg:1.0
```

### Open web broswer
* [send massages](http://127.0.0.1:8080/coolmsg/send/)
* [view massages](http://127.0.0.1:8080/coolmsg/messages/)

### Example
![Example](https://github.com/mikelovato/coolEncryptMsg/blob/main/docs/example.gif)