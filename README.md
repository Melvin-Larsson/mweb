# Mweb
A webserver written in C for Linux. Currently only supports http2 over TLS.
## Design goals
- Optimize for performance
 - Minimize thread overhead by keeping the number of threads close to the number of cores and using asynchronous calls instead. 
 - Running content generation code, written in C, in a somewhat sandboxed environment allowing crashes and memory leaks. This is achieved through the "content-server" which runs as a separate process to the webserver process, allowing restarts on crashes. 


## Running
### Dependencies
- openssl
- libjson
```bash
sudo apt install libssl-dev libcjson-dev
```

### Building
```
cmake -S . -B build
cmake --build build
```

### Generate self signed certificates
```bash
mkdir cert
openssl req -x509 -newkey rsa:2048 -nodes -keyout cert/key.pem -out cert/cert.pem  -days 365
```


### Run
```
build/web
```


## Configuration
The application will look for the configuration file specified in the environment variable `APP_CONFIG_PATH`. If no such file is found, it will look for `config.json` in the directory of the binary. 

The configuration file might look something like
```json
{
  "Port": 8443,
  "Certificate": "./cert/cert.pem",
  "PrivateKey": "./cert/key.pem",
  "Content": "./content"
}

```

### Custom routes (currently broken)
Custom routes can be specified in a `routes.json` located in the content directory. It might look like this:
```json
{
  "/index.html": ["/dir/index-path-1", "/dir2/index-path-2"],
  "/style.css": ["/my-style.css"]
}
```

Resulting in requests for `/dir/index-path-1` and `dir2/index-path-2` being redirected to `index.html` while requests for `/my-style.css` being redirected to `style.css`