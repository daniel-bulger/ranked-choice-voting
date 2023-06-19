# Running instructions

1. Get launchfile from dan
2. python debugger in vscode 
3. install pip if not already installed
4. pip install -r requirements.txt
5. make up fake SSL cert for localhost and localhost-key
6. ensure you're running from the Python: Flask Debugger




## Create a .pem file for localhost

A `.pem` file is a type of SSL certificate that is used to encrypt data sent between a client and a server. This prevents data from being intercepted. You can create a `.pem` file for localhost using OpenSSL, an open-source tool for handling SSL certificates.

### Steps:

1. Open a terminal and execute the following commands to create a new private key:

    ```bash
    openssl genrsa -out localhost.key 2048
    ```

2. Next, create a new self-signed certificate from the private key:

    ```bash
    openssl req -new -x509 -key localhost.key -out localhost.cert -days 365 -subj /CN=localhost
    ```

3. Finally, combine the private key and certificate into a single `.pem` file:

    ```bash
    cat localhost.key localhost.cert > localhost.pem
    ```

### Important Notes:

- This will create a self-signed certificate, which may cause browsers to warn users that the certificate is not trusted. While this is suitable for local development, in a production setting, a certificate signed by a trusted certificate authority should be used.

- OpenSSL must be installed on your system to execute these commands. If not, it can usually be installed with your package manager. For example, on Ubuntu, you can use `sudo apt-get install openssl`.

- The command `openssl req -new -x509...` creates a certificate that lasts 365 days. Replace `365` with a different number to adjust the certificate's validity.

- Your server needs to be configured to use the `localhost.pem` file. The configuration will depend on the server software in use. For instance, for a Flask server in Python, you can use the following code:

    ```python
    from flask import Flask
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'Hello, World!'

    if __name__ == '__main__':
        context = ('localhost.cert', 'localhost.key')  # Certificate and key files
        app.run(port=3000, ssl_context=context)
    ```

- Remember to properly secure your `.key` and `.pem` files, as they can be used to decrypt your secure traffic if they fall into the wrong hands. 
