# Secure Messaging Platform

You need to have Python3 (>= 3.6.4) installed as well as some libraries:

```bash
$ pip3 install -r requirements.txt
```

You also need to make sure that the middleware of the Cartão de Cidadão 
(Portuguese National ID) is correctly installed and configured, because all the
messages between users must be signed using CC's Authentication Key. All the
certificates up until the last commit made are updated, but as the time passes by, 
you may need to download the most updated ones.

To run the server, just make sure you have port 8080 free:

```bash
$ python3 src/Server/server.py
```

To open a client console:

```bash
$ python3 src/Client/client.py
```

It was also created a script (`delete_accounts.sh`) in order to reset user 
accounts on the system, which is particularly useful for testing different
cipher suites.

```bash
$ chmod +x src/delete_accounts.sh
$ ./ delete_accounts.sh
```

Diogo Ferreira

Pedro Martins

2018
