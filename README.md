# Secure messaging platform

Para a correta execução da plataforma, primeiro é necessário garantir que se tem instalado Python3 (foi testado usando Python 3.6.4). 
De seguida devem ser instaladas todas as bibliotecas usadas:
```bash
$ pip3 install -r requirements.txt
```

Deve-se também garantir que se tem o middleware do CC corretamente instalado e configurado, pois este é um sistema de mensagens de seguras
entre utilizadores do CC. Como tal, também os certificados do mesmo devem ser corretamente descarregados, no entanto, os mesmos já são
disponibilizados na pasta certs(tanto do lado do servidor como do cliente).
Para executar o servidor, basta garantir que a porta 8080 está disponível e executar:
```bash
$ python3 src/Server/server.py
```

Para abrir uma consola de cliente, basta:

```bash
$ python3 src/Client/client.py
```

Foi ainda criado um pequeno script(delete_accounts.sh), que permite fazer um reset às contas de utilizador registadas no sistema (tanto no cliente 
como no servidor), e que é útil, entre outros, para teste de vários cipher_specs, uma vez que a quantidade de contas de utilizadores que 
podemos criar é muito limitada, graças ao número de CC disponíveis:

```bash
$ chmod +x src/delete_accounts.sh
$ ./ delete_accounts.sh
```
