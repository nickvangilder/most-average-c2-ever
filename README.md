# most-average-c2-ever
The most average C2 ever (MACE)

1. On the server-side: pip3 install pycryptodome
2. On the server-side, ensure that server.py (or whatever you might name it) is located within /opt/c2
3. You'll need to update this line of code (currently line 236) with your own certificates: sslctx.load_cert_chain(certfile='/etc/letsencrypt/live/your.domain.com/cert.pem', keyfile="/etc/letsencrypt/live/your.domain.com/privkey.pem")
4. Start the server like this: python3 server.py
5. The python program _should_ create the initial databasse and directory structure. However, if not, remember that it is the most average C2 ever and prone to issues
6. Modify implant.cs to include reference to your c2 server (this is at the very top and there is only once place to specifiy it)
7. Compile the implant like this: csc.exe /out:"c:\whatever\implant.exe" /target:exe "c:\whatever\implant.cs"
8. Run implant.exe


![image](https://user-images.githubusercontent.com/26583248/159715005-639d9af4-60d5-4a28-a166-1a7771c3bcb9.png)
