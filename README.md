# most-average-c2-ever
The most average C2 ever (MACE)

1. On the server-side, ensure that server.py (or whatever you might name it) is located within /opt/c2
2. You'll need to update this line of code (currently line 236) with your own certificates: sslctx.load_cert_chain(certfile='/etc/letsencrypt/live/your.domain.com/cert.pem', keyfile="/etc/letsencrypt/live/your.domain.com/privkey.pem")
3. Start the server like this: python3 server.py
4. The python program _should_ create the initial databasse and directory structure. However, if not, remember that it is the most average C2 ever and prone to issues
5. Modify implant.cs to include reference to your c2 server (this is at the very top and there is only once place to specifiy it)
6. Compile the implant like this: csc.exe /out:"c:\whatever\implant.exe" /target:exe "c:\whatever\implant.cs"
7. Run implant.exe
