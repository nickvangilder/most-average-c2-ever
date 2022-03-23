# most-average-c2-ever
The most average C2 ever (MACE)

1. pip3 install pycryptodome
2. Ensure that server.py (or whatever you might name it) is located within /opt/c2
3. Update server.py with referenecs to your own certificates (top of program in global variables)
4. Start the server like this: python3 server.py
5. Modify implant.cs to include reference to your c2 server (this is at the very top and there is only once place to specifiy it)
6. Compile the implant like this: csc.exe /out:"c:\whatever\implant.exe" /target:exe "c:\whatever\implant.cs"
7. Run implant.exe

Example of implant connecting back to the listening post:

![image](https://user-images.githubusercontent.com/26583248/159715005-639d9af4-60d5-4a28-a166-1a7771c3bcb9.png)
