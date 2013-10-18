using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using RSAEncryptDemo.Resources;

using RSAEncryptDemo.Common;

namespace RSAEncryptDemo
{
    public partial class MainPage : PhoneApplicationPage
    {
        public MainPage()
        {
            InitializeComponent();
            this.Loaded += MainPage_Loaded;
        }

        void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            this.Encrypt_TB.Text = "http://chenkai.cnblogs.com";
        }

        private void EncryptOperator_BT_Click(object sender, RoutedEventArgs e)
        {
            string needEncryptStr = this.Encrypt_TB.Text.Trim();
            if (string.IsNullOrEmpty(needEncryptStr))
                return;

            RsaDataEncryptHelper rsaHelper = new RsaDataEncryptHelper();
            string encryptRsaStr=rsaHelper.UseSystemRsaDataEncrypt(needEncryptStr);

            if (!string.IsNullOrEmpty(encryptRsaStr))
                this.DeEncrypt_TB.Text = encryptRsaStr;
        }

    }
}