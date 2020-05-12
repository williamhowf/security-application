using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace SecurityApp
{
    public partial class SecurityForm : Form
    {
        private const string version = "1.3.1";
        private string passwordInput;
        private string saltInput;
        private string PGHashAlgorithm;
        private string passwordToEncryptInput;
        private string ENHashAlgorithm;
        private readonly string SHA1 = "SHA1";
        private readonly string SHA256 = "SHA256";
        private readonly string SHA512 = "SHA512";
        private readonly string MD5 = "MD5";

        public SecurityForm()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Init();
        }

        private void Init()
        {
            /* Password generator */
            plainPassword.Text = string.Empty;
            SHA1Button.Checked = true;
            SaltRandomButton.Checked = true;
            SaltPrefixInput.Text = string.Empty;
            SaltPrefixInput.Enabled = false;
            PasswordResult.Text = string.Empty;
            SaltResult.Text = string.Empty;
            passwordInput = null;
            saltInput = null;
            PGHashAlgorithm = null;

            /* Signature generator */
            SignInputText1.Text = string.Empty;
            SignInputText2.Text = string.Empty;
            SignInputText3.Text = string.Empty;
            SignatureResult.Text = string.Empty;

            /* Password ecryptor generator */
            PasswordToEncrypt.Text = string.Empty;
            EN_SHA1Button.Checked = true;
            passwordToEncryptInput = null;
            ENHashAlgorithm = null;

            /* Password decryptor */
            CipherPassword.Text = string.Empty;
            DecipherPassword.Text = string.Empty;

            /* Signature verifier */
            VerifyField1.Text = string.Empty;
            VerifyField2.Text = string.Empty;
            VerifyField3.Text = string.Empty;
            VerifyFieldSign.Text = string.Empty;
            SignVerifiedResult.Text = string.Empty;

            /* Secret message to secret key */
            secretmsgbox.Text = string.Empty;
            secretkey64box.Text = string.Empty;
            SK_SHA256.Checked = true;

        }

        private void aboutToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("Security Application");
            sb.AppendLine();
            sb.AppendLine();
            sb.Append("Organization  : GGIT");
            sb.AppendLine();
            sb.Append("Developer  : William");
            sb.AppendLine();
            sb.Append("Version : " + version);
            sb.AppendLine();
            sb.AppendLine();
            sb.AppendLine();
            sb.Append("All rights reserved. 2019© ");
            MessageBox.Show(sb.ToString(), "About");
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            SaltPrefixInput.Text = string.Empty;
            SaltPrefixInput.Enabled = false;
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            SaltPrefixInput.Text = string.Empty;
            SaltPrefixInput.Enabled = true;
        }

        private void GeneratePassword_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();

            if (string.IsNullOrEmpty(plainPassword.Text))
            {
                MessageBox.Show("Please key in password.", "Missing input");
                plainPassword.Focus();
                return;
            }
            if(SaltPrefixButton.Checked && string.IsNullOrEmpty(SaltPrefixInput.Text))
            {
                MessageBox.Show("Please input salt value.", "Missing input");
                SaltPrefixInput.Focus();
                return;
            }
            else
            {
                if (SaltPrefixButton.Checked && !string.IsNullOrEmpty(SaltPrefixInput.Text))
                    saltInput = SaltPrefixInput.Text;
                else
                    saltInput = crypto.CreateSaltKey();
            }
            passwordInput = plainPassword.Text;
            

            if (SHA1Button.Checked)
                PGHashAlgorithm = SHA1;
            else if (SHA256Button.Checked)
                PGHashAlgorithm = SHA256;
            else if (SHA512Button.Checked)
                PGHashAlgorithm = SHA512;

            string hashedPassword = crypto.Hashing(PGHashAlgorithm, passwordInput);
            string doubleHashedPassword = crypto.PasswordHash(hashedPassword, saltInput);

            PasswordResult.Text = doubleHashedPassword;
            SaltResult.Text = saltInput;

        }

        private void ResetPasswordGenerator_Click(object sender, EventArgs e)
        {
            SaltPrefixInput.Text = string.Empty;
            saltInput = null;
            passwordInput = null;
            plainPassword.Text = string.Empty;
            PasswordResult.Text = string.Empty;
            SaltResult.Text = string.Empty;
            SHA1Button.Checked = true;
            SaltRandomButton.Checked = true;
        }

        private void PasswordEncryptor_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();

            if (string.IsNullOrEmpty(PasswordToEncrypt.Text))
            {
                MessageBox.Show("Please key in password.", "Missing input");
                PasswordToEncrypt.Focus();
                return;
            }
            passwordToEncryptInput = PasswordToEncrypt.Text;

            if (EN_SHA1Button.Checked)
                ENHashAlgorithm = SHA1;
            else if (EN_SHA256Button.Checked)
                ENHashAlgorithm = SHA256;
            else if (EN_SHA512Button.Checked)
                ENHashAlgorithm = SHA512;

            string hashedPassword = crypto.Hashing(ENHashAlgorithm, passwordToEncryptInput);
            string encryptedPassword = crypto.TripleDES_Encryptor(hashedPassword);
            HashedResultPassword.Text = hashedPassword;
            EncryptedResultPassword.Text = encryptedPassword;
        }

        private void ResetPasswordEncryptor_Click(object sender, EventArgs e)
        {
            PasswordToEncrypt.Text = string.Empty;
            passwordToEncryptInput = null;
            ENHashAlgorithm = null;
            HashedResultPassword.Text = string.Empty;
            EncryptedResultPassword.Text = string.Empty;
        }

        private void GenerateSignature_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();
            if(string.IsNullOrEmpty(SignInputText1.Text) && string.IsNullOrEmpty(SignInputText2.Text) && string.IsNullOrEmpty(SignInputText3.Text))
            {
                MessageBox.Show("Please key in fields.", "Missing input");
                SignInputText1.Focus();
                return;
            }
            bool field1Encrypted = SG_EN_F1.Checked;
            bool field2Encrypted = SG_EN_F2.Checked;
            string signField1 = SignInputText1.Text;
            string signField2 = SignInputText2.Text;
            string signField3 = SignInputText3.Text;
            try
            {
                if (field1Encrypted)
                    signField1 = crypto.TripleDES_Decryptor(SignInputText1.Text);
                if (field2Encrypted)
                    signField2 = crypto.TripleDES_Decryptor(SignInputText2.Text);
            }
            catch(Exception ex)
            {
                MessageBox.Show("Invalid input to decrypt. \n"+ex.Message, "Invalid input");
                return;
            }
            string toSign = signField1 + "|" + signField2 + "|" + signField3;

            string signaturedMessage = crypto.RSADigitalSignatureSHA1(toSign);
            SignatureResult.Text = signaturedMessage;
        }

        private void ResetSignatureGenerator_Click(object sender, EventArgs e)
        {
            SignInputText1.Text = string.Empty;
            SignInputText2.Text = string.Empty;
            SignInputText3.Text = string.Empty;
            SignatureResult.Text = string.Empty;
        }

        private void PasswordDecrptorGenerate_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();
            if (string.IsNullOrEmpty(CipherPassword.Text))
            {
                MessageBox.Show("Please key in password.", "Missing input");
                CipherPassword.Focus();
                return;
            }
            string cipherText = CipherPassword.Text;
            try
            {
                DecipherPassword.Text = crypto.TripleDES_Decryptor(cipherText);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Invalid input to decrypt. \n" + ex.Message, "Invalid input");
                return;
            }
        }

        private void PasswordDecryptorReset_Click(object sender, EventArgs e)
        {
            CipherPassword.Text = string.Empty;
            DecipherPassword.Text = string.Empty;
        }

        private void SignVerify_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();
            if (string.IsNullOrEmpty(VerifyField1.Text) ||
            string.IsNullOrEmpty(VerifyField2.Text) ||
            string.IsNullOrEmpty(VerifyField3.Text) ||
            string.IsNullOrEmpty(VerifyFieldSign.Text))
            {
                MessageBox.Show("Please key in all fields.", "Missing input");
                return;
            }
            bool field1Encrypted = Field1Checked.Checked;
            bool field2Encrypted = Field2Checked.Checked;
            string field1 = VerifyField1.Text;
            string field2 = VerifyField2.Text;
            try
            {
                if (field1Encrypted)
                    field1 = crypto.TripleDES_Decryptor(VerifyField1.Text);
                if (field2Encrypted)
                    field2 = crypto.TripleDES_Decryptor(VerifyField2.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Invalid input to decrypt. \n" + ex.Message, "Invalid input");
                return;
            }
            string plainData = field1 + "|" + field2 + "|" + VerifyField3.Text;
            SignVerifiedResult.Text = crypto.VerifyRSADigitalSignatureSHA1(plainData, VerifyFieldSign.Text).ToString().ToUpper();
        }

        private void ResetVerify_Click(object sender, EventArgs e)
        {
            VerifyField1.Text = string.Empty;
            VerifyField2.Text = string.Empty;
            VerifyField3.Text = string.Empty;
            VerifyFieldSign.Text = string.Empty;
            SignVerifiedResult.Text = string.Empty;
        }

        private void resetSecret_Click(object sender, EventArgs e)
        {
            secretmsgbox.Text = string.Empty;
            secretkey64box.Text = string.Empty;
            SK_SHA256.Checked = true;
        }

        private void generateSecret_Click(object sender, EventArgs e)
        {
            string algorithm = SHA256; // default algorithm
            Cryptography crypto = new Cryptography();
            if (string.IsNullOrEmpty(secretmsgbox.Text))
            {
                MessageBox.Show("Please generate secret key with secret message.");
                return;
            }
            if (SK_SHA512.Checked)
                algorithm = SHA512;

            secretkey64box.Text = crypto.GenerateSecretKey(algorithm, secretmsgbox.Text);
        }

        private void exportSecret_Click(object sender, EventArgs e)
        {
            Cryptography crypto = new Cryptography();
            if (string.IsNullOrEmpty(secretmsgbox.Text) || string.IsNullOrEmpty(secretkey64box.Text))
            {
                MessageBox.Show("Please generate secret key with secret message \nbefore export it into a file.");
                return;
            }
            if (string.IsNullOrWhiteSpace(FileOutputExportSecretKey.Text))
            {
                MessageBox.Show("Please enter file path and output file name.");
                return;
            }
            bool result = crypto.CreateBufferFile(FileOutputExportSecretKey.Text, secretkey64box.Text);
            MessageBox.Show("Export to file : "+ (result ? "SUCCESS":"FAIL"));
        }

        private void hmac_gen_defsk_CheckedChanged(object sender, EventArgs e)
        {
            if (hmac_gen_defsk.Checked)
            {
                hmac_gen_sk.Enabled = false;
                hmac_gen_sk.Text = string.Empty;
            }
            if (!hmac_gen_defsk.Checked)
            {
                hmac_gen_sk.Enabled = true;
            }
        }

        private void hmac_gen_reset_Click(object sender, EventArgs e)
        {
            hmac_gen_sk.Enabled = false;
            hmac_gen_defsk.Checked = true;
            hmac_gen_sk.Text = string.Empty;
            hmac_gen_msg.Text = string.Empty;
            hmac_gen_sha256.Checked = true;
            //hmac_gen_signaturebase64.Text = string.Empty;
            hmac_gen_signaturehexbinary.Text = string.Empty;
        }

        private void hmac_ver_reset_Click(object sender, EventArgs e)
        {
            hmac_ver_sk.Enabled = false;
            hmac_ver_defsk.Checked = true;
            hmac_ver_sk.Text = string.Empty;
            hmac_ver_msg.Text = string.Empty;
            hmac_ver_sha256.Checked = true;
            hmac_ver_signature.Text = string.Empty;
        }

        private void hmac_ver_defsk_CheckedChanged(object sender, EventArgs e)
        {
            if (hmac_ver_defsk.Checked)
            {
                hmac_ver_sk.Enabled = false;
                hmac_ver_sk.Text = string.Empty;
            }
            if (!hmac_ver_defsk.Checked)
            {
                hmac_ver_sk.Enabled = true;
            }
        }

        private void hmac_gen_generator_Click(object sender, EventArgs e)
        {
            if(string.IsNullOrEmpty(hmac_gen_msg.Text) || 
                (!hmac_gen_defsk.Checked && string.IsNullOrEmpty(hmac_gen_sk.Text))
              )
            {
                MessageBox.Show("Please enter message and secret key");
                return;
            }

            string algorithm = SHA256;
            if (hmac_gen_sha512.Checked)
                algorithm = SHA512;

            Cryptography crypto = new Cryptography();
            var result = crypto.HMACSignatures(algorithm, hmac_gen_msg.Text, hmac_gen_sk.Text);
            //hmac_gen_signaturebase64.Text = crypto.ConvertByteToBase64String(result);
            hmac_gen_signaturehexbinary.Text = crypto.ConvertByteToHex(result);
        }

        private void hmac_ver_generator_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(hmac_ver_msg.Text) ||
                (!hmac_ver_defsk.Checked && string.IsNullOrEmpty(hmac_ver_sk.Text))
              )
            {
                MessageBox.Show("Please enter message and secret key");
                return;
            }

            string algorithm = SHA256;
            if (hmac_ver_sha512.Checked)
                algorithm = SHA512;

            Cryptography crypto = new Cryptography();
            hmac_ver_signresult.Text = crypto.HMACVerify(algorithm, hmac_ver_msg.Text, hmac_ver_signature.Text, hmac_ver_sk.Text).ToString();
        }
        
        private void plainText_enc_reset_Click(object sender, EventArgs e)
        {
            plainText_enc_sk.Enabled = false;
            plainText_enc_defkey.Checked = true;
            plainText_enc_sk.Text = string.Empty;
            plainText_enc_result.Text = string.Empty;
            plainText_enc_msg.Text = string.Empty;
        }

        private void plainText_dec_reset_Click(object sender, EventArgs e)
        {
            plainText_dec_sk.Enabled = false;
            plainText_dec_defkey.Checked = true;
            plainText_dec_sk.Text = string.Empty;
            plainText_dec_result.Text = string.Empty;
            plainText_dec_msg.Text = string.Empty;
        }

        private void plainText_enc_defkey_CheckedChanged(object sender, EventArgs e)
        {
            if (plainText_enc_defkey.Checked)
            {
                plainText_enc_sk.Enabled = false;
                plainText_enc_sk.Text = string.Empty;
            }
            if (!plainText_enc_defkey.Checked)
            {
                plainText_enc_sk.Enabled = true;
            }
        }

        private void plainText_dec_defkey_CheckedChanged(object sender, EventArgs e)
        {
            if (plainText_dec_defkey.Checked)
            {
                plainText_dec_sk.Enabled = false;
                plainText_dec_sk.Text = string.Empty;
            }
            if (!plainText_dec_defkey.Checked)
            {
                plainText_dec_sk.Enabled = true;
            }
        }

        private void plainText_enc_upload_Click(object sender, EventArgs e)
        {
            DialogResult result = openFileDialog1.ShowDialog(); // Show the dialog.
            if (result == DialogResult.OK) // Test result.
            {
                string file = openFileDialog1.FileName;
                string directoryName = new DirectoryInfo(Path.GetDirectoryName(file)).Name;
                string fileName = Path.GetFileName(file);
                string ext = file.Substring(file.LastIndexOf("."));
                
                if (ext != ".json" || string.IsNullOrEmpty(plainText_enc_defkey.Text))
                {
                    MessageBox.Show("Input file format not as .json or Environment does'nt choosen");
                    return;
                }

                //Read text
                string text = File.ReadAllText(file);

                //Encryption
                Cryptography crypto = new Cryptography();
                string encryptedMsgResult = crypto.TripleDES_Encryptor(text, Encoding.UTF8.GetBytes(plainText_enc_sk.Text));

                //Copy new json file which is encrypted
                Directory.CreateDirectory($"{Directory.GetCurrentDirectory()}/App_Data/{directoryName}");
                File.WriteAllText(Directory.GetCurrentDirectory() + $"/App_Data/{directoryName}/{fileName}", encryptedMsgResult);
                plainText_enc_result.Text = encryptedMsgResult;
            }
        }

        private void plainText_dec_upload_Click(object sender, EventArgs e)
        {
            DialogResult result = openFileDialog1.ShowDialog(); // Show the dialog.
            if (result == DialogResult.OK) // Test result.
            {
                string file = openFileDialog1.FileName;
                string ext = file.Substring(file.LastIndexOf("."));

                if (ext != ".json" || string.IsNullOrEmpty(plainText_dec_defkey.Text))
                {
                    MessageBox.Show("Input file format not as .json");
                    return;
                }

                //Read text
                string text = File.ReadAllText(file);

                //Decryption
                Cryptography crypto = new Cryptography();
                string decryptedMsgResult = crypto.TripleDES_Decryptor(text, Encoding.UTF8.GetBytes(plainText_dec_sk.Text));

                //Decrypted json file cipher text which is encrypted
                plainText_dec_result.Text = decryptedMsgResult;
            }
        }

        private void plainText_dec_generator_Click_1(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(plainText_dec_msg.Text) ||
                (!plainText_dec_defkey.Checked && string.IsNullOrEmpty(plainText_dec_sk.Text))
              )
            {
                MessageBox.Show("Please enter plain text and secret key");
                return;
            }

            Cryptography crypto = new Cryptography();
            plainText_dec_result.Text = crypto.TripleDES_Decryptor(plainText_dec_msg.Text, Encoding.UTF8.GetBytes(plainText_dec_sk.Text));
        }

        private void plainText_enc_generator_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(plainText_enc_msg.Text) ||
                (!plainText_enc_defkey.Checked && string.IsNullOrEmpty(plainText_enc_sk.Text))
              )
            {
                MessageBox.Show("Please enter plain text and secret key");
                return;
            }

            Cryptography crypto = new Cryptography();
            plainText_enc_result.Text = crypto.TripleDES_Encryptor(plainText_enc_msg.Text, Encoding.UTF8.GetBytes(plainText_enc_sk.Text));            
        }

        private void plainText_enc_allowedinput_CheckedChanged(object sender, EventArgs e)
        {
            if (plainText_enc_allowedinput.Checked)
            {
                plainText_enc_msg.Enabled = false;
                plainText_enc_msg.Text = string.Empty;
            }
            else if (!plainText_enc_allowedinput.Checked)
                plainText_enc_msg.Enabled = true;
        }

        private void plainText_dec_allowedinput_CheckedChanged(object sender, EventArgs e)
        {
            if (plainText_dec_allowedinput.Checked)
            {
                plainText_dec_msg.Enabled = false;
                plainText_dec_msg.Text = string.Empty;
            }
            else if (!plainText_dec_allowedinput.Checked)
                plainText_dec_msg.Enabled = true;
            
        }
    }
}
