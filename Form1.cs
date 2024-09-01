using System.Diagnostics;
using System;
using System.Reflection.PortableExecutable;
using PEAnalyzer;

namespace PEAnalyzer

{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btn_path_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = @"C:\";

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string path = openFileDialog.FileName;
                Console.WriteLine(path);
                txt_path.Text = path;
                PEParser.pe_static_analysing(path);
            }
            else
            {
                Console.WriteLine("nada papai");
            }
        }

      
    }
}
