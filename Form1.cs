using System.Diagnostics;
using System;
using System.Reflection.PortableExecutable;
using PEAnalyzer;


namespace PEAnalyzer
{
    using DWORD = uint;
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

                PEManipulation manipulator = new PEManipulation(path);
                if (manipulator.isPE())
                {
                    manipulator._InitializeSuspendedProcess();
                    manipulator._InjectDLL();
                    manipulator._ResumeMainThread();
                }

            }  
        }
    }
}
