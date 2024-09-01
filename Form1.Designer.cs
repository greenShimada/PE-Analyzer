namespace PEAnalyzer
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            label1 = new Label();
            txt_path = new TextBox();
            btn_path = new Button();
            label2 = new Label();
            SuspendLayout();
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(12, 9);
            label1.Name = "label1";
            label1.Size = new Size(140, 15);
            label1.TabIndex = 0;
            label1.Text = "Selecione um arquivo PE!";
            // 
            // txt_path
            // 
            txt_path.Location = new Point(12, 27);
            txt_path.Name = "txt_path";
            txt_path.Size = new Size(483, 23);
            txt_path.TabIndex = 1;
            // 
            // btn_path
            // 
            btn_path.Location = new Point(511, 27);
            btn_path.Name = "btn_path";
            btn_path.Size = new Size(70, 23);
            btn_path.TabIndex = 2;
            btn_path.Text = "Procurar";
            btn_path.UseVisualStyleBackColor = true;
            btn_path.Click += btn_path_Click;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.ForeColor = Color.Red;
            label2.Location = new Point(12, 53);
            label2.Name = "label2";
            label2.Size = new Size(154, 15);
            label2.TabIndex = 3;
            label2.Text = "**Não é um executável PE**";
            label2.Visible = false;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(800, 450);
            Controls.Add(label2);
            Controls.Add(btn_path);
            Controls.Add(txt_path);
            Controls.Add(label1);
            Name = "Form1";
            Text = "Form1";
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label label1;
        private TextBox txt_path;
        private Button btn_path;
        private Label label2;
    }
}
