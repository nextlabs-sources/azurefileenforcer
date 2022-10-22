namespace ContentService
{
    partial class ProjectInstaller
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
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

        #region Component Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.CSProcessInstaller = new System.ServiceProcess.ServiceProcessInstaller();
            this.ContentServiceInstaller = new System.ServiceProcess.ServiceInstaller();
            // 
            // CSProcessInstaller
            // 
            this.CSProcessInstaller.Account = System.ServiceProcess.ServiceAccount.LocalService;
            this.CSProcessInstaller.Password = null;
            this.CSProcessInstaller.Username = null;
            // 
            // ContentServiceInstaller
            // 
            this.ContentServiceInstaller.Description = "Content Service";
            this.ContentServiceInstaller.DisplayName = "Content Service";
            this.ContentServiceInstaller.ServiceName = "SocketServ";
            // 
            // ProjectInstaller
            // 
            this.Installers.AddRange(new System.Configuration.Install.Installer[] {
            this.CSProcessInstaller,
            this.ContentServiceInstaller});

        }

        #endregion

        private System.ServiceProcess.ServiceProcessInstaller CSProcessInstaller;
        private System.ServiceProcess.ServiceInstaller ContentServiceInstaller;
    }
}