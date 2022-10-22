namespace SocketServiceWrapper
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
            this.SocketServiceProcessInstaller = new System.ServiceProcess.ServiceProcessInstaller();
            this.SocketServiceInstaller = new System.ServiceProcess.ServiceInstaller();
            // 
            // SocketServiceProcessInstaller
            // 
            this.SocketServiceProcessInstaller.Account = System.ServiceProcess.ServiceAccount.LocalSystem;
            this.SocketServiceProcessInstaller.Password = null;
            this.SocketServiceProcessInstaller.Username = null;
            // 
            // SocketServiceInstaller
            // 
            this.SocketServiceInstaller.Description = "Nextlabs service of retrieving file infos";
            this.SocketServiceInstaller.DisplayName = "Nextlabs File Info Socket Service";
            this.SocketServiceInstaller.ServiceName = "SocketService";
            this.SocketServiceInstaller.StartType = System.ServiceProcess.ServiceStartMode.Automatic;
            // 
            // ProjectInstaller
            // 
            this.Installers.AddRange(new System.Configuration.Install.Installer[] {
            this.SocketServiceProcessInstaller,
            this.SocketServiceInstaller});

        }

        #endregion

        private System.ServiceProcess.ServiceProcessInstaller SocketServiceProcessInstaller;
        private System.ServiceProcess.ServiceInstaller SocketServiceInstaller;
    }
}