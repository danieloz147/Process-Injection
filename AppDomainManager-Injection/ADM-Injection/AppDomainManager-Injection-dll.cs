// This class library demonstrates AppDomainManager injection by displaying a message box
// when a new application domain is initialized.
using System;
using System.Windows.Forms;

namespace ADM_Injection;

// Custom AppDomainManager that shows a message box upon domain initialization.
public sealed class DomainManager : AppDomainManager
{
    //Override the InitializeNewDomain method to display a message box.
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        MessageBox.Show("Hello World", "Success");
    }
}