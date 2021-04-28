using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FactFindHEATUAT.HEATAPI;

namespace FactFindHEATUAT
{
    class Program
    {
      public  static String tenantID = "";

        static void Main(string[] args)
        {
            String samAccountName="";
            String password="";  
            String heatRole="";

            FRSHEATIntegration heat = new FRSHEATIntegration();
            FRSHEATIntegrationConnectionResponse cr = heat.Connect(samAccountName, password, tenantID, heatRole);

            String username = args[0];
 
            CreateINC(heat, cr,username);

        }

        static void CreateINC(FRSHEATIntegration heat, FRSHEATIntegrationConnectionResponse cr,String uname)
        {
            //Create New Incident
            ObjectCommandData data = new ObjectCommandData();
            data.ObjectType = "Incident#";

            String rec = FindEmployee(heat, cr,uname);

            if (rec != "")
            {

                List<ObjectCommandDataFieldValue> dataFields = new List<ObjectCommandDataFieldValue>();
                Dictionary<string, object> fields = new Dictionary<string, object>();

                fields["Subject"] = "User account compromised and disabled";
                fields["Symptom"] = uname + " was identified by Azure as either having it's credentials hacked or leaked, and has been disabled. The account will be unusable for all board services until this is resolved. Someone from the Account Security team will contact this user shortly to perform a password reset.";
                fields["ProfileLink_RecID"] = rec;
                fields["OwnerTeam"] = "Data Centre";
                fields["CreatedBy"] = "Azure.Reporting";
                fields["LastModBy"] = "Azure.Reporting";
                fields["LastModDateTime"] = String.Format("{0:MM/dd/yyyy hh:mm tt}", DateTime.Now).Replace("-", "/");
                fields["CreatedDateTime"] = String.Format("{0:MM/dd/yyyy hh:mm tt}", DateTime.Now).Replace("-", "/");
                fields["Category"] = "Account";
                fields["Service"] = "Account Management";
                fields["Subcategory"] = "Lockout";
                fields["Urgency"] = "Unable to work"; 
                fields["Source"] = "AutoTicket"; 
                fields["Impact"] = "1 user";
               // fields["Status"] = "Logged";

                foreach (string key in fields.Keys)
                {
                    dataFields.Add(new ObjectCommandDataFieldValue()
                    {
                        Name = key,
                        Value = fields[key].ToString()
                    });
                }

                data.Fields = dataFields.ToArray();

                FRSHEATIntegrationCreateBOResponse result = heat.CreateObject(cr.sessionKey, tenantID, data);

                if (result.status == "Success")
                {
                    if (result.obj != null)
                    {
                        // Console.WriteLine(result.obj.Alias);
                    }
                    else
                    {
                        // Console.WriteLine("OBJ Still null");
                    }

                    //If incident creation was successful, get incident number and return it to powershell script
                    FRSHEATIntegrationFindBOResponse inc2 = heat.FindBusinessObject(cr.sessionKey, "uat-YRDSBHEATDEV01", "Incident", result.recId);
                    if (inc2.status == "Success")
                    {
                        Console.WriteLine(inc2.obj.FieldValues.SingleOrDefault(f => f.Name == "IncidentNumber").Value.ToString());
                    }
                    else
                    {
                        // Console.WriteLine("Cant find INC from RECID even though was success.");
                    }

                }
                else
                {
                    // Console.WriteLine(result.exceptionReason);
                }

            }
            else
            {
                Console.WriteLine("Error making incident ticket");
            }
        }

        //Method to get employee RecordID for linking to incident
        static string FindEmployee(FRSHEATIntegration heat, FRSHEATIntegrationConnectionResponse cr,string uname)
        {
            String returnname = "";
            FRSHEATIntegrationFindBOResponse inc2 = heat.FindSingleBusinessObjectByField(cr.sessionKey, tenantID, "Employee", "PrimaryEmail", uname);      

            if (inc2.status == "Success")
            {
                try
                {
                   returnname = inc2.obj.FieldValues.SingleOrDefault(f => f.Name == "RecId").Value.ToString();
                }
                catch (Exception e) { }
                
            }

            return returnname;

        }
    }
}
