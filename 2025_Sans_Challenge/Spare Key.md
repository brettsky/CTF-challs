
---
## Concept

Azure CLI interaction - interact with containers and read files hosted in azure storage containers. 

---

1. We start of this challenge with the prompt to enter the command 
	`az group list -o table`
	This command will show azure resource groups and output the results to the console
2. We then see our resource groups
```
Name                 Location    ProvisioningState
-------------------  ----------  -------------------
rg-the-neighborhood  eastus      Succeeded
rg-hoa-maintenance   eastus      Succeeded
rg-hoa-clubhouse     eastus      Succeeded
rg-hoa-security      eastus      Succeeded
rg-hoa-landscaping   eastus      Succeeded
```

3. We are prompted to enter another command ` az storage account list --resource-group rg-the-neighborhood -o table` 
	1. This command will output the storage accounts associate with the resource group `rg-the-neighborhood`
```
 az storage account list --resource-group rg-the-neighborhood -o table
Name             Kind         Location    ResourceGroup        ProvisioningState
---------------  -----------  ----------  -------------------  -------------------
neighborhoodhoa  StorageV2    eastus      rg-the-neighborhood  Succeeded
hoamaintenance   StorageV2    eastus      rg-hoa-maintenance   Succeeded
hoaclubhouse     StorageV2    eastus      rg-hoa-clubhouse     Succeeded
hoasecurity      BlobStorage  eastus      rg-hoa-security      Succeeded
hoalandscaping   StorageV2    eastus      rg-hoa-landscaping   Succeeded
```
4. This is where the challenge starts to lets us figure things out vs giving us commands
	 we have the prompt ```Someone mentioned there was a website in here.maybe a static website? try:$ az storage blob service-properties show --account-name <insert_account_name> --auth-mode login```
	so we enter the command assuming `neighborhoodhoa` will be the storage account hosting the webserver `az storage blob service-properties show --account-name neighborhoodhoa --auth-mode login`

	We are given another clue ```
	Hint: You will need to use az storage container list
	We want to list the container and its public access levels.```

	We enter the command `az storage container list --account-name neighborhoodhoa --auth-mode login`
```
[
  {
    "name": "$web",
    "properties": {
      "lastModified": "2025-09-20T10:30:00Z",
      "publicAccess": null
    }
  },
  {
    "name": "public",
    "properties": {
      "lastModified": "2025-09-15T14:20:00Z",
      "publicAccess": "Blob"
    }
  }
]
```

We want to see what files are in $web so we add the tag `--container-name \$web` to our command \ is needed to escape the special character $ 

` az storage blob list --account-name neighborhoodhoa --container-name \$web --auth-mode login`

```
[
  {
    "name": "index.html",
    "properties": {
      "contentLength": 512,
      "contentType": "text/html",
      "metadata": {
        "source": "hoa-website"
      }
    }
  },
  {
    "name": "about.html",
    "properties": {
      "contentLength": 384,
      "contentType": "text/html",
      "metadata": {
        "source": "hoa-website"
      }
    }
  },
  {
    "name": "iac/terraform.tfvars",
    "properties": {
      "contentLength": 1024,
      "contentType": "text/plain",
      "metadata": {
        "WARNING": "LEAKED_SECRETS"
      }
    }
  }
]
```

Uh oh - a .tfvars file is not good. These files often contain highly secret keys and values. They should never be publicly accessible. 

To complete the challenge we need to open this file and read its contents 
We do that via `az storage blob download`

` az storage blob download --account-name neighborhoodhoa --container-name \$web --name iac/terraform.tfvars --file /dev/stdout --auth-mode login | less`

```
# Terraform Variables for HOA Website Deployment
# Application: Neighborhood HOA Service Request Portal  
# Environment: Production
# Last Updated: 2025-09-20
# DO NOT COMMIT TO PUBLIC REPOS

# === Application Configuration ===
app_name = "hoa-service-portal"
app_version = "2.1.4"
environment = "production"

# === Database Configuration ===
database_server = "sql-neighborhoodhoa.database.windows.net"
database_name = "hoa_requests"
database_username = "hoa_app_user"
# Using Key Vault reference for security
database_password_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/db-password/)"

# === Storage Configuration for File Uploads ===
storage_account = "neighborhoodhoa"
uploads_container = "resident-uploads"
documents_container = "hoa-documents"

# TEMPORARY: Direct storage access for migration script
# WARNING: Remove after data migration to new storage account
# This SAS token provides full access - HIGHLY SENSITIVE!
migration_sas_token = "sv=2023-11-03&ss=b&srt=co&sp=rlacwdx&se=2100-01-01T00:00:00Z&spr=https&sig=1djO1Q%2Bv0wIh7mYi3n%2F7r1d%2F9u9H%2F5%2BQxw8o2i9QMQc%3D"

# === Email Service Configuration ===
# Using Key Vault for sensitive email credentials
sendgrid_api_key_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/sendgrid-key/)"
from_email = "noreply@theneighborhood.com" 
admin_email = "admin@theneighborhood.com"

# === Application Settings ===
session_timeout_minutes = 60
max_file_upload_mb = 10
allowed_file_types = ["pdf", "jpg", "jpeg", "png", "doc", "docx"]

# === Feature Flags ===
enable_online_payments = true
enable_maintenance_requests = true
enable_document_portal = false
enable_resident_directory = true

# === API Keys (Key Vault References) ===
maps_api_key_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/maps-api-key/)"
weather_api_key_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/weather-api-key/)"

# === Notification Settings (Key Vault References) ===
sms_service_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/sms-credentials/)"
notification_webhook_vault_ref = "@Microsoft.KeyVault(SecretUri=https://kv-neighborhoodhoa-prod.vault.azure.net/secrets/slack-webhook/)"
```


We get some valuable info and our prompted to type `FINISHED` into the  console to complete the challenge


---
## Conclusion

We worked with AZ Cli commands to go through some resource groups and storage accounts. We found a publicly facing storage account hosting .tfvars file. Opening this file gave us the challenge completion