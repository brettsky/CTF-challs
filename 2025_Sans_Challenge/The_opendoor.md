## Concept 
* Using AZ Cli commands to inspect NSG rules and find bad rules.

---
1.  az group list -o table 
	1. Will show the resource groups we have access to and output them into a table
2. az network nsg -list -o table 
	1. Will output the NSGs we have access to see 
3. az network nsg list --name nsg-web-eastus --resource-group theneighborhood-rg1
	1. Will list out the rules associated with the web NSG in eastus
	2. Piping the command into | less will allow us to page through the output
4. The challenge now begins and we have to look through the NSGs and find a bad rule
5. I start with production `az network nsg show --name nsg-production-eastus --resource-group theneighborhood-rg1 | less`
6. After inspection I see a very bad rule 'Allow-RDP-From-Internet' this rule allows RDP connections from the internet 
7. The final task is to submit a command that will list out the details of the bad rule 
8. `az network nsg rule show --name nsg-production-eastus --resource-group theneighborhood-rg1 --nsg-name Allow-RDP-From-Internet| less`
9. This command gives us the completion, we can now type finish in the terminal to get the points