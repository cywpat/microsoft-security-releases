import requests
import pandas as pd
from datetime import datetime

# Read existing Excel into a DataFrame
# fileName has to be full name of the file
df = pd.read_excel('microsoft-security-releases\microsoft security release for July 2024.xlsx', header=3)

# Fill in empty cells in df
df = df.ffill()

# Get link of CVE and store in new column in df
# example base_url = "https://www.cve.org/CVERecord?id=CVE-2024-37985"
# example json_base_url = "https://cveawg.mitre.org/api/cve/CVE-2024-21317"
base_url = "https://www.cve.org/CVERecord?id="
json_base_url = "https://cveawg.mitre.org/api/cve/"
link = base_url + df['CVE']
json_link = json_base_url + df['CVE']
df['Link'] = link
df['JSON Link'] = json_link

# Get Title, Product Name, min Version, max Version and store in new column in df
for json_link in df['JSON Link']:
    # initialise and reset string vars
    productNameStr = ""
    productMinVersStr = ""
    productMaxVersStr = ""

    # Send HTTP request to URL and save the response from server in response object
    response = requests.get(json_link)
    
    # Get JSON data from the response
    data = response.json()

    # Get relevant data and store in new column
    try:
        # store JSON data as df
        df_web = pd.DataFrame(data)

        # retrieve relevant information
        # Title
        details = df_web['containers']['cna']
        title = details.get('title', "No title available")
        # store in respective row and Title column
        df.loc[df['JSON Link'] == json_link, 'Title'] = title

        # Product Name, min Version, max Version
        products = details['affected']
        for product in products: 
            productName = product.get('product', "No product name available")
            productNameStr += productName + "\n"
            
            productVers = product['versions'][0]  
            productMinVers = productVers.get('version', "No product min version available")
            productMinVersStr += productMinVers + "\n"
            productMaxVers = productVers.get('lessThan', "No product max version available")
            productMaxVersStr += productMaxVers + "\n"
        
        # store in respective row and column
        df.loc[df['JSON Link'] == json_link, 'Product Name'] = productNameStr
        df.loc[df['JSON Link'] == json_link, 'Product Min Version'] = productMinVersStr
        df.loc[df['JSON Link'] == json_link, 'Product Max Version'] = productMaxVersStr

    # When JSON data retrieved is not of the above expected format
    except ValueError:
        err = "ValueError: Unable to convert data to DataFrame. Please check link manually."
        df.loc[df['JSON Link'] == json_link, 'Title'] = err

    except Exception as e:
        print("An unexpected error occurred: ", e)

# To determine which team is responsible for the product
appsKeywords = ["Microsoft Dynamics 365", ".NET", "Microsoft Visual Studio", "Azure"]
afmKeywords = ["Microsoft SQL Server", "Windows", "Microsoft SharePoint"]
df.loc[
    df['Product Name'].str.contains('|'.join(appsKeywords)) == True
    , 'Team'
] = "Apps"
df.loc[
    df['Product Name'].str.contains('|'.join(afmKeywords)) == True
    , 'Team'
] = "AFM"

# To determine if patching is required
ourProducts = ["Windows Server 2016", "Windows Server 2019", "Windows Server 10 Enterprise", 
               "Microsoft SQL Server 2017", "Microsoft Dynamics 365 (on-premises) version 9.0", 
               "Microsoft Visual Studio 2019 Professional", "Microsoft Office 2019", "Azure DevOps Server 2022"]
df.loc[
    df['Product Name'].str.contains('|'.join(ourProducts)) == True
    , 'Affected?'
] = "Possibly"

# Save results into csv
# note that files cannot be overwritten
current_month = datetime.now().strftime("%b")
current_year = datetime.now().year
df.to_csv(f"microsoft-security-releases\microsoft security release for {current_month} {current_year}_updated.csv")