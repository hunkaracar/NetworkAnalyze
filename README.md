# NetworkAnalyze

Follow the steps:

cd SaldırıTespitVeAtakSistemi

for linux => ls    
for windows => dir

pip install -r requirements.txt

python3 detNet.py -ip 10.0.2.1/24 or python3 detNet.py -ip 192.168.1.1/24

***You can read the documents.txt file to see other options****

-----------------------------------------------------------------------------------

DEPENDECIES FOR WINDOWS

=> https://www.winpcap.org/install/ 
=> https://npcap.com/vs-winpcap.html  ***
=> https://npcap.com/#download

You need to install these

then;

For Windows:

Open the start menu and type "System" (or "System Properties") to open "System Settings".
Select "Advanced system settings" from the menu on the left.
In the window that opens, click the "Environment Variables" button.
In the "System Variables" section, select the variable named "Path" (or "PATH") and click the edit button.
Add the full path to the nmap program to the Path value. For example, it could be C:\Program Files (x86)\Nmap.
Save and confirm the changes made.
Restart the command prompt and check if it is installed correctly by running the nmap command.
